// Package handlers translates HTTP into service calls and service results back
// into HTTP. That is all it does.
//
// A handler must not: query the database, hash a password, decide whether a
// user may perform an action, or contain an `if` that encodes a business rule.
// If you find yourself writing one, it belongs in a service.
//
// The shape of every handler in this package is identical:
//
//  1. bind the request (decode + validate)
//  2. call exactly one service method
//  3. on error, hand it to response.Error and return
//  4. on success, map the model to a DTO and write it
//
// When every handler looks the same, a reviewer can see at a glance that one
// does not.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/validators"
)

// maxBodyBytes caps how much a client may send.
//
// Without a cap, `curl -d @/dev/zero` makes your server allocate until the
// kernel kills it. json.Decoder streams, but it streams into memory.
//
// 1 MiB is generous for JSON. Raise it only for endpoints that accept file
// uploads, and raise it for those endpoints only.
const maxBodyBytes = 1 << 20 // 1 MiB

// bind decodes the JSON body into dst and validates it.
//
// Every failure is returned as an *apperrors.AppError, so the caller's error
// path is one line. The messages are written for a developer integrating
// against this API — they say what was wrong and where.
func bind(w http.ResponseWriter, r *http.Request, v *validators.Validator, dst any) error {
	// A body sent as text/plain that happens to be valid JSON is a sign of a
	// misconfigured client, and accepting it hides the bug. It is also one of
	// the conditions that makes a request "simple" under CORS, i.e. exempt from
	// a preflight check — so requiring JSON is a small CSRF hardening measure.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if !strings.EqualFold(mediaType, "application/json") {
			return apperrors.BadRequest("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type must be application/json")
		}
	}

	// MaxBytesReader closes the connection once the limit is exceeded, so a
	// malicious client cannot keep streaming. It also makes the Decode below
	// return an *http.MaxBytesError, which we translate specifically.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)

	// Reject unknown fields.
	//
	// Without this, a client POSTing {"firstNmae": "Bob"} silently gets an
	// empty FirstName and a confusing "required" error about a field they
	// believe they sent. With it, they are told `firstNmae` is not a field.
	//
	// It is also a defence: a request carrying {"isAdmin": true} against a DTO
	// that has no such field is now a 400 rather than a silently ignored
	// attempt at mass assignment. (The DTO already made the attempt useless;
	// this makes it visible.)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}

	// A body of `{"a":1}{"b":2}` decodes the first object and silently discards
	// the second. Insist on exactly one JSON value.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apperrors.BadRequest("MALFORMED_JSON", "Request body must contain a single JSON object")
	}

	// Normalise BEFORE validating.
	//
	// A user who copy-pastes " Alice@Example.COM " must not be told their email
	// is invalid — it is, once trimmed. Validating first and trimming later
	// would reject input we are perfectly able to accept.
	//
	// Implemented as an optional interface rather than a field on every DTO:
	// a request with nothing to normalise simply does not implement it, and
	// costs one type assertion.
	if n, ok := dst.(Normalizer); ok {
		n.Normalize()
	}

	return v.Struct(dst)
}

// Normalizer is implemented by request DTOs that need cleaning before their
// validation rules are applied. See internal/dto/request.
type Normalizer interface {
	Normalize()
}

// decodeError turns encoding/json's errors into messages a client can act on.
//
// The default errors are written for a Go programmer reading a stack trace, not
// for someone integrating against an API.
func decodeError(err error) error {
	var (
		syntaxErr    *json.SyntaxError
		typeErr      *json.UnmarshalTypeError
		maxBytesErr  *http.MaxBytesError
		invalidUnmar *json.InvalidUnmarshalError
	)

	switch {
	case errors.As(err, &syntaxErr):
		return apperrors.BadRequest("MALFORMED_JSON",
			fmt.Sprintf("Request body contains malformed JSON at position %d", syntaxErr.Offset))

	case errors.Is(err, io.ErrUnexpectedEOF):
		return apperrors.BadRequest("MALFORMED_JSON", "Request body contains malformed JSON")

	case errors.As(err, &typeErr):
		// e.g. {"page": "one"} where page is an int.
		return apperrors.Validation("The submitted data is invalid",
			apperrors.FieldError{
				Field:   typeErr.Field,
				Message: fmt.Sprintf("Must be of type %s", typeErr.Type.String()),
			})

	case errors.Is(err, io.EOF):
		return apperrors.BadRequest("EMPTY_BODY", "Request body must not be empty")

	case errors.As(err, &maxBytesErr):
		return apperrors.BadRequest("BODY_TOO_LARGE",
			fmt.Sprintf("Request body must not exceed %d bytes", maxBytesErr.Limit))

	case strings.HasPrefix(err.Error(), "json: unknown field "):
		// encoding/json offers no typed error for this, so the string is all
		// we have. The field name is quoted in the message.
		field := strings.TrimPrefix(err.Error(), "json: unknown field ")
		return apperrors.BadRequest("UNKNOWN_FIELD",
			fmt.Sprintf("Request body contains unknown field %s", field))

	case errors.As(err, &invalidUnmar):
		// dst was not a pointer. A programming bug, not a client error.
		return apperrors.Internal(fmt.Errorf("handlers: bind called with non-pointer: %w", err))

	default:
		return apperrors.Wrap(err, apperrors.KindBadRequest, "MALFORMED_JSON",
			"Request body could not be parsed")
	}
}
