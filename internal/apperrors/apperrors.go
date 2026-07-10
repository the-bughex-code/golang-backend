// Package apperrors defines the single error type that crosses layer
// boundaries in this application, plus constructors for each failure category.
//
// # The problem this solves
//
// A repository knows it got Postgres SQLSTATE 23505. An HTTP handler needs to
// send 409 Conflict. Without a shared vocabulary, one of two bad things
// happens: either the repository imports net/http and starts caring about
// status codes, or the handler imports pgx and starts decoding SQLSTATE. Both
// destroy the layering.
//
// AppError is that shared vocabulary. Repositories translate storage errors
// into an AppError. Services create AppErrors for business-rule violations.
// Exactly one place — the response writer — translates AppError into HTTP.
//
// # The two-message rule
//
// Every AppError carries two pieces of text:
//
//	Message  what the client is allowed to read
//	err      the wrapped cause, for your logs only
//
// This separation is a security control, not a style choice. "pq: duplicate key
// value violates unique constraint \"users_email_key\"" tells an attacker your
// table name, your column name, and your index name. "Email already registered"
// tells them nothing they did not already know.
//
// # Why not sentinel errors alone
//
// Sentinel errors (var ErrNotFound = errors.New("not found")) compare cheaply
// with errors.Is, but carry no context: which resource, which id, what to tell
// the user. AppError keeps errors.Is working via Unwrap while adding that
// context. Use both: sentinels for identity, AppError for detail.
package apperrors

import (
	"errors"
	"fmt"
	"net/http"
)

// Kind classifies a failure. It is deliberately a small, closed set: every kind
// maps to exactly one HTTP status, and adding one is a deliberate act.
type Kind uint8

// The complete set of failure categories. Each maps to exactly one HTTP status;
// see Kind.HTTPStatus.
const (
	// KindInternal is the zero value on purpose. An error whose kind was never
	// set is treated as a server fault, which is the safe default: it gets
	// logged loudly and reported to the client as a generic 500.
	KindInternal Kind = iota
	KindValidation
	KindBadRequest
	KindUnauthorized
	KindForbidden
	KindNotFound
	KindMethodNotAllowed
	KindConflict
	KindRateLimited
	KindUnavailable
)

// String makes Kind printable in logs.
func (k Kind) String() string {
	switch k {
	case KindValidation:
		return "validation"
	case KindBadRequest:
		return "bad_request"
	case KindUnauthorized:
		return "unauthorized"
	case KindForbidden:
		return "forbidden"
	case KindNotFound:
		return "not_found"
	case KindMethodNotAllowed:
		return "method_not_allowed"
	case KindConflict:
		return "conflict"
	case KindRateLimited:
		return "rate_limited"
	case KindUnavailable:
		return "unavailable"
	default:
		return "internal"
	}
}

// HTTPStatus is the one and only place a Kind becomes an HTTP status code.
func (k Kind) HTTPStatus() int {
	switch k {
	case KindValidation:
		// 422, not 400. The request was syntactically valid JSON that we
		// understood; it failed our semantic rules. 400 means "I could not
		// even parse this".
		return http.StatusUnprocessableEntity
	case KindBadRequest:
		return http.StatusBadRequest
	case KindUnauthorized:
		// "Unauthorized" is a misnomer baked into the HTTP spec: 401 means
		// *unauthenticated* — we do not know who you are.
		return http.StatusUnauthorized
	case KindForbidden:
		// 403 means we know who you are, and you may not do this.
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindMethodNotAllowed:
		// 405, not 400. The URL exists; the verb does not. A client that gets
		// 400 assumes its body was wrong and retries with the same verb forever.
		return http.StatusMethodNotAllowed
	case KindConflict:
		return http.StatusConflict
	case KindRateLimited:
		return http.StatusTooManyRequests
	case KindUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// FieldError describes one failed validation rule on one input field.
// It is the only error detail ever echoed back to a client verbatim.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// AppError is the application's error type. It satisfies the standard error
// interface and supports errors.Is / errors.As through Unwrap.
type AppError struct {
	// Kind selects the HTTP status and the log severity.
	Kind Kind

	// Code is a stable, machine-readable identifier such as "EMAIL_TAKEN".
	// Clients should branch on this, never on Message, which is free to change
	// and to be translated.
	Code string

	// Message is safe to show a user. It must never contain a SQL statement,
	// a stack trace, a file path, or an internal identifier.
	Message string

	// Fields carries per-field validation failures. Populated only when
	// Kind is KindValidation.
	Fields []FieldError

	// err is the underlying cause. It goes to the logs. It never reaches
	// the client.
	err error
}

// Error implements the error interface. The result is for logs and tests, not
// for users — it deliberately includes the internal cause.
func (e *AppError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s[%s]: %s: %v", e.Kind, e.Code, e.Message, e.err)
	}
	return fmt.Sprintf("%s[%s]: %s", e.Kind, e.Code, e.Message)
}

// Unwrap exposes the cause so errors.Is and errors.As can walk the chain.
// This is what lets a handler ask errors.Is(err, pgx.ErrNoRows) even though
// the error it holds is an *AppError.
func (e *AppError) Unwrap() error { return e.err }

// HTTPStatus is a convenience passthrough to Kind.HTTPStatus.
func (e *AppError) HTTPStatus() int { return e.Kind.HTTPStatus() }

// WithField appends a validation field error and returns the receiver, so
// construction reads as a single expression.
func (e *AppError) WithField(field, message string) *AppError {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: message})
	return e
}

// ---------------------------------------------------------------------------
// Constructors
//
// Each takes the client-safe message. Use the Wrap* variants when you have an
// underlying cause worth logging.
// ---------------------------------------------------------------------------

// New builds an AppError with no underlying cause. Use it when this code is the
// origin of the failure, not the messenger.
func New(kind Kind, code, message string) *AppError {
	return &AppError{Kind: kind, Code: code, Message: message}
}

// Wrap attaches an underlying cause. The cause is logged; it is never sent to
// the client.
func Wrap(err error, kind Kind, code, message string) *AppError {
	return &AppError{Kind: kind, Code: code, Message: message, err: err}
}

// Validation reports one or more broken input rules. Renders as 422, and its
// Fields are the only error detail echoed back to a client verbatim.
func Validation(message string, fields ...FieldError) *AppError {
	return &AppError{Kind: KindValidation, Code: "VALIDATION_FAILED", Message: message, Fields: fields}
}

// BadRequest reports a request we could not even parse or interpret. Renders
// as 400. For a request we understood but rejected, use Validation.
func BadRequest(code, message string) *AppError {
	return New(KindBadRequest, code, message)
}

// Unauthorized reports that we do not know who the caller is. Renders as 401,
// which the HTTP spec misnames: it means unauthenticated, not unauthorised.
func Unauthorized(code, message string) *AppError {
	return New(KindUnauthorized, code, message)
}

// Forbidden reports that we know who the caller is and they may not do this.
// Renders as 403.
func Forbidden(code, message string) *AppError {
	return New(KindForbidden, code, message)
}

// NotFound produces a message of the form "user not found".
func NotFound(resource string) *AppError {
	return New(KindNotFound, "NOT_FOUND", resource+" not found")
}

// Conflict reports a well-formed request that clashes with current state, such
// as registering an email that already exists. Renders as 409.
func Conflict(code, message string) *AppError {
	return New(KindConflict, code, message)
}

// RateLimited reports that the caller has exceeded their quota. Renders as 429.
func RateLimited(message string) *AppError {
	return New(KindRateLimited, "RATE_LIMITED", message)
}

// Internal is the catch-all for faults that are our problem, not the client's.
// The message sent to the client is intentionally uninformative; the real cause
// lives in err and reaches the logs.
func Internal(err error) *AppError {
	return Wrap(err, KindInternal, "INTERNAL_ERROR", "An unexpected error occurred")
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

// From converts any error into an *AppError.
//
// If err already is (or wraps) an *AppError, that value is returned unchanged,
// preserving its Kind, Code, Message and Fields. Anything else becomes an
// Internal error, which is the safe default: an error we did not deliberately
// classify is, by definition, one we did not expect.
//
// This is what makes the global error handler in the HTTP layer a three-line
// function.
func From(err error) *AppError {
	if err == nil {
		return nil
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return Internal(err)
}

// IsKind reports whether err is, or wraps, an *AppError of the given kind.
func IsKind(err error, kind Kind) bool {
	var appErr *AppError
	return errors.As(err, &appErr) && appErr.Kind == kind
}
