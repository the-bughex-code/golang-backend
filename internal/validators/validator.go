// Package validators wraps go-playground/validator and converts its output
// into the application's own error type.
//
// # Why wrap it at all
//
// validator.ValidationErrors is a library type. If handlers inspected it
// directly, every handler would import the library, and swapping validators
// later would mean touching every handler. Worse, its default Error() string
// is unusable in a client response:
//
//	Key: 'RegisterRequest.Email' Error:Field validation for 'Email'
//	failed on the 'email' tag
//
// This package turns that into {"field":"email","message":"Must be a valid
// email address"} — once, here, for every endpoint. That is the DRY principle
// applied to error formatting.
//
// # Field names come from JSON tags, not Go field names
//
// A client that posted {"firstName": ""} must be told that `firstName` is
// invalid, not that `FirstName` is. RegisterTagNameFunc below makes the
// validator report the JSON name it actually received.
package validators

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
)

// Validator validates structs. It is safe for concurrent use and should be
// constructed once, at startup: the underlying validator caches struct
// reflection metadata, and throwing that away per-request is pure waste.
type Validator struct {
	v *validator.Validate
}

// New builds the validator and registers the project's conventions.
func New() *Validator {
	v := validator.New(validator.WithRequiredStructEnabled())

	// Report the JSON field name rather than the Go field name.
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})

	return &Validator{v: v}
}

// Struct validates s and returns nil, or an *apperrors.AppError of kind
// KindValidation carrying one FieldError per broken rule.
//
// Returning the application's error type — rather than the library's — means a
// handler's error path is always the same single line:
//
//	if err := v.Struct(req); err != nil { response.Error(w, r, err); return }
func (val *Validator) Struct(s any) error {
	err := val.v.Struct(s)
	if err == nil {
		return nil
	}

	// An InvalidValidationError means the caller passed something that is not
	// a struct. That is a programming bug, not a user error, so it must not
	// become a 422.
	//
	// errors.As, not a bare type assertion. `err.(*T)` inspects only the
	// outermost error; the moment anything wraps it with %w, the assertion
	// silently fails and this becomes a 500. errors.As walks the whole chain.
	var invalid *validator.InvalidValidationError
	if errors.As(err, &invalid) {
		return apperrors.Internal(fmt.Errorf("validators: %w", err))
	}

	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return apperrors.Internal(fmt.Errorf("validators: unexpected error: %w", err))
	}

	fields := make([]apperrors.FieldError, 0, len(verrs))
	for _, fe := range verrs {
		fields = append(fields, apperrors.FieldError{
			Field:   fe.Field(),
			Message: message(fe),
		})
	}
	return apperrors.Validation("The submitted data is invalid", fields...)
}

// message renders one failed rule as a sentence a user can act on.
//
// The default library message names the tag ("failed on the 'gte' tag"), which
// is meaningless to anyone who has not read the library's documentation.
func message(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Must be a valid email address"
	case "min":
		if fe.Kind() == reflect.String {
			return fmt.Sprintf("Must be at least %s characters", fe.Param())
		}
		return fmt.Sprintf("Must be at least %s", fe.Param())
	case "max":
		if fe.Kind() == reflect.String {
			return fmt.Sprintf("Must be at most %s characters", fe.Param())
		}
		return fmt.Sprintf("Must be at most %s", fe.Param())
	case "uuid", "uuid4", "uuid7":
		return "Must be a valid UUID"
	case "eqfield":
		return fmt.Sprintf("Must match %s", strings.ToLower(fe.Param()))
	case "nefield":
		return fmt.Sprintf("Must be different from %s", strings.ToLower(fe.Param()))
	case "oneof":
		return fmt.Sprintf("Must be one of: %s", strings.ReplaceAll(fe.Param(), " ", ", "))
	case "gte":
		return fmt.Sprintf("Must be %s or greater", fe.Param())
	case "lte":
		return fmt.Sprintf("Must be %s or less", fe.Param())
	case "alphanum":
		return "Must contain only letters and numbers"
	default:
		// A rule with no bespoke message still produces something readable
		// rather than leaking the tag name alone.
		return fmt.Sprintf("Failed the '%s' rule", fe.Tag())
	}
}
