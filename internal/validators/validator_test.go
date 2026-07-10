package validators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
)

type sample struct {
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"  validate:"required,min=8,max=72"`
	FirstName string `json:"firstName" validate:"required"`
	Age       int    `json:"age"       validate:"gte=0,lte=130"`
}

func TestStruct_Valid(t *testing.T) {
	t.Parallel()
	v := New()

	assert.NoError(t, v.Struct(&sample{
		Email: "a@b.com", Password: "long-enough", FirstName: "Alice", Age: 30,
	}))
}

// The field names in the response must be the JSON names the client sent,
// not the Go struct field names. A client that posted "firstName" cannot act
// on an error about "FirstName".
func TestStruct_ReportsJSONFieldNames(t *testing.T) {
	t.Parallel()
	v := New()

	err := v.Struct(&sample{Email: "not-an-email", Password: "short", Age: 200})
	require.Error(t, err)

	appErr := apperrors.From(err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindValidation))
	assert.Equal(t, 422, appErr.HTTPStatus(), "a semantically invalid body is 422, not 400")

	fields := make(map[string]string, len(appErr.Fields))
	for _, f := range appErr.Fields {
		fields[f.Field] = f.Message
	}

	assert.Equal(t, "Must be a valid email address", fields["email"])
	assert.Equal(t, "Must be at least 8 characters", fields["password"])
	assert.Equal(t, "This field is required", fields["firstName"])
	assert.Equal(t, "Must be 130 or less", fields["age"])

	// And never the Go names.
	assert.NotContains(t, fields, "Email")
	assert.NotContains(t, fields, "FirstName")
}

// Every rule the project uses must produce a human sentence, never the raw tag
// name. This test fails the moment someone adds a tag without a message.
func TestStruct_AllMessagesAreHuman(t *testing.T) {
	t.Parallel()
	v := New()

	err := v.Struct(&sample{})
	require.Error(t, err)

	for _, f := range apperrors.From(err).Fields {
		assert.NotContains(t, f.Message, "Failed the",
			"field %q fell through to the default message; add a case to message()", f.Field)
	}
}

// Passing a non-struct is a programming bug, not a user error. It must become a
// 500 that someone investigates, never a 422 blamed on the client.
func TestStruct_NonStructIsInternalError(t *testing.T) {
	t.Parallel()
	v := New()

	err := v.Struct("this is a string, not a struct")
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindInternal))
	assert.Equal(t, 500, apperrors.From(err).HTTPStatus())
}

func TestStruct_NefieldRule(t *testing.T) {
	t.Parallel()
	v := New()

	type changePassword struct {
		Current string `json:"currentPassword" validate:"required"`
		New     string `json:"newPassword"     validate:"required,nefield=Current"`
	}

	assert.NoError(t, v.Struct(&changePassword{Current: "old-one", New: "new-one"}))

	err := v.Struct(&changePassword{Current: "same", New: "same"})
	require.Error(t, err)
	assert.Equal(t, "newPassword", apperrors.From(err).Fields[0].Field)
}
