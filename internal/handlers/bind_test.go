package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/validators"
)

type payload struct {
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name"  validate:"required"`
}

// Normalize is exercised by TestBind_NormalizesBeforeValidating below.
func (p *payload) Normalize() {
	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	p.Name = strings.TrimSpace(p.Name)
}

// newRequest builds a POST with the given body and content type.
//
// NewRequestWithContext rather than NewRequest: t.Context() is cancelled when
// the test finishes, so a handler that leaks a goroutine blocked on the request
// context is unblocked rather than hanging the suite.
func newRequest(t *testing.T, body, contentType string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewBufferString(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return httptest.NewRecorder(), r
}

func TestBind_Success(t *testing.T) {
	t.Parallel()
	v := validators.New()
	w, r := newRequest(t, `{"email":"a@b.com","name":"Alice"}`, "application/json")

	var got payload
	require.NoError(t, bind(w, r, v, &got))
	assert.Equal(t, "a@b.com", got.Email)
	assert.Equal(t, "Alice", got.Name)
}

// The bug this catches: validating before trimming rejects a copy-pasted email
// that is perfectly acceptable once cleaned.
func TestBind_NormalizesBeforeValidating(t *testing.T) {
	t.Parallel()
	v := validators.New()
	w, r := newRequest(t, `{"email":"  Alice@Example.COM  ","name":"  Alice  "}`, "application/json")

	var got payload
	require.NoError(t, bind(w, r, v, &got), "whitespace must not make a valid email invalid")
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "Alice", got.Name)
}

// Mass assignment: a client sending a field the DTO does not have gets a clear
// 400 rather than having it silently ignored.
func TestBind_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	v := validators.New()
	w, r := newRequest(t, `{"email":"a@b.com","name":"Alice","isAdmin":true}`, "application/json")

	var got payload
	err := bind(w, r, v, &got)
	require.Error(t, err)

	appErr := apperrors.From(err)
	assert.Equal(t, "UNKNOWN_FIELD", appErr.Code)
	assert.Equal(t, 400, appErr.HTTPStatus())
	assert.Contains(t, appErr.Message, "isAdmin")
}

func TestBind_RejectsSecondJSONValue(t *testing.T) {
	t.Parallel()
	v := validators.New()
	// The second object would otherwise be silently discarded.
	w, r := newRequest(t, `{"email":"a@b.com","name":"A"}{"email":"evil@b.com","name":"E"}`, "application/json")

	var got payload
	err := bind(w, r, v, &got)
	require.Error(t, err)
	assert.Equal(t, "MALFORMED_JSON", apperrors.From(err).Code)
}

func TestBind_ErrorTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		body        string
		contentType string
		wantCode    string
		wantStatus  int
	}{
		{"empty body", "", "application/json", "EMPTY_BODY", 400},
		{"malformed json", `{"email":`, "application/json", "MALFORMED_JSON", 400},
		{"wrong content type", `{"email":"a@b.com","name":"A"}`, "text/plain", "UNSUPPORTED_MEDIA_TYPE", 400},
		{"validation failure", `{"email":"nope","name":""}`, "application/json", "VALIDATION_FAILED", 422},
		{"wrong field type", `{"email":123,"name":"A"}`, "application/json", "VALIDATION_FAILED", 422},
	}

	v := validators.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, r := newRequest(t, tc.body, tc.contentType)

			var got payload
			err := bind(w, r, v, &got)
			require.Error(t, err)

			appErr := apperrors.From(err)
			assert.Equal(t, tc.wantCode, appErr.Code)
			assert.Equal(t, tc.wantStatus, appErr.HTTPStatus())
		})
	}
}

// A body larger than maxBodyBytes must be rejected without buffering all of it.
func TestBind_RejectsOversizedBody(t *testing.T) {
	t.Parallel()
	v := validators.New()

	huge := `{"email":"a@b.com","name":"` + strings.Repeat("x", maxBodyBytes+1024) + `"}`
	w, r := newRequest(t, huge, "application/json")

	var got payload
	err := bind(w, r, v, &got)
	require.Error(t, err)
	assert.Equal(t, "BODY_TOO_LARGE", apperrors.From(err).Code)
}

// A missing Content-Type is tolerated: some HTTP clients omit it, and the JSON
// decoder will reject the body anyway if it is not JSON.
func TestBind_AllowsMissingContentType(t *testing.T) {
	t.Parallel()
	v := validators.New()
	w, r := newRequest(t, `{"email":"a@b.com","name":"Alice"}`, "")

	var got payload
	assert.NoError(t, bind(w, r, v, &got))
}

// Content-Type with a charset parameter is still application/json.
func TestBind_AllowsContentTypeWithCharset(t *testing.T) {
	t.Parallel()
	v := validators.New()
	w, r := newRequest(t, `{"email":"a@b.com","name":"Alice"}`, "application/json; charset=utf-8")

	var got payload
	assert.NoError(t, bind(w, r, v, &got))
}
