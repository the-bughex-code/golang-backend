package middlewares

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlsDummy is a non-nil ConnectionState. SecurityHeaders only checks r.TLS !=
// nil to decide whether the connection is encrypted; it never reads the fields.
var tlsDummy = tls.ConnectionState{}

// headersFor runs SecurityHeaders around a no-op handler and returns the
// response headers.
//
// It returns the headers rather than the *http.Response so that the body is
// closed here, once, instead of at every call site. The header map stays valid
// after the body is closed.
func headersFor(t *testing.T, path string, isProduction, tls bool) http.Header {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	if tls {
		r.TLS = &tlsDummy
	}
	w := httptest.NewRecorder()

	SecurityHeaders(isProduction)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(w, r)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	return res.Header
}

func TestSecurityHeaders_APIGetsTheStrictPolicy(t *testing.T) {
	t.Parallel()

	csp := headersFor(t, "/api/v1/users", false, false).Get("Content-Security-Policy")

	assert.Equal(t, apiCSP, csp)
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "sandbox")
	assert.NotContains(t, csp, "unsafe-inline",
		"a JSON response must never be allowed to run an inline script")
}

// The regression this guards against: apiCSP applied to /docs made Swagger UI
// render as a blank white page. The assets returned 200, the browser downloaded
// them, and then refused to execute anything. Nothing failed visibly.
func TestSecurityHeaders_DocsGetALoosePolicySoSwaggerUIRenders(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/docs", "/docs/", "/docs/index.html", "/docs/swagger-ui-bundle.js"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			csp := headersFor(t, path, false, false).Get("Content-Security-Policy")

			require.Equal(t, docsCSP, csp)
			// Swagger UI's index.html carries one inline <script> and one
			// inline <style>. Both must be permitted, or the page is blank.
			assert.Contains(t, csp, "script-src 'self' 'unsafe-inline'")
			assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
			assert.NotContains(t, csp, "sandbox")
		})
	}
}

// A path that merely starts with the letters "docs" is not the docs UI.
// HasPrefix("/docs") alone would hand /docsomething the loose policy.
func TestSecurityHeaders_LookalikePathsGetTheStrictPolicy(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/docsomething", "/docs-internal", "/api/v1/docs", "/"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, apiCSP, headersFor(t, path, false, false).Get("Content-Security-Policy"))
		})
	}
}

// In production /docs is not routed at all, so a request for it is a JSON 404
// and must carry the strict policy like any other JSON response.
func TestSecurityHeaders_ProductionNeverLoosensCSP(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/docs", "/docs/index.html", "/api/v1/users"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			csp := headersFor(t, path, true, false).Get("Content-Security-Policy")
			assert.Equal(t, apiCSP, csp)
			assert.NotContains(t, csp, "unsafe-inline")
		})
	}
}

func TestSecurityHeaders_AlwaysPresent(t *testing.T) {
	t.Parallel()

	h := headersFor(t, "/api/v1/users", false, false)

	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
	assert.NotEmpty(t, h.Get("Permissions-Policy"))
}

// HSTS pins a host as HTTPS-only in the browser for two years. Setting it on
// localhost would break every other project served over plain HTTP on that
// host, and it is very difficult to undo.
func TestSecurityHeaders_HSTSOnlyInProductionOverTLS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		isProduction bool
		tls          bool
		want         bool
	}{
		{"development, no tls", false, false, false},
		{"development, tls", false, true, false},
		{"production, no tls", true, false, false},
		{"production, tls", true, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hsts := headersFor(t, "/api/v1/users", tc.isProduction, tc.tls).
				Get("Strict-Transport-Security")

			if tc.want {
				assert.True(t, strings.HasPrefix(hsts, "max-age="), "expected HSTS, got %q", hsts)
			} else {
				assert.Empty(t, hsts)
			}
		})
	}
}
