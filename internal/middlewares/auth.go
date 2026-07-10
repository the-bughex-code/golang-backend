package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/the-bughex-code/backend/internal/apperrors"
	"github.com/the-bughex-code/backend/internal/dto/response"
	"github.com/the-bughex-code/backend/internal/services"
)

// contextKey is an unexported type, so a key created here cannot collide with
// a key created by any other package — even one using the same string.
// This is the documented Go idiom; a bare string key is a latent bug.
type contextKey struct{ name string }

var claimsContextKey = &contextKey{"jwt-claims"}

// Authenticate verifies the Bearer token and stores its claims in the context.
//
// It answers "who are you?" — authentication. It does not answer "may you do
// this?" — that is RequirePermission, below. Conflating the two is how endpoints
// end up accidentally public.
func Authenticate(tokens *services.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := bearerToken(r)
			if err != nil {
				response.Error(w, r, err)
				return
			}

			claims, err := tokens.ParseAccessToken(raw)
			if err != nil {
				response.Error(w, r, err)
				return
			}

			// Fail closed: a token whose subject is not a UUID is malformed,
			// no matter that its signature checked out.
			if _, err := claims.UserID(); err != nil {
				response.Error(w, r, apperrors.Unauthorized("TOKEN_INVALID", "Invalid access token"))
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the credential from `Authorization: Bearer <token>`.
func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", apperrors.Unauthorized("TOKEN_MISSING", "Authorization header is required")
	}

	// RFC 7235 says the scheme is case-insensitive, so "bearer" and "BEARER"
	// are both valid and some HTTP clients do send them.
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", apperrors.Unauthorized("TOKEN_MALFORMED",
			"Authorization header must be in the form: Bearer <token>")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", apperrors.Unauthorized("TOKEN_MISSING", "Bearer token is empty")
	}
	return token, nil
}

// ClaimsFromContext returns the authenticated user's claims.
//
// The bool is false when the request did not pass through Authenticate. A
// handler behind Authenticate can ignore it; a handler that might be mounted
// publicly must check it.
func ClaimsFromContext(ctx context.Context) (*services.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*services.Claims)
	return claims, ok
}

// UserIDFromContext returns the authenticated user's id.
//
// It returns an Unauthorized error rather than a zero UUID when there are no
// claims. A zero UUID would be a valid-looking value that silently matches no
// row, turning a missing-auth bug into a confusing 404.
func UserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return uuid.Nil, apperrors.Unauthorized("NOT_AUTHENTICATED", "Authentication is required")
	}
	return claims.UserID()
}

// RequirePermission rejects a request whose token does not carry the named
// permission. It must be mounted after Authenticate.
//
// # Why permissions and not roles at the endpoint
//
// Writing RequireRole("admin") on twenty endpoints means that the day you add a
// "support" role which may read users but not delete them, you edit twenty
// handlers. Writing RequirePermission("users:read") means you edit one row in
// the role_permissions table.
//
// Endpoints should assert the CAPABILITY they need. Roles are how capabilities
// are bundled for humans, and that bundling belongs in data, not in code.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// Reaching here means RequirePermission was mounted without
				// Authenticate in front of it — a wiring bug. Fail closed.
				response.Error(w, r, apperrors.Unauthorized("NOT_AUTHENTICATED", "Authentication is required"))
				return
			}

			if !claims.HasPermission(permission) {
				// 403, not 404. Hiding the endpoint's existence behind a 404
				// is sometimes recommended, but it makes debugging miserable
				// and provides little real protection: the route is in your
				// public API documentation anyway.
				response.Error(w, r, apperrors.Forbidden("PERMISSION_DENIED",
					"You do not have permission to perform this action"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole rejects a request whose token does not carry the named role.
//
// Prefer RequirePermission. Use this only for genuinely role-shaped concepts,
// such as an admin-only diagnostics page that no permission cleanly describes.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !claims.HasRole(role) {
				response.Error(w, r, apperrors.Forbidden("ROLE_REQUIRED",
					"You do not have permission to perform this action"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
