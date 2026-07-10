// Package routes maps URLs to handlers and decides which middleware guards
// which endpoint.
//
// It is the security-critical file in this project. Everything else can be
// correct, and a route mounted outside its authentication group is still a data
// breach. Read this file in a code review before you read any handler.
package routes

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/the-bughex-code/golang-backend/docs"
	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/config"
	"github.com/the-bughex-code/golang-backend/internal/dto/response"
	"github.com/the-bughex-code/golang-backend/internal/handlers"
	"github.com/the-bughex-code/golang-backend/internal/middlewares"
	"github.com/the-bughex-code/golang-backend/internal/models"
	"github.com/the-bughex-code/golang-backend/internal/services"
)

// Dependencies is everything the router needs, supplied by the composition root
// in cmd/api/main.go.
//
// A struct rather than a long parameter list: adding a handler later becomes a
// one-line change here and one line in main, instead of a signature change that
// ripples through every caller.
type Dependencies struct {
	Config *config.Config
	Logger *slog.Logger
	Tokens *services.TokenService

	Health  *handlers.HealthHandler
	Auth    *handlers.AuthHandler
	Profile *handlers.ProfileHandler
	Users   *handlers.UserHandler
}

// New builds the HTTP handler for the whole application.
//
// ctx is the application's lifetime context. It is handed to the rate limiter
// so its background cleanup goroutine stops when the server shuts down.
func New(ctx context.Context, d Dependencies) http.Handler {
	r := chi.NewRouter()

	// ── Global middleware chain ────────────────────────────────────────────
	//
	// Order is behaviour. Each line explains why it is where it is.

	// 1. Assign an id before anything else, so every log line and every error
	//    response — including one produced by a panic — can be correlated.
	//    Honours an inbound X-Request-Id, so a mobile client can supply its own
	//    and match its logs to yours.
	r.Use(chimw.RequestID)

	// 2. Log every request, and install a request-scoped logger into the
	//    context. Before Recover, so a panicking request is still logged, and
	//    so Recover finds the tagged logger.
	r.Use(middlewares.RequestLogger(d.Logger))

	// 3. Catch panics from here down. Turns a dropped connection into a proper
	//    500 with the standard envelope.
	r.Use(middlewares.Recover)

	// 4. Security headers on every response, including error responses. Placed
	//    before CORS so that even a rejected preflight carries them.
	r.Use(middlewares.SecurityHeaders(d.Config.App.Env.IsProduction()))

	// 5. CORS. Must run before routing, because a browser's preflight is an
	//    OPTIONS request to a path that may not have an OPTIONS handler.
	r.Use(middlewares.CORS(d.Config.CORS))

	// 6. Rate limiting. Before authentication, so an unauthenticated flood is
	//    rejected without the server doing any real work.
	r.Use(middlewares.RateLimit(ctx,
		d.Config.RateLimit.Enabled,
		d.Config.RateLimit.RequestsPerSecond,
		d.Config.RateLimit.Burst))

	// 7. A deadline on every request's context. When it fires, ctx is
	//    cancelled, and pgx aborts the in-flight query rather than letting it
	//    run to completion for a client that has already given up.
	//
	//    Kept just under the server's WriteTimeout so the handler gets a chance
	//    to write a timeout response before net/http closes the connection.
	r.Use(chimw.Timeout(handlerTimeout(d.Config.Server.WriteTimeout)))

	// ── Fallbacks ─────────────────────────────────────────────────────────
	//
	// chi's defaults write a bare `404 page not found` in text/plain. A client
	// that parses our envelope would choke on it. These make every response
	// from this server — including the ones we never wrote a handler for —
	// the same shape.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, r, apperrors.New(apperrors.KindNotFound, "ROUTE_NOT_FOUND",
			"The requested endpoint does not exist"))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, r, apperrors.New(apperrors.KindMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"This method is not allowed on this endpoint"))
	})

	// ── Health probes ─────────────────────────────────────────────────────
	//
	// Deliberately OUTSIDE /api/v1. They are not part of your public API, they
	// are not versioned, and they must not be broken by an API version bump.
	// They are also unauthenticated: a load balancer has no credentials.
	r.Route("/health", func(r chi.Router) {
		r.Get("/live", d.Health.Live)
		r.Get("/ready", d.Health.Ready)
	})

	// ── API documentation ─────────────────────────────────────────────────
	//
	// Served only outside production. A public endpoint that enumerates every
	// route, every parameter and every error code is a gift to an attacker,
	// and it is not something your customers need.
	//
	// In production, publish the generated docs/swagger.json to an internal
	// developer portal instead.
	if !d.Config.App.Env.IsProduction() {
		// Redirect the bare /docs to the UI, so the obvious URL works.
		r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
		})

		// Serve the embedded spec ourselves.
		//
		// httpSwagger would otherwise try to serve /docs/doc.json out of swag
		// v1's global registry, which our OpenAPI 3.1 document never enters.
		// chi matches a static segment before a wildcard, so this route wins
		// over /docs/* below.
		r.Get("/docs/doc.json", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(docs.SwaggerJSON)
		})

		// Everything else under /docs/ is Swagger UI's own assets, embedded in
		// the httpSwagger package. No CDN, no network access required.
		r.Get("/docs/*", httpSwagger.Handler(
			httpSwagger.URL("/docs/doc.json"),
			httpSwagger.DeepLinking(true),
		))
	}

	// ── Versioned API ─────────────────────────────────────────────────────
	//
	// Why version in the URL path rather than in a header:
	//
	//   It is visible in a log, a browser address bar, and a curl command. You
	//   can run v1 and v2 side by side and delete v1 when its traffic reaches
	//   zero — which you can measure, because it is in the path.
	//
	//   Header versioning (Accept: application/vnd.api.v2+json) is more
	//   RESTfully pure and much harder to debug at 3am.
	//
	// Never break v1. Add v2.
	r.Route("/api/v1", func(r chi.Router) {
		// ── Public: no token required ─────────────────────────────────────
		r.Route("/auth", func(r chi.Router) {
			// A second, far stricter limiter, stacked on top of the global one.
			// This is what stands between an attacker and unlimited password
			// guesses. Every rejected request here costs them a round trip and
			// costs us nothing.
			r.Use(middlewares.RateLimit(ctx,
				d.Config.RateLimit.Enabled,
				d.Config.RateLimit.AuthRequestsPerSecond,
				d.Config.RateLimit.AuthBurst))

			r.Post("/register", d.Auth.Register)
			r.Post("/login", d.Auth.Login)

			// Unauthenticated on purpose: the caller's access token has expired,
			// which is precisely why they are here. The refresh token in the
			// body is the credential.
			r.Post("/refresh", d.Auth.Refresh)
			r.Post("/logout", d.Auth.Logout)

			// Also unauthenticated: a user who has not verified their address
			// may not yet have signed in, and the token in the body is itself
			// the credential. Both sit inside the strict auth rate limiter.
			r.Post("/verify-email", d.Auth.VerifyEmail)
			r.Post("/resend-verification", d.Auth.ResendVerification)
		})

		// ── Authenticated: a valid access token is required ────────────────
		//
		// chi's Group creates a new middleware stack for the routes inside it
		// without changing the URL path. Everything below this line is behind
		// Authenticate. Adding a route inside this block is safe by default;
		// adding one outside it is public by default.
		r.Group(func(r chi.Router) {
			r.Use(middlewares.Authenticate(d.Tokens))

			// The caller acting on their OWN record. The user id comes from the
			// verified token, so no permission check is needed — there is no id
			// a caller could supply to reach someone else.
			r.Route("/profile", func(r chi.Router) {
				r.Get("/", d.Profile.Me)
				r.Patch("/", d.Profile.Update)
				r.Post("/change-password", d.Profile.ChangePassword)
			})

			// The caller acting on OTHER people's records. Every route asserts
			// the capability it needs — never the role that happens to have it
			// today. See middlewares.RequirePermission.
			r.Route("/users", func(r chi.Router) {
				r.With(middlewares.RequirePermission(models.PermissionUsersRead)).
					Get("/", d.Users.List)
				r.With(middlewares.RequirePermission(models.PermissionUsersRead)).
					Get("/{id}", d.Users.GetByID)
				r.With(middlewares.RequirePermission(models.PermissionUsersDelete)).
					Delete("/{id}", d.Users.Delete)
				r.With(middlewares.RequirePermission(models.PermissionRolesAssign)).
					Post("/{id}/roles", d.Users.AssignRole)
			})

			r.With(middlewares.RequirePermission(models.PermissionRolesRead)).
				Get("/roles", d.Users.ListRoles)
		})
	})

	return r
}

// handlerTimeout keeps the per-request deadline strictly below the server's
// WriteTimeout, so the handler can write a response before net/http gives up.
func handlerTimeout(writeTimeout time.Duration) time.Duration {
	const margin = time.Second
	if writeTimeout > 2*margin {
		return writeTimeout - margin
	}
	return writeTimeout
}
