package middlewares

import (
	"net/http"

	"github.com/go-chi/cors"

	"github.com/the-bughex-code/golang-backend/internal/config"
)

// SecurityHeaders sets response headers that instruct browsers to behave.
//
// Every header here is a browser directive. None of them affect curl, Postman,
// or a Flutter mobile app — those ignore all of it. They matter because your
// API will eventually be called from a web page, and because a JSON endpoint
// that reflects user input can be turned into an XSS vector if a browser is
// allowed to guess that the response is HTML.
func SecurityHeaders(isProduction bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// Do not guess the content type. Without this, a browser that
			// receives Content-Type: application/json whose body begins with
			// "<html>" may render it as HTML — turning a reflected username
			// into executed script.
			h.Set("X-Content-Type-Options", "nosniff")

			// Refuse to be embedded in a frame. Prevents clickjacking, where an
			// attacker overlays an invisible iframe of your app over their own
			// buttons. Superseded by CSP frame-ancestors, but still honoured by
			// older browsers.
			h.Set("X-Frame-Options", "DENY")

			// Do not leak the requested URL — which may contain an id or a
			// token — to third-party sites the user navigates to next.
			h.Set("Referrer-Policy", "no-referrer")

			// A JSON API never needs to load a script, a style, or an image.
			// Telling the browser it may load nothing at all means a response
			// that somehow gets rendered as HTML still cannot execute anything.
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")

			// Deny access to device APIs outright.
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// HSTS tells a browser to refuse plain HTTP to this host for the
			// next two years, defeating an attacker who strips TLS on a hostile
			// network.
			//
			// Set ONLY in production and ONLY over HTTPS. On localhost it would
			// pin http://localhost as HTTPS-only in your browser, breaking
			// every other project you develop on that host — and it is very
			// difficult to undo.
			if isProduction && r.TLS != nil {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS configures cross-origin access.
//
// # What CORS actually is
//
// A browser rule, enforced by the browser, not by your server. When a page on
// https://evil.com runs `fetch("https://api.yours.com/me")`, the browser sends
// the request, receives your response, and then REFUSES to hand the body to
// evil.com's JavaScript unless your response says evil.com is allowed.
//
// So CORS protects your users from other websites. It does not protect your
// server from anything: curl, Postman, a Go client and a Flutter mobile app all
// ignore CORS entirely, because they have no origin to protect.
//
// # What this means for you
//
//   - Flutter mobile (iOS/Android): CORS is irrelevant. It will never send an
//     Origin header and never enforce the response.
//   - Flutter Web: CORS is enforced. Your web build's origin must be listed.
//   - Never think of CORS as authentication. An open CORS policy does not let
//     anyone read data they could not already read with curl.
//
// # The wildcard trap
//
// AllowedOrigins=["*"] together with AllowCredentials=true is forbidden by the
// CORS specification, and browsers reject it. config.validate() refuses to boot
// a production build with that combination, rather than letting you discover it
// from a confusing browser console message.
func CORS(cfg config.CORSConfig) func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		AllowCredentials: cfg.AllowCredentials,

		// How long a browser may cache the preflight OPTIONS response. Without
		// it, a browser sends an extra round trip before every non-simple
		// request, doubling perceived latency.
		MaxAge: cfg.MaxAge,

		// Let the client read the request id from a response, so a web app can
		// show it in an error dialog.
		ExposedHeaders: []string{"X-Request-Id"},
	})
}
