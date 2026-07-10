// Package middlewares holds the functions that wrap every HTTP handler.
//
// A middleware is `func(http.Handler) http.Handler`: it receives the next
// handler in the chain and returns a new handler that does something before,
// after, or instead of calling it. Because the signature is from the standard
// library, these compose with any Go HTTP router — chi, gorilla, net/http
// itself — and any third-party middleware works here.
//
// # Order is behaviour, not style
//
// The chain in routes.go is not arbitrary. Recovery must be outermost or a
// panic in another middleware escapes it. The logger must run before
// authentication, or a rejected request is never logged. Rate limiting must run
// before authentication, or an attacker forces you to do bcrypt work for free.
package middlewares

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/the-bughex-code/golang-backend/internal/logger"
)

// RequestLogger logs one line per completed request and installs a
// request-scoped logger into the context.
//
// Every downstream log call — in a handler, a service, a repository — picks up
// that logger via logger.FromContext and therefore carries the same request_id
// automatically. That is what lets you reconstruct a single user's journey from
// a million interleaved lines.
func RequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// http.ResponseWriter does not expose the status code that was
			// written. chi's wrapper records it so we can log it.
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			reqID := middleware.GetReqID(r.Context())
			reqLog := log.With(slog.String("request_id", reqID))

			// Put the tagged logger where everything downstream can find it.
			r = r.WithContext(logger.IntoContext(r.Context(), reqLog))

			// The deferred call runs even if the handler panics, so a panicking
			// request still produces an access-log line. Recovery re-panics
			// after logging, and this defer fires on the way out.
			defer func() {
				attrs := []any{
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Duration("duration", time.Since(start)),
					slog.String("remote_addr", clientIP(r)),
				}

				switch {
				case isHealthCheck(r.URL.Path):
					// A load balancer probes /health every second. At info
					// level that is 86,400 useless lines a day, and it hides
					// the lines that matter.
					reqLog.Debug("request", attrs...)
				case ww.Status() >= http.StatusInternalServerError:
					reqLog.Error("request", attrs...)
				case ww.Status() >= http.StatusBadRequest:
					reqLog.Warn("request", attrs...)
				default:
					reqLog.Info("request", attrs...)
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func isHealthCheck(path string) bool {
	return strings.HasPrefix(path, "/health")
}

// clientIP returns the address to attribute a request to.
//
// It reads r.RemoteAddr — the peer of the actual TCP connection — and NOT the
// X-Forwarded-For header.
//
// # Why not X-Forwarded-For
//
// Any client can send `X-Forwarded-For: 1.2.3.4`. If you trust that header
// while your server is directly reachable, an attacker rotates a fake value on
// every request and your per-IP rate limiter becomes decorative.
//
// The header is only trustworthy when a proxy you control OVERWRITES it, and
// nothing can reach your server except through that proxy. If you deploy behind
// exactly one such load balancer, add chi's middleware.RealIP to the chain in
// routes.go — but only then.
func clientIP(r *http.Request) string {
	// RemoteAddr is "host:port"; strip the port so one client is one key.
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		host := r.RemoteAddr[:idx]
		// IPv6 literals arrive bracketed: [::1]:54321
		return strings.Trim(host, "[]")
	}
	return r.RemoteAddr
}
