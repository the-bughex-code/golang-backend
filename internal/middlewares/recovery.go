package middlewares

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/the-bughex-code/backend/internal/apperrors"
	"github.com/the-bughex-code/backend/internal/dto/response"
	"github.com/the-bughex-code/backend/internal/logger"
)

// Recover turns a panic in any handler into a logged 500 response.
//
// # Why this is not optional
//
// Go's net/http server already recovers from a panicking handler: it logs the
// stack and closes the connection. From the client's perspective that is an
// abruptly dropped request with no status code and no body — a Flutter app sees
// a SocketException, not an error it can display.
//
// This middleware turns the same panic into a normal 500 carrying the standard
// envelope, so the client's single error path handles it like any other
// failure, complete with a requestId the user can quote to support.
//
// # Where it goes in the chain
//
// A panic inside a middleware that runs BEFORE Recover escapes it: a deferred
// function only covers frames already on the stack. So Recover must wrap
// everything that could panic — which is everything downstream of it.
//
// Exactly two middlewares sit outside it, both deliberately:
//
//	RequestID      so the 500 response carries an id the user can quote.
//	RequestLogger  so the panicking request still produces an access-log line,
//	               and so the logger it installs in the context is the one this
//	               function retrieves. Neither of them can panic.
//
// Everything else — security headers, CORS, rate limiting, authentication,
// handlers — is inside.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}

			// http.ErrAbortHandler is not an error: it is how a handler says
			// "stop, silently". net/http expects to see it, so re-panic and
			// let the server handle it. Swallowing it would log a bogus 500
			// for every aborted request.
			if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, per net/http docs
				panic(rec)
			}

			log := logger.FromContext(r.Context())

			// debug.Stack() captures the stack at the point of recovery, which
			// still includes the panicking frames. Capturing it later, or in
			// the response writer, would show only this function.
			log.Error("panic recovered",
				slog.Any("panic", rec),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("stack", string(debug.Stack())),
			)

			// apperrors.Internal ensures the client sees the generic message.
			// The panic value itself may contain a database DSN, a token, or a
			// file path, and must never be echoed.
			response.Error(w, r, apperrors.Internal(fmt.Errorf("panic: %v", rec)))
		}()

		next.ServeHTTP(w, r)
	})
}
