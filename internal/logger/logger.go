// Package logger builds the application's structured logger and carries a
// request-scoped logger through context.
//
// # Why log/slog and not zap or zerolog
//
// slog entered the standard library in Go 1.21. For a typical API it is fast
// enough that logging will never be your bottleneck, and it has one decisive
// advantage: it is the interface every future Go library will accept. Zap is
// faster in microbenchmarks; if you are ever writing enough logs for that gap
// to matter, the fix is to write fewer logs, not to swap the library.
//
// # Why structured logging at all
//
// A line like `user 42 failed login from 1.2.3.4` cannot be searched, counted,
// or alerted on without a regular expression that breaks the moment someone
// rewords it. The structured form
//
//	{"msg":"login failed","user_id":42,"ip":"1.2.3.4"}
//
// can be queried directly: `msg="login failed" | count by ip`. In production
// this is the difference between finding an incident and guessing at it.
//
// # Redaction is enforced here, not at the call site
//
// Relying on every developer to remember never to log a password is relying on
// a human. ReplaceAttr intercepts a set of sensitive keys and replaces their
// values before they are ever written. A slip becomes "[REDACTED]" instead of
// a credential in your log aggregator.
package logger

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// sensitiveKeys are attribute names whose values are replaced with [REDACTED]
// no matter where they are logged from. Matching is case-insensitive and
// substring-based, so "user_password" and "Authorization" both match.
var sensitiveKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"authorization",
	"cookie",
	"api_key",
	"apikey",
	"refresh_token",
	"access_token",
	"credit_card",
}

const redacted = "[REDACTED]"

// New builds a slog.Logger.
//
// format "json" emits one JSON object per line, which is what log aggregators
// (Loki, CloudWatch, Datadog) expect. format "text" emits aligned key=value
// pairs, which is what a human reading a terminal wants. Use text locally and
// json everywhere else.
//
// The logger is deliberately not a package-level global. It is constructed in
// main and passed down explicitly, so a test can hand any component a logger
// that writes to a buffer.
func New(level, format string, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),

		// AddSource attaches file:line to every record. It costs a stack walk
		// per log call, so it is enabled only at debug level, where you are
		// already trading performance for insight.
		AddSource: parseLevel(level) == slog.LevelDebug,

		ReplaceAttr: redactSensitive,
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// redactSensitive is called by slog for every attribute of every record.
func redactSensitive(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(key, sensitive) {
			return slog.String(a.Key, redacted)
		}
	}
	return a
}

// ---------------------------------------------------------------------------
// Request-scoped logging
//
// Every log line emitted while handling a request should carry that request's
// id, so that a single user's journey can be reconstructed from a million
// interleaved lines. We do that by storing a logger — already tagged with the
// request id — in the request context.
// ---------------------------------------------------------------------------

// ctxKey is an unexported struct type. This is the standard Go idiom for
// context keys: because the type is unexported, no other package can construct
// a colliding key, even by accident. A string key like "logger" could silently
// collide with a key set by a third-party library.
type ctxKey struct{}

// IntoContext returns a copy of ctx carrying the given logger.
func IntoContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext retrieves the request-scoped logger.
//
// It never returns nil. If no logger was stored — which happens in unit tests
// that construct a bare context — it falls back to slog.Default(). Code that
// logs should not have to nil-check.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
