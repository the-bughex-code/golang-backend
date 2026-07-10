// Package response defines the one JSON envelope every endpoint returns, and
// the only functions permitted to write to an http.ResponseWriter.
//
// # Why a single envelope
//
// Your Flutter client writes one decoder, once. Without an envelope, the
// client must know that POST /login returns a bare token object, GET /users
// returns a bare array, and an error returns {"error": "..."} — three shapes,
// three parsers, three chances to crash on a null.
//
// With an envelope, `ApiResponse<T>.fromJson` is written once and handles
// every endpoint, including every failure.
//
// # Why fields are not omitempty
//
// `data`, `errors`, `pagination` and `meta` are always present, carrying null
// when unused. The payload is a few bytes larger. In exchange, the client never
// has to distinguish "key absent" from "key null" — which in Dart are both
// `null` but in a code generator are different nullability rules. A stable
// shape is worth more than a stable byte count.
package response

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/logger"
)

// Envelope is the body of every response this API produces, success or failure.
type Envelope struct {
	// Success is the single field a client should branch on. It is redundant
	// with the HTTP status code on purpose: some proxies and SDKs swallow the
	// status, and a body that says success=false is impossible to misread.
	Success bool `json:"success"`

	// Message is human-readable and safe to display. It is not stable; do not
	// branch on it.
	Message string `json:"message"`

	// Data carries the payload on success, and is null on failure.
	Data any `json:"data"`

	// Errors carries per-field validation failures, and is null otherwise.
	// This is the only error detail ever echoed back verbatim.
	Errors []apperrors.FieldError `json:"errors"`

	// Pagination is present only on list endpoints.
	Pagination *Pagination `json:"pagination"`

	// Meta is an escape hatch for endpoint-specific extras that do not deserve
	// a top-level field.
	Meta map[string]any `json:"meta"`

	// Timestamp is the server's UTC clock at the moment of the response. Useful
	// for diagnosing client clock skew, which breaks token expiry checks.
	Timestamp time.Time `json:"timestamp"`

	// RequestID ties this response to the server logs. When a user reports a
	// bug, this string finds the exact request.
	RequestID string `json:"requestId"`
}

// Pagination describes the slice of a collection that Data contains.
type Pagination struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"perPage"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"totalPages"`
	HasNext    bool  `json:"hasNext"`
	HasPrev    bool  `json:"hasPrev"`
}

// NewPagination computes the derived fields so no caller has to.
func NewPagination(page, perPage int, total int64) *Pagination {
	if perPage < 1 {
		perPage = 1
	}
	totalPages := int((total + int64(perPage) - 1) / int64(perPage)) // ceiling division
	return &Pagination{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

// write is the single point where an Envelope becomes bytes on the wire.
func write(w http.ResponseWriter, r *http.Request, status int, env Envelope) {
	env.Timestamp = time.Now().UTC()
	env.RequestID = middleware.GetReqID(r.Context())

	// Marshal BEFORE writing the header. If encoding fails after
	// WriteHeader(200), the status is already sent and cannot be corrected;
	// the client receives a 200 with a truncated body.
	body, err := json.Marshal(env)
	if err != nil {
		logger.FromContext(r.Context()).Error("response: marshalling envelope failed",
			slog.String("error", err.Error()))
		http.Error(w, `{"success":false,"message":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Tell browsers not to sniff the content type. Without this, a response
	// whose body happens to look like HTML can be rendered as HTML, turning a
	// reflected value into stored XSS.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		// The client hung up mid-write. Nothing to do but note it. Do not try
		// to write an error: the header is long gone.
		logger.FromContext(r.Context()).Warn("response: writing body failed",
			slog.String("error", err.Error()))
	}
}

// OK writes 200 with a payload.
func OK(w http.ResponseWriter, r *http.Request, message string, data any) {
	write(w, r, http.StatusOK, Envelope{Success: true, Message: message, Data: data})
}

// Created writes 201. Use it when a request created a new resource.
func Created(w http.ResponseWriter, r *http.Request, message string, data any) {
	write(w, r, http.StatusCreated, Envelope{Success: true, Message: message, Data: data})
}

// NoContent writes 204 with no body at all.
//
// 204 is defined to have no body, so no envelope is sent. This is the one
// endpoint shape a client must special-case. Prefer 200 with a null Data unless
// you have a reason.
func NoContent(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// Paginated writes 200 with a collection and its pagination block.
func Paginated(w http.ResponseWriter, r *http.Request, message string, data any, p *Pagination) {
	write(w, r, http.StatusOK, Envelope{Success: true, Message: message, Data: data, Pagination: p})
}

// Error is the application's global error handler.
//
// Every handler ends either in a success writer or in this function. It is the
// only place that decides what a client learns about a failure.
//
// Behaviour:
//   - Any error is normalised to *apperrors.AppError. An unclassified error
//     becomes Internal, which is the safe default.
//   - Server faults (5xx) are logged at ERROR with the underlying cause.
//   - Client faults (4xx) are logged at WARN without the cause, because they
//     are not bugs and would otherwise drown real problems.
//   - The client receives only Kind, Code, Message and Fields. Never the cause.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	appErr := apperrors.From(err)
	status := appErr.HTTPStatus()

	log := logger.FromContext(r.Context())
	attrs := []any{
		slog.String("code", appErr.Code),
		slog.String("kind", appErr.Kind.String()),
		slog.Int("status", status),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}

	if status >= http.StatusInternalServerError {
		// appErr.Error() includes the wrapped cause. This string goes to the
		// log and never to the client.
		log.Error("request failed", append(attrs, slog.String("error", appErr.Error()))...)
	} else {
		log.Warn("request rejected", attrs...)
	}

	write(w, r, status, Envelope{
		Success: false,
		Message: appErr.Message,
		Errors:  appErr.Fields,
		Meta:    map[string]any{"code": appErr.Code},
	})
}
