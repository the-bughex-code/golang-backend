package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/database"
	"github.com/the-bughex-code/golang-backend/internal/dto/response"
)

// HealthHandler reports whether the process is alive and whether it can serve.
//
// # Liveness and readiness are different questions
//
// LIVENESS asks: is this process wedged? A deadlocked server answers nothing.
// An orchestrator that gets no answer RESTARTS the container. So liveness must
// never depend on anything external — if the database goes down and your
// liveness probe checks the database, every replica is killed and restarted in
// a loop, turning a recoverable database outage into a total outage.
//
// READINESS asks: should traffic be routed here right now? A process that
// cannot reach its database cannot serve requests, so it should be pulled from
// the load balancer — but NOT killed, because it will recover when the database
// does.
//
// This distinction is the single most common Kubernetes misconfiguration.
type HealthHandler struct {
	db      *database.DB
	version string
	started time.Time
}

// NewHealthHandler builds the liveness and readiness probes. version is
// stamped into the response so you can confirm which build is serving.
func NewHealthHandler(db *database.DB, version string) *HealthHandler {
	return &HealthHandler{db: db, version: version, started: time.Now()}
}

// Live answers "is the process running?" and touches nothing external.
//
//	@Summary		Liveness probe
//	@Description	Answers "is the process running?". Touches nothing external, deliberately:
//	@Description	a liveness probe that checks the database turns a database outage into a
//	@Description	container restart loop.
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	response.Envelope
//	@Router			/health/live [get]
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	response.OK(w, r, "Service is alive", map[string]any{
		"status":  "ok",
		"version": h.version,
		"uptime":  time.Since(h.started).Round(time.Second).String(),
	})
}

// Ready answers "can this process serve a real request?" and therefore checks
// its dependencies.
//
//	@Summary		Readiness probe
//	@Description	Answers "can this process serve a request?". Pings the database. A failure
//	@Description	should remove the instance from the load balancer, not restart it.
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	response.Envelope
//	@Failure		503	{object}	response.Envelope	"DATABASE_UNAVAILABLE"
//	@Router			/health/ready [get]
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	// A short, independent deadline. If the database is hanging, the probe must
	// still answer promptly — the orchestrator has its own timeout, and a probe
	// that hangs is indistinguishable from a probe that fails, except that it
	// occupies a connection while it does so.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.db.Ping(ctx); err != nil {
		// 503, and the client is told which dependency is down — this endpoint
		// is for your own infrastructure, not for end users.
		response.Error(w, r, apperrors.Wrap(err, apperrors.KindUnavailable,
			"DATABASE_UNAVAILABLE", "Service is not ready: database is unreachable"))
		return
	}

	stats := h.db.Stats()
	response.OK(w, r, "Service is ready", map[string]any{
		"status":  "ok",
		"version": h.version,
		"database": map[string]any{
			"status":               "up",
			"total_connections":    stats.TotalConns(),
			"idle_connections":     stats.IdleConns(),
			"acquired_connections": stats.AcquiredConns(),
		},
	})
}
