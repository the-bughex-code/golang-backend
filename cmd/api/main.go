// Command api is the HTTP server.
//
// # This file is the composition root
//
// It is the ONE place that knows which concrete type satisfies which interface.
// It constructs the pool, hands it to the repositories, hands those to the
// services, hands those to the handlers, and hands those to the router.
//
// That is Dependency Injection. There is no framework, no container, no
// reflection, no struct tags. Just constructors taking arguments. Go does not
// need more than this, and the wiring is a function you can read top to bottom.
//
// # Why the compiler checks the wiring for you
//
// services.NewAuthService takes an AuthUserStore. We pass *repositories.
// UserRepository. Nothing declares that the repository implements the
// interface — but if it ever stops doing so, THIS FILE fails to compile.
// The seam between layers is verified at build time, for free.
//
// # Why main() is three lines
//
// main() cannot return an error, and os.Exit skips deferred functions. So all
// the work lives in run(), where `defer db.Close()` actually runs.
//
// ---------------------------------------------------------------------------
// The @-prefixed lines below are read by `swag` to generate the OpenAPI 3.1
// document (`make docs`). They are ordinary Go comments to the compiler.
// ---------------------------------------------------------------------------
//
//	@title			Backend API
//	@version		1.0
//	@description	A production-ready Go backend: JWT authentication, RBAC, and PostgreSQL.
//	@description	Every response uses the same envelope: success, message, data, errors,
//	@description	pagination, meta, timestamp, requestId.
//
//	@contact.name	the-bughex-code
//	@license.name	MIT
//
//	@host		localhost:8080
//	@BasePath	/
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Send the access token as: Bearer <token>
//
//	@tag.name			auth
//	@tag.description	Registration, login, token refresh and logout
//	@tag.name			profile
//	@tag.description	Operations on the authenticated caller's own account
//	@tag.name			users
//	@tag.description	Administrative operations on other users (permission-gated)
//	@tag.name			roles
//	@tag.description	Role listing and assignment
//	@tag.name			health
//	@tag.description	Liveness and readiness probes for orchestrators
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/the-bughex-code/golang-backend/internal/config"
	"github.com/the-bughex-code/golang-backend/internal/database"
	"github.com/the-bughex-code/golang-backend/internal/handlers"
	"github.com/the-bughex-code/golang-backend/internal/logger"
	"github.com/the-bughex-code/golang-backend/internal/repositories"
	"github.com/the-bughex-code/golang-backend/internal/routes"
	"github.com/the-bughex-code/golang-backend/internal/services"
	"github.com/the-bughex-code/golang-backend/internal/validators"
)

// version is stamped at build time by the Makefile:
//
//	go build -ldflags "-X main.version=$(git rev-parse --short HEAD)"
//
// A binary that cannot tell you which commit it came from is a binary you
// cannot debug in production.
var version = "dev"

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet — config could be what failed — so this
		// one message goes to stderr directly.
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Configuration ─────────────────────────────────────────────────────
	// Loaded first, and validated. A missing DB_PASSWORD stops the process
	// here, with a message naming every problem at once.
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// ── Logging ───────────────────────────────────────────────────────────
	log := logger.New(cfg.Log.Level, cfg.Log.Format, os.Stdout)

	// Set the default too. logger.FromContext falls back to slog.Default() when
	// a context carries no request-scoped logger — in tests, in background
	// jobs, and inside Recover if it ever runs before RequestLogger.
	slog.SetDefault(log)

	log.Info("starting",
		slog.String("app", cfg.App.Name),
		slog.String("version", version),
		slog.String("env", string(cfg.App.Env)),
	)

	// ── Signal handling ───────────────────────────────────────────────────
	//
	// signal.NotifyContext cancels ctx on SIGINT (Ctrl-C) or SIGTERM (what
	// Kubernetes, systemd and Docker send before killing you). Everything that
	// should stop when the process stops takes this context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── Database ──────────────────────────────────────────────────────────
	db, err := database.New(ctx, cfg.Database, log)
	if err != nil {
		return err
	}
	defer db.Close()

	// Migrations are NOT run here.
	//
	// Two replicas starting at once would race to apply the same migration.
	// More importantly, a migration that fails should not take your API down —
	// and a deploy that needs a rollback should not have already altered the
	// schema. Run `make migrate-up` as a separate, deliberate step.

	// ── Wiring: repositories ──────────────────────────────────────────────
	// They depend on the database, and on nothing else.
	var (
		userRepo    = repositories.NewUserRepository(db)
		roleRepo    = repositories.NewRoleRepository(db)
		refreshRepo = repositories.NewRefreshTokenRepository(db)
	)

	// ── Wiring: services ──────────────────────────────────────────────────
	// They depend on repository INTERFACES that they themselves declare, and on
	// a Clock. They know nothing about HTTP.
	//
	// `db` is passed as the TxRunner: *database.DB has an InTx method, so it
	// satisfies that one-method interface without ever mentioning it.
	var (
		clock    = services.SystemClock
		tokenSvc = services.NewTokenService(cfg.JWT, clock)
		authSvc  = services.NewAuthService(userRepo, roleRepo, refreshRepo, tokenSvc, db, clock)
		userSvc  = services.NewUserService(userRepo, roleRepo)
		validate = validators.New()
	)

	// ── Wiring: handlers ──────────────────────────────────────────────────
	// They depend on services. They know nothing about SQL.
	var (
		healthHandler  = handlers.NewHealthHandler(db, version)
		authHandler    = handlers.NewAuthHandler(authSvc, validate)
		profileHandler = handlers.NewProfileHandler(userSvc, authSvc, validate)
		userHandler    = handlers.NewUserHandler(userSvc, validate)
	)

	// ── Wiring: router ────────────────────────────────────────────────────
	handler := routes.New(ctx, routes.Dependencies{
		Config:  cfg,
		Logger:  log,
		Tokens:  tokenSvc,
		Health:  healthHandler,
		Auth:    authHandler,
		Profile: profileHandler,
		Users:   userHandler,
	})

	// ── HTTP server ───────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:    cfg.Server.Addr(),
		Handler: handler,

		// Every one of these timeouts exists because its absence is a
		// vulnerability. http.Server's zero value has NO timeouts at all: one
		// slow client can hold a connection, and its goroutine, forever.

		// ReadHeaderTimeout bounds the time to read request headers. This is
		// the specific defence against Slowloris, where an attacker opens
		// thousands of connections and dribbles one header byte per second.
		ReadHeaderTimeout: 5 * time.Second,

		// ReadTimeout bounds headers AND body together.
		ReadTimeout: cfg.Server.ReadTimeout,

		// WriteTimeout bounds how long a handler may take to respond.
		WriteTimeout: cfg.Server.WriteTimeout,

		// IdleTimeout bounds how long a keep-alive connection may sit unused.
		IdleTimeout: cfg.Server.IdleTimeout,

		// net/http logs its own internal errors (bad TLS handshakes, malformed
		// requests) to the standard logger by default, which would bypass our
		// structured logging entirely. Route them through slog.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	// ListenAndServe blocks. Run it in a goroutine so this function can also
	// wait on ctx.Done(). The buffered channel means the goroutine can send and
	// exit even if nobody is receiving yet, so it never leaks.
	serverErrors := make(chan error, 1)
	go func() {
		log.Info("http server listening", slog.String("addr", srv.Addr))
		serverErrors <- srv.ListenAndServe()
	}()

	// ── Block until the server dies or we are asked to stop ───────────────
	select {
	case err := <-serverErrors:
		// ErrServerClosed is what Shutdown causes; it is not a failure.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil

	case <-ctx.Done():
		// slog.Duration renders as raw nanoseconds in JSON (15000000000), which
		// nobody can read at 3am. String() gives "15s".
		log.Info("shutdown signal received", slog.String("grace_period", cfg.Server.ShutdownTimeout.String()))

		// Stop trapping the signal. A second Ctrl-C now kills the process
		// immediately, which is what an impatient operator expects.
		stop()

		// ── Graceful shutdown ─────────────────────────────────────────────
		//
		// Shutdown stops accepting new connections, then waits for in-flight
		// requests to finish. Without it, a deploy drops every request that
		// happened to be mid-flight — including the payment someone just
		// submitted.
		//
		// A FRESH context, not ctx: ctx is already cancelled, and a cancelled
		// context would make Shutdown give up instantly.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			// The grace period elapsed and requests were still running. Force
			// the connections closed rather than hanging forever; the
			// orchestrator is about to SIGKILL us anyway.
			log.Error("graceful shutdown timed out; forcing close",
				slog.String("error", err.Error()))
			_ = srv.Close()
			return fmt.Errorf("shutdown: %w", err)
		}

		log.Info("shutdown complete")
		return nil
	}
}
