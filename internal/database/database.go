// Package database owns the PostgreSQL connection pool, transaction handling,
// and health checks. It is the only package that imports pgx.
//
// # Why pgx directly, and not database/sql
//
// database/sql is a lowest-common-denominator abstraction over every SQL
// engine. That portability costs real things: Postgres arrays, jsonb, and uuid
// arrive as []byte for you to parse; the wire protocol is text rather than
// binary; and driver errors are opaque, so you cannot distinguish "unique
// violation" from "connection reset" without string matching.
//
// pgx speaks Postgres natively. `pgconn.PgError.Code == "23505"` is a reliable,
// documented way to detect a unique violation, which is what lets the
// repository turn a storage error into a clean "email already registered"
// business error. We are committed to Postgres; there is no portability left
// to buy.
//
// Use database/sql instead when you genuinely must support more than one
// engine, or when a library you depend on requires a *sql.DB.
package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/the-bughex-code/golang-backend/internal/config"
)

// Querier is the subset of pgx that repositories are allowed to use.
//
// Both *pgxpool.Pool and pgx.Tx implement it. That single fact is what makes
// transactions transparent: a repository writes its query once and does not
// know, or care, whether it is running inside a transaction.
//
// This is Interface Segregation in practice — repositories depend on three
// methods, not on the ~30 that *pgxpool.Pool exposes.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Compile-time proof that both types satisfy Querier. If a future pgx release
// changes a signature, this fails at build time rather than at 3am.
var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (pgx.Tx)(nil)
)

// DB wraps the connection pool.
type DB struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// txKey is the context key under which an in-flight transaction is stored.
// Unexported struct type, so no other package can collide with it.
type txKey struct{}

// New builds the pool and verifies it can actually reach the database.
//
// Connecting lazily — returning a pool that has never talked to Postgres — is
// a trap: the process reports "started successfully" and then every request
// fails. We Ping here so that a bad password is a startup crash, not a
// production incident.
func New(ctx context.Context, cfg config.DatabaseConfig, log *slog.Logger) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("database: parsing dsn: %w", err)
	}

	// Pool sizing. Each Postgres connection is a separate OS process on the
	// server with its own work_mem. A pool bigger than the database can serve
	// does not increase throughput; it moves the queue from your application,
	// where you can see it, into the database, where you cannot.
	//
	// A reasonable starting point is (2 * cores) + effective_spindle_count on
	// the DATABASE server, divided by the number of application instances.
	// Measure before raising it.
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns

	// Recycling connections lets the pool rebalance after a failover and
	// bounds server-side memory growth on long-lived sessions.
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	// HealthCheckPeriod controls how often idle connections are probed, so a
	// silently dropped TCP connection is discovered by the pool rather than by
	// a user's request.
	poolCfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database: creating pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: cannot reach postgres at %s:%d: %w", cfg.Host, cfg.Port, err)
	}

	log.Info("database connected",
		slog.String("host", cfg.Host),
		slog.Int("port", cfg.Port),
		slog.String("database", cfg.Name),
		slog.Int("max_conns", int(cfg.MaxConns)),
	)

	return &DB{pool: pool, log: log}, nil
}

// Close drains the pool. Safe to call more than once.
func (d *DB) Close() {
	if d.pool != nil {
		d.pool.Close()
	}
}

// Ping reports whether the database is reachable right now. Used by the
// readiness probe.
func (d *DB) Ping(ctx context.Context) error {
	return d.pool.Ping(ctx)
}

// Pool exposes the underlying pool. Needed only for statistics and tests;
// repositories must use Querier instead.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Querier returns the thing a repository should run its query against.
//
// If ctx carries an in-flight transaction (because a service called InTx), the
// transaction is returned, so the query joins it. Otherwise the pool is
// returned and the query runs standalone, auto-committed.
//
// # Trade-off, stated honestly
//
// This is implicit. A reader of a repository method cannot tell, from that
// method alone, whether it will run in a transaction. The alternative is to
// thread a `tx` parameter through every repository signature, which is explicit
// but means every method grows a parameter it usually ignores, and every
// service that does not need a transaction must pass nil.
//
// We chose implicit because the failure mode is benign: forgetting to use
// Querier(ctx) means your query runs outside the transaction — a bug, but one
// that integration tests catch immediately. Threading tx everywhere is a cost
// paid on every line of the codebase forever.
func (d *DB) Querier(ctx context.Context) Querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok && tx != nil {
		return tx
	}
	return d.pool
}

// InTx runs fn inside a single database transaction.
//
// Commit on success, roll back on any error or panic. The transaction is placed
// in the context that fn receives, so every repository call made with that
// context automatically participates.
//
//	err := db.InTx(ctx, func(ctx context.Context) error {
//	    if err := users.Create(ctx, u); err != nil { return err }
//	    return roles.Assign(ctx, u.ID, roleID)   // same transaction
//	})
//
// Either both rows exist, or neither does.
func (d *DB) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	// Nested InTx joins the outer transaction rather than opening a second
	// one. Postgres has savepoints, but a nested "transaction" that can commit
	// independently of its parent is a lie we refuse to tell.
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok && tx != nil {
		return fn(ctx)
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	// Rollback must run even when ctx has been cancelled — otherwise a
	// client disconnect leaves the transaction open until the server times it
	// out, holding locks the whole time. context.WithoutCancel strips the
	// cancellation while keeping deadlines and values.
	rollbackCtx := context.WithoutCancel(ctx)

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(rollbackCtx)
			panic(p) // re-panic; the recovery middleware turns it into a 500.
		}
	}()

	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		if rbErr := tx.Rollback(rollbackCtx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			// Both the original failure and the rollback failure matter.
			// errors.Join keeps both retrievable via errors.Is.
			return errors.Join(err, fmt.Errorf("database: rollback: %w", rbErr))
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit: %w", err)
	}
	return nil
}

// Stats returns live pool statistics. Surface these on a metrics endpoint:
// AcquireCount climbing while TotalConns sits at MaxConns is the signature of
// a pool that is too small.
func (d *DB) Stats() *pgxpool.Stat { return d.pool.Stat() }
