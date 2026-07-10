//go:build integration

// Package tests holds tests that require a real PostgreSQL server.
//
// # Why these are separated from unit tests
//
// They are slow, they need infrastructure, and they fail for reasons that have
// nothing to do with your code (the database is down). Mixing them with unit
// tests means `go test ./...` stops being the thing you run on every save.
//
// The `//go:build integration` tag above excludes this file from a normal
// build. `make test` never compiles it; `make test-integration` passes
// `-tags=integration` and does.
//
// # Why they cannot be replaced by unit tests
//
// Everything here tests a promise that only PostgreSQL can keep:
//
//   - a transaction really rolls back on error
//   - the partial unique index really allows re-registering a deleted email
//   - SQLSTATE 23505 really becomes a Conflict error
//   - the updated_at trigger really fires
//
// A fake repository would happily agree with whatever we assumed. That is the
// whole danger of testing only against fakes.
package tests

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/backend/internal/apperrors"
	"github.com/the-bughex-code/backend/internal/config"
	"github.com/the-bughex-code/backend/internal/database"
	"github.com/the-bughex-code/backend/internal/models"
	"github.com/the-bughex-code/backend/internal/repositories"
)

// testDB connects to the test database, wipes it, and registers cleanup.
//
// Every test gets an empty users table. Tests that share state are tests that
// pass in isolation and fail in CI, and finding out why costs a day.
func testDB(t *testing.T) *database.DB {
	t.Helper()

	cfg, err := config.Load()
	if err != nil {
		t.Skipf("skipping: configuration not available (%v)\nrun via: make test-integration", err)
	}

	// Never, ever run destructive tests against the development database.
	cfg.Database.Name = envOr("TEST_DB_NAME", "backend_test")
	if cfg.Database.Name == "backend_dev" {
		t.Fatal("refusing to run destructive tests against backend_dev")
	}

	// Logs go nowhere: a passing test should print nothing.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx := context.Background()
	db, err := database.New(ctx, cfg.Database, log)
	if err != nil {
		t.Skipf("skipping: cannot reach %s (%v)\nrun: make migrate-test-up", cfg.Database.Name, err)
	}
	t.Cleanup(db.Close)

	// TRUNCATE ... CASCADE also empties user_roles and refresh_tokens, which
	// reference users. roles and permissions survive: they are seeded reference
	// data, not test fixtures.
	_, err = db.Pool().Exec(ctx, `TRUNCATE users CASCADE`)
	require.NoError(t, err, "the test database must be migrated: make migrate-test-up")

	return db
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func newUser(email string) *models.User {
	return &models.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        email,
		PasswordHash: "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012",
		FirstName:    "Test",
		LastName:     "User",
		IsActive:     true,
	}
}

// ---------------------------------------------------------------------------

func TestUserRepository_CreateAndFetch(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, repo.Create(ctx, user))

	// CreatedAt and UpdatedAt come back from the database via RETURNING.
	assert.False(t, user.CreatedAt.IsZero(), "created_at must be populated by RETURNING")
	assert.Equal(t, user.CreatedAt, user.UpdatedAt)

	fetched, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, fetched.Email)
	assert.True(t, fetched.IsActive)
	assert.Nil(t, fetched.DeletedAt)

	byEmail, err := repo.GetByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, byEmail.ID)
}

// pgx returns ErrNoRows; the repository must translate it into a 404-kind error
// before the service ever sees it.
func TestUserRepository_NotFound(t *testing.T) {
	db := testDB(t)
	repo := repositories.NewUserRepository(db)

	_, err := repo.GetByID(context.Background(), uuid.Must(uuid.NewV7()))
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound))
	assert.Equal(t, 404, apperrors.From(err).HTTPStatus())
}

// SQLSTATE 23505 on constraint users_email_unique must become EMAIL_TAKEN,
// with a field error, and without leaking the constraint name to the client.
func TestUserRepository_DuplicateEmailBecomesConflict(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	require.NoError(t, repo.Create(ctx, newUser("alice@example.com")))

	err := repo.Create(ctx, newUser("alice@example.com"))
	require.Error(t, err)

	appErr := apperrors.From(err)
	assert.Equal(t, "EMAIL_TAKEN", appErr.Code)
	assert.Equal(t, 409, appErr.HTTPStatus())
	require.Len(t, appErr.Fields, 1)
	assert.Equal(t, "email", appErr.Fields[0].Field)

	assert.NotContains(t, appErr.Message, "users_email_unique",
		"the constraint name must never reach the client")
	assert.NotContains(t, appErr.Message, "duplicate key")
}

// The migration creates a PARTIAL unique index (WHERE deleted_at IS NULL), so
// an address becomes available again once its account is soft-deleted. A plain
// UNIQUE(email) would fail this test.
func TestUserRepository_SoftDeleteFreesTheEmail(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	first := newUser("alice@example.com")
	require.NoError(t, repo.Create(ctx, first))
	require.NoError(t, repo.SoftDelete(ctx, first.ID))

	// The row still exists, so foreign keys from audit tables still resolve...
	var deletedAt *time.Time
	require.NoError(t, db.Pool().QueryRow(ctx,
		`SELECT deleted_at FROM users WHERE id = $1`, first.ID).Scan(&deletedAt))
	require.NotNil(t, deletedAt)

	// ...but it is invisible to every repository read.
	_, err := repo.GetByID(ctx, first.ID)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound))

	exists, err := repo.ExistsByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.False(t, exists)

	// And the address can be registered again.
	second := newUser("alice@example.com")
	assert.NoError(t, repo.Create(ctx, second), "the partial unique index must allow re-registration")
	assert.NotEqual(t, first.ID, second.ID)
}

// Deleting twice must be a 404, not a success. Both branches — unknown id and
// already-deleted — answer the same question and must look identical.
func TestUserRepository_SoftDeleteIsNotIdempotentlySilent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, repo.Create(ctx, user))
	require.NoError(t, repo.SoftDelete(ctx, user.ID))

	err := repo.SoftDelete(ctx, user.ID)
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound))
}

// The updated_at trigger is the database's job. If it were done in Go, an
// UPDATE run by a DBA or a second service would leave the column stale.
func TestUserRepository_UpdatedAtTriggerFires(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, repo.Create(ctx, user))
	original := user.UpdatedAt

	// Postgres NOW() is the transaction start time, so two statements in
	// separate transactions are needed for the timestamps to differ at all.
	time.Sleep(10 * time.Millisecond)

	updated, err := repo.UpdateProfile(ctx, user.ID, "Alicia", "Nguyen")
	require.NoError(t, err)

	assert.Equal(t, "Alicia", updated.FirstName)
	assert.True(t, updated.UpdatedAt.After(original), "the trigger must bump updated_at")
	assert.Equal(t, user.CreatedAt.UnixMicro(), updated.CreatedAt.UnixMicro(), "created_at must not move")
}

// ---------------------------------------------------------------------------
// Transactions. This is what a fake cannot verify.
// ---------------------------------------------------------------------------

func TestInTx_CommitsOnSuccess(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)
	roles := repositories.NewRoleRepository(db)

	user := newUser("alice@example.com")

	err := db.InTx(ctx, func(ctx context.Context) error {
		if err := users.Create(ctx, user); err != nil {
			return err
		}
		role, err := roles.GetByName(ctx, models.RoleUser)
		if err != nil {
			return err
		}
		return roles.AssignToUser(ctx, user.ID, role.ID)
	})
	require.NoError(t, err)

	// Both writes survived.
	_, err = users.GetByID(ctx, user.ID)
	require.NoError(t, err)

	assigned, err := roles.ForUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assigned, 1)
	assert.Equal(t, models.RoleUser, assigned[0].Name)
}

// The promise: either both rows exist, or neither does.
func TestInTx_RollsBackOnError(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")
	sentinel := fmt.Errorf("something went wrong after the insert")

	err := db.InTx(ctx, func(ctx context.Context) error {
		if err := users.Create(ctx, user); err != nil {
			return err
		}
		// The row exists inside this transaction...
		if _, err := users.GetByID(ctx, user.ID); err != nil {
			return fmt.Errorf("row should be visible inside its own tx: %w", err)
		}
		return sentinel
	})

	require.ErrorIs(t, err, sentinel, "InTx must return the closure's error unchanged")

	// ...and does not exist outside it.
	_, err = users.GetByID(ctx, user.ID)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound), "the insert must have been rolled back")
}

func TestInTx_RollsBackOnPanic(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")

	assert.Panics(t, func() {
		_ = db.InTx(ctx, func(ctx context.Context) error {
			_ = users.Create(ctx, user)
			panic("handler exploded mid-transaction")
		})
	}, "InTx must re-panic so the recovery middleware can turn it into a 500")

	_, err := users.GetByID(ctx, user.ID)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound), "the panic must have rolled back the insert")
}

// A nested InTx joins the outer transaction rather than opening a second one.
// If it opened its own, the inner commit would survive the outer rollback.
func TestInTx_NestedJoinsOuterTransaction(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)

	user := newUser("alice@example.com")
	sentinel := fmt.Errorf("outer failure")

	err := db.InTx(ctx, func(ctx context.Context) error {
		if err := db.InTx(ctx, func(ctx context.Context) error {
			return users.Create(ctx, user) // inner "transaction" commits here
		}); err != nil {
			return err
		}
		return sentinel // outer rolls back
	})
	require.ErrorIs(t, err, sentinel)

	_, err = users.GetByID(ctx, user.ID)
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound),
		"the inner write must be rolled back with the outer transaction")
}

// ---------------------------------------------------------------------------
// Roles and refresh tokens
// ---------------------------------------------------------------------------

func TestRoleRepository_ForUserLoadsPermissions(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)
	roles := repositories.NewRoleRepository(db)

	user := newUser("admin@example.com")
	require.NoError(t, users.Create(ctx, user))

	admin, err := roles.GetByName(ctx, models.RoleAdmin)
	require.NoError(t, err)
	require.NoError(t, roles.AssignToUser(ctx, user.ID, admin.ID))

	// Idempotent: ON CONFLICT DO NOTHING.
	require.NoError(t, roles.AssignToUser(ctx, user.ID, admin.ID))

	loaded, err := roles.ForUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, loaded, 1, "re-assigning the same role must not duplicate it")

	// Migration 00004 grants the admin role every permission that exists.
	assert.Len(t, loaded[0].Permissions, 6)

	user.Roles = loaded
	assert.True(t, user.HasPermission(models.PermissionUsersDelete))
	assert.False(t, user.HasPermission("invoices:approve"))
}

func TestRefreshTokenRepository_RevokePreservesFirstTimestamp(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, users.Create(ctx, user))

	token := &models.RefreshToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    user.ID,
		TokenHash: "a-unique-sha256-hex-digest-for-this-test",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, tokens.Create(ctx, token))

	require.NoError(t, tokens.Revoke(ctx, token.ID))
	first, err := tokens.GetByHash(ctx, token.TokenHash)
	require.NoError(t, err)
	require.NotNil(t, first.RevokedAt)

	time.Sleep(10 * time.Millisecond)

	// Revoking again must not overwrite the original timestamp: that is the
	// audit trail of when the session actually ended.
	require.NoError(t, tokens.Revoke(ctx, token.ID))
	second, err := tokens.GetByHash(ctx, token.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, first.RevokedAt.UnixMicro(), second.RevokedAt.UnixMicro())

	assert.False(t, second.IsUsable(time.Now()))
}

func TestRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, users.Create(ctx, user))

	for i := range 3 {
		require.NoError(t, tokens.Create(ctx, &models.RefreshToken{
			ID:        uuid.Must(uuid.NewV7()),
			UserID:    user.ID,
			TokenHash: fmt.Sprintf("hash-%d", i),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}))
	}

	require.NoError(t, tokens.RevokeAllForUser(ctx, user.ID))

	for i := range 3 {
		got, err := tokens.GetByHash(ctx, fmt.Sprintf("hash-%d", i))
		require.NoError(t, err)
		assert.NotNil(t, got.RevokedAt, "token %d must be revoked", i)
	}
}

// Deleting a user must cascade to their refresh tokens. Otherwise the rows
// linger forever, referencing a person who no longer exists.
func TestRefreshTokens_CascadeOnUserHardDelete(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)

	user := newUser("alice@example.com")
	require.NoError(t, users.Create(ctx, user))
	require.NoError(t, tokens.Create(ctx, &models.RefreshToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    user.ID,
		TokenHash: "cascade-test-hash",
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	// A hard DELETE, not the repository's soft delete.
	_, err := db.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID)
	require.NoError(t, err)

	_, err = tokens.GetByHash(ctx, "cascade-test-hash")
	assert.True(t, apperrors.IsKind(err, apperrors.KindNotFound), "ON DELETE CASCADE must have removed it")
}

// Pagination must be stable. Without `id` as a tiebreaker in ORDER BY, two rows
// created in the same microsecond can appear on two different pages.
func TestUserRepository_ListPaginationIsStable(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	for i := range 5 {
		require.NoError(t, repo.Create(ctx, newUser(fmt.Sprintf("user%d@example.com", i))))
	}

	page1, total, err := repo.List(ctx, repositories.ListFilter{Limit: 2, Offset: 0})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	require.Len(t, page1, 2)

	page2, _, err := repo.List(ctx, repositories.ListFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	require.Len(t, page2, 2)

	page3, _, err := repo.List(ctx, repositories.ListFilter{Limit: 2, Offset: 4})
	require.NoError(t, err)
	require.Len(t, page3, 1)

	seen := make(map[uuid.UUID]bool)
	for _, u := range append(append(page1, page2...), page3...) {
		require.False(t, seen[u.ID], "user %s appeared on two pages", u.Email)
		seen[u.ID] = true
	}
	assert.Len(t, seen, 5, "every user must appear exactly once across all pages")
}

// The search term is a bind parameter, so SQL inside it is data, not code.
func TestUserRepository_SearchIsInjectionProof(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := repositories.NewUserRepository(db)

	require.NoError(t, repo.Create(ctx, newUser("alice@example.com")))

	for _, payload := range []string{
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"%' UNION SELECT NULL --",
	} {
		found, total, err := repo.List(ctx, repositories.ListFilter{Limit: 10, Search: payload})
		require.NoError(t, err, "payload %q must be treated as a search term", payload)
		assert.Zero(t, total)
		assert.Empty(t, found)
	}

	// The table survived and still holds its row.
	_, total, err := repo.List(ctx, repositories.ListFilter{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
}
