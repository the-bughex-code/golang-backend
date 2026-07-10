// Package repositories is the only package in the application that contains
// SQL. It translates between database rows and domain models, and between
// storage errors and application errors.
//
// # What a repository must not do
//
//   - It must not hash a password, send an email, or check a permission.
//     Those are business rules; they live in services.
//   - It must not return a pgx type, or accept one. The signature speaks only
//     in models and apperrors.
//   - It must not decide HTTP status codes.
//
// # Why the Repository Pattern earns its keep here
//
// The service layer depends on an interface it declares itself (see
// services.UserRepository). That means a service test needs no database: it
// passes a fake. And the day a query needs a cache in front of it, the cache
// implements the same interface and nothing above it changes.
//
// The pattern does NOT earn its keep when it becomes a thin, generic
// Get/Save/Delete wrapper over every table. Repositories should expose the
// queries the business actually needs — ListActiveUsersWithRoles — not a
// generic query builder that leaks SQL back into the service.
package repositories

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/database"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// UserRepository reads and writes the users table.
type UserRepository struct {
	db *database.DB
}

// NewUserRepository is the constructor. Dependencies arrive as arguments; the
// repository never reaches out for a global.
func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{db: db}
}

// userColumns is declared once so that every SELECT and every scanUser agree.
// A mismatch between column order and scan order is a silent data-corruption
// bug: Postgres will happily scan first_name into last_name.
const userColumns = `
	id, email, password_hash, first_name, last_name,
	is_active, email_verified_at, created_at, updated_at, deleted_at`

// rowScanner is satisfied by both pgx.Row and pgx.Rows, so one scan function
// serves single-row and multi-row queries.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.IsActive, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Create inserts a user. The caller is responsible for having set ID and
// PasswordHash; the repository does not invent either.
//
// created_at and updated_at are assigned by the database defaults and read back
// with RETURNING, so the in-memory struct matches the row exactly. Computing
// them in Go would drift from the database clock.
func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
	const q = `
		INSERT INTO users (id, email, password_hash, first_name, last_name, is_active)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at`

	// $1, $2 ... are bind parameters. The SQL text and the data travel to the
	// server separately, so a value can never be parsed as SQL. This is what
	// makes SQL injection structurally impossible here — not escaping, not a
	// sanitising function, but the fact that data never enters the query text.
	err := r.db.Querier(ctx).
		QueryRow(ctx, q, u.ID, u.Email, u.PasswordHash, u.FirstName, u.LastName, u.IsActive).
		Scan(&u.CreatedAt, &u.UpdatedAt)

	return mapError(err, "user")
}

// GetByID returns a live (not soft-deleted) user.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1 AND deleted_at IS NULL`

	u, err := scanUser(r.db.Querier(ctx).QueryRow(ctx, q, id))
	if err != nil {
		return nil, mapError(err, "user")
	}
	return u, nil
}

// GetByEmail returns a live user by email.
//
// The caller must pass an already-normalised (lowercased, trimmed) address.
// Normalising here would hide the rule from the service that owns it, and
// would silently diverge from the plain unique index the schema relies on.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE email = $1 AND deleted_at IS NULL`

	u, err := scanUser(r.db.Querier(ctx).QueryRow(ctx, q, email))
	if err != nil {
		return nil, mapError(err, "user")
	}
	return u, nil
}

// ExistsByEmail reports whether a live account uses this email.
//
// SELECT EXISTS is used rather than SELECT COUNT(*): Postgres can stop at the
// first matching row instead of counting all of them.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`

	var exists bool
	if err := r.db.Querier(ctx).QueryRow(ctx, q, email).Scan(&exists); err != nil {
		return false, mapError(err, "user")
	}
	return exists, nil
}

// ListFilter describes a page of users to fetch.
type ListFilter struct {
	Limit  int
	Offset int
	Search string
}

// List returns one page of users and the total number of matches.
//
// Roles are NOT loaded. Loading them here would issue one extra query per user
// — the N+1 problem. A caller that needs roles for a single user asks the role
// repository directly.
//
// Two queries run: one for the page, one for the count. A window function
// (COUNT(*) OVER ()) would fetch both at once, but returns no count at all when
// the page is empty, which then needs special-casing. Two queries are clearer.
func (r *UserRepository) List(ctx context.Context, f ListFilter) ([]models.User, int64, error) {
	// The search term is passed as a bind parameter, never concatenated.
	// An empty search must match everything, so we use a NULL sentinel and let
	// SQL short-circuit rather than building two different query strings.
	var search any
	if s := strings.TrimSpace(f.Search); s != "" {
		search = "%" + s + "%"
	}

	const countQ = `
		SELECT COUNT(*) FROM users
		WHERE deleted_at IS NULL
		  AND ($1::text IS NULL OR email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)`

	var total int64
	if err := r.db.Querier(ctx).QueryRow(ctx, countQ, search).Scan(&total); err != nil {
		return nil, 0, mapError(err, "user")
	}
	if total == 0 {
		// Nothing to page through. Return an empty (non-nil) slice so the JSON
		// is [] rather than null.
		return []models.User{}, 0, nil
	}

	// ILIKE with a leading % cannot use a plain B-tree index, so this is a
	// sequential scan. That is fine for an admin screen over thousands of
	// rows. At millions, add a trigram index:
	//   CREATE EXTENSION pg_trgm;
	//   CREATE INDEX users_search_idx ON users USING gin (email gin_trgm_ops);
	const listQ = `
		SELECT ` + userColumns + `
		FROM users
		WHERE deleted_at IS NULL
		  AND ($1::text IS NULL OR email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3`

	// ORDER BY includes id as a tiebreaker. Without it, two users created in
	// the same microsecond have an undefined relative order, and a row can
	// appear on both page 1 and page 2.

	rows, err := r.db.Querier(ctx).Query(ctx, listQ, search, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, mapError(err, "user")
	}
	defer rows.Close() // returns the connection to the pool; skipping it leaks

	users := make([]models.User, 0, f.Limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, mapError(err, "user")
		}
		users = append(users, *u)
	}
	// rows.Err() reports a failure that happened DURING iteration — a dropped
	// connection halfway through. Without this check the caller silently
	// receives a truncated page and believes it is complete.
	if err := rows.Err(); err != nil {
		return nil, 0, mapError(err, "user")
	}

	return users, total, nil
}

// UpdateProfile changes the mutable, user-owned fields. Nothing else.
//
// The updated_at column is maintained by a database trigger, so it is read back
// rather than written.
func (r *UserRepository) UpdateProfile(ctx context.Context, id uuid.UUID, firstName, lastName string) (*models.User, error) {
	const q = `
		UPDATE users SET first_name = $2, last_name = $3
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING ` + userColumns

	u, err := scanUser(r.db.Querier(ctx).QueryRow(ctx, q, id, firstName, lastName))
	if err != nil {
		return nil, mapError(err, "user")
	}
	return u, nil
}

// UpdatePassword replaces the stored hash.
func (r *UserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	const q = `UPDATE users SET password_hash = $2 WHERE id = $1 AND deleted_at IS NULL`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, id, passwordHash)
	if err != nil {
		return mapError(err, "user")
	}
	// An UPDATE that matches no rows is not an error to Postgres. It IS an
	// error to us: the user we were told to update does not exist.
	if tag.RowsAffected() == 0 {
		return mapError(pgxNoRows, "user")
	}
	return nil
}

// SoftDelete marks the user deleted without removing the row, preserving
// foreign keys from audit tables that reference it.
func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, id)
	if err != nil {
		return mapError(err, "user")
	}
	if tag.RowsAffected() == 0 {
		// Either the id is unknown, or the user was already deleted. Both
		// answer the same question — there is no live user with this id — so
		// both produce the same 404. Distinguishing them would leak whether
		// an account ever existed.
		return mapError(pgxNoRows, "user")
	}
	return nil
}

// MarkEmailVerified records the moment the user proved they own the address.
func (r *UserRepository) MarkEmailVerified(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `UPDATE users SET email_verified_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, id, at)
	if err != nil {
		return mapError(err, "user")
	}
	if tag.RowsAffected() == 0 {
		return mapError(pgxNoRows, "user")
	}
	return nil
}
