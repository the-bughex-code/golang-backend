package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/database"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// RefreshTokenRepository persists refresh tokens as hashes.
type RefreshTokenRepository struct {
	db *database.DB
}

// NewRefreshTokenRepository returns a repository backed by the given pool.
func NewRefreshTokenRepository(db *database.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create stores a new refresh token. TokenHash must already be hashed; this
// repository never sees the raw token and could not store it by mistake.
func (r *RefreshTokenRepository) Create(ctx context.Context, t *models.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at`

	err := r.db.Querier(ctx).QueryRow(ctx, q, t.ID, t.UserID, t.TokenHash, t.ExpiresAt).
		Scan(&t.CreatedAt)
	return mapError(err, "refresh token")
}

// GetByHash finds a token by its digest.
//
// Note it returns revoked and expired tokens too. Deciding whether a token is
// usable is a business rule (models.RefreshToken.IsUsable), not a storage
// concern — and the service needs to distinguish "no such token" from
// "revoked token", because the latter may indicate token theft.
func (r *RefreshTokenRepository) GetByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
		FROM refresh_tokens WHERE token_hash = $1`

	var t models.RefreshToken
	err := r.db.Querier(ctx).QueryRow(ctx, q, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, mapError(err, "refresh token")
	}
	return &t, nil
}

// Revoke invalidates one token.
//
// `AND revoked_at IS NULL` makes this idempotent and preserves the ORIGINAL
// revocation time. Without it, revoking twice would overwrite the timestamp and
// destroy the audit trail of when the session actually ended.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`

	_, err := r.db.Querier(ctx).Exec(ctx, q, id)
	return mapError(err, "refresh token")
}

// RevokeAllForUser ends every session the user has.
//
// Called on password change. This is the whole reason a refresh token is worth
// storing server-side: a stateless JWT cannot be un-issued, but a row can be
// updated. After this runs, the user's other devices can no longer obtain a new
// access token, and their existing ones expire within JWT_ACCESS_TTL.
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	const q = `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`

	_, err := r.db.Querier(ctx).Exec(ctx, q, userID)
	return mapError(err, "refresh token")
}

// DeleteExpired removes tokens that expired before `before` and returns how
// many rows went away.
//
// Run this on a schedule. Nothing breaks if you never do — expired tokens are
// rejected on use — but the table grows without bound, and an unbounded table
// eventually makes its indexes slow.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	const q = `DELETE FROM refresh_tokens WHERE expires_at < $1`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, before)
	if err != nil {
		return 0, mapError(err, "refresh token")
	}
	return tag.RowsAffected(), nil
}
