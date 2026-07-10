package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/database"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// EmailVerificationTokenRepository persists email-verification tokens as hashes.
type EmailVerificationTokenRepository struct {
	db *database.DB
}

// NewEmailVerificationTokenRepository returns a repository backed by the given pool.
func NewEmailVerificationTokenRepository(db *database.DB) *EmailVerificationTokenRepository {
	return &EmailVerificationTokenRepository{db: db}
}

// Create stores a new token. TokenHash must already be hashed; this repository
// never sees the raw token and could not store it by mistake.
func (r *EmailVerificationTokenRepository) Create(ctx context.Context, t *models.EmailVerificationToken) error {
	const q = `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at`

	err := r.db.Querier(ctx).QueryRow(ctx, q, t.ID, t.UserID, t.TokenHash, t.ExpiresAt).
		Scan(&t.CreatedAt)
	return mapError(err, "verification token")
}

// GetByHash finds a token by its digest.
//
// It returns used and expired tokens too. Deciding whether a token may be
// redeemed is a business rule (models.EmailVerificationToken.IsUsable), not a
// storage concern.
func (r *EmailVerificationTokenRepository) GetByHash(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM email_verification_tokens WHERE token_hash = $1`

	var t models.EmailVerificationToken
	err := r.db.Querier(ctx).QueryRow(ctx, q, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		return nil, mapError(err, "verification token")
	}
	return &t, nil
}

// MarkUsed consumes a token.
//
// `AND used_at IS NULL` makes this idempotent AND is the concurrency guard:
// two requests redeeming the same token race, and exactly one of them updates a
// row. The caller checks RowsAffected to learn whether it won.
//
// Without that clause, both requests would succeed, and a token that must work
// once would have worked twice.
func (r *EmailVerificationTokenRepository) MarkUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `UPDATE email_verification_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, id, at)
	if err != nil {
		return mapError(err, "verification token")
	}
	if tag.RowsAffected() == 0 {
		// Already used, by an earlier request or by a concurrent one.
		return mapError(pgxNoRows, "verification token")
	}
	return nil
}

// InvalidateAllForUser marks every outstanding token for the user as used.
//
// Called before issuing a new one, so that only the most recent link works. A
// user who clicks "resend" three times must not end up with three live links,
// each an independent way into their account.
func (r *EmailVerificationTokenRepository) InvalidateAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) error {
	const q = `UPDATE email_verification_tokens SET used_at = $2 WHERE user_id = $1 AND used_at IS NULL`

	_, err := r.db.Querier(ctx).Exec(ctx, q, userID, at)
	return mapError(err, "verification token")
}

// DeleteExpired removes tokens that expired before `before`, returning the count.
//
// Run it on a schedule. Nothing breaks if you never do — expired tokens are
// rejected on use — but the table grows without bound, and an unbounded table
// eventually makes its indexes slow.
func (r *EmailVerificationTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	const q = `DELETE FROM email_verification_tokens WHERE expires_at < $1`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, before)
	if err != nil {
		return 0, mapError(err, "verification token")
	}
	return tag.RowsAffected(), nil
}
