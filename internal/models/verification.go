package models

import (
	"time"

	"github.com/google/uuid"
)

// EmailVerificationToken is a single-use credential proving that someone can
// read the mail sent to a given address.
//
// # Why verify an email address at all
//
// Without it, anyone can register with someone else's address. That is not a
// theoretical problem: it lets an attacker squat on a victim's account before
// they sign up, receive their password-reset emails, and appear in your user
// list as that person. It also means your "email a receipt" feature sends
// receipts to strangers.
//
// # Why it is a database row and not a JWT
//
// The same reason a refresh token is: it must be revocable, and it must work
// exactly once. A signed token that says "alice@example.com is verified" cannot
// be un-issued, and can be redeemed twice.
type EmailVerificationToken struct {
	ID     uuid.UUID
	UserID uuid.UUID

	// TokenHash is a SHA-256 digest. The raw token exists only inside the email
	// that was sent, and inside the request that redeems it.
	TokenHash string

	ExpiresAt time.Time

	// UsedAt is set when the token is redeemed, and also when a newer token
	// supersedes it. Either way it means: this link no longer works.
	UsedAt *time.Time

	CreatedAt time.Time
}

// IsUsable reports whether the token may still be redeemed.
func (t *EmailVerificationToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && now.Before(t.ExpiresAt)
}
