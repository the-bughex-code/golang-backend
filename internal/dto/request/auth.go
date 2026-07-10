// Package request holds the shapes a client is allowed to send, together with
// the validation rules each field must satisfy.
//
// These types exist so that models.User is never the target of a JSON decode.
// If a handler decoded straight into models.User, a client could POST
// {"isActive": true, "passwordHash": "..."} and set fields it has no business
// setting. This is called mass assignment, and the DTO layer makes it
// impossible: RegisterRequest simply has nowhere to put those keys.
//
// A DTO may implement Normalize(); handlers.bind calls it after decoding and
// before validating, so that whitespace and letter case never cause a spurious
// rejection.
package request

import "strings"

// normalizeEmail trims surrounding whitespace and lowercases.
//
// It runs before validation, so " Alice@Example.COM " is accepted rather than
// rejected for containing a space. The service layer applies the same rule
// again (services.NormalizeEmail) — cheap, idempotent, and it means a caller
// that bypasses this DTO still cannot create a mixed-case duplicate.
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Register creates a new account.
type Register struct {
	Email string `json:"email" validate:"required,email,max=254"`

	// Password bounds, and why they are what they are:
	//
	//   min=8  — NIST SP 800-63B sets 8 as the floor for user-chosen secrets.
	//   max=72 — bcrypt hashes at most 72 BYTES. Go's implementation returns
	//            an error above that rather than silently truncating (some
	//            other languages truncate, which means "correcthorse..." and
	//            "correcthorse...extra" become the same password). Rejecting
	//            it here produces a clear message instead of a 500.
	//
	// Deliberately absent: composition rules ("must contain an uppercase
	// letter and a symbol"). NIST advises against them. They push users toward
	// P@ssw0rd1 — predictable to a cracker, hard for a human — while adding
	// no meaningful entropy. Length is what matters.
	Password string `json:"password" validate:"required,min=8,max=72"`

	FirstName string `json:"firstName" validate:"required,min=1,max=100"`
	LastName  string `json:"lastName"  validate:"required,min=1,max=100"`
}

// Normalize trims whitespace and lowercases the email.
//
// The password is deliberately NOT trimmed. A trailing space may be a genuine
// part of someone's password, and silently removing it means the password they
// registered with is not the password they typed.
func (r *Register) Normalize() {
	r.Email = normalizeEmail(r.Email)
	r.FirstName = strings.TrimSpace(r.FirstName)
	r.LastName = strings.TrimSpace(r.LastName)
}

// Login exchanges credentials for a token pair.
type Login struct {
	Email string `json:"email" validate:"required,email"`

	// No min= here. Rejecting a 3-character password at login with "must be at
	// least 8 characters" tells an attacker the password was too short to be
	// real, and annoys a legitimate user whose password predates the rule.
	// Login either matches or it does not.
	Password string `json:"password" validate:"required"`
}

// Normalize trims and lowercases the email so that a user who registered as
// "alice@example.com" can sign in as " Alice@Example.com ".
func (l *Login) Normalize() {
	l.Email = normalizeEmail(l.Email)
}

// Refresh exchanges a refresh token for a new token pair.
type Refresh struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// Logout revokes a refresh token.
type Logout struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// ChangePassword updates the caller's own password.
type ChangePassword struct {
	// Requiring the current password stops an attacker who has stolen an
	// access token (say, from a logged XHR) from locking the real owner out.
	CurrentPassword string `json:"currentPassword" validate:"required"`

	// nefield ensures the new password actually differs from the old one.
	NewPassword string `json:"newPassword" validate:"required,min=8,max=72,nefield=CurrentPassword"`
}
