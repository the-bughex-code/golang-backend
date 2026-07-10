package models

import (
	"time"

	"github.com/google/uuid"
)

// Role groups permissions. Users are assigned roles; roles carry permissions.
//
// # Why not put permissions directly on users
//
// Direct user→permission grants look simpler for the first ten users. Then
// someone asks "which of our 4,000 users can approve invoices?" and the answer
// requires scanning every user's grant list. Worse, onboarding a new manager
// means hand-copying twenty permissions and getting one wrong.
//
// Roles add one join and remove that whole class of problem: permissions are
// granted to a role once, and membership is the only thing that varies.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time

	// Permissions is nil when not loaded, exactly as User.Roles is.
	Permissions []Permission
}

// Permission is a single, atomic capability.
//
// # Naming convention: resource:action
//
// "users:read", "invoices:approve". This reads well in code, sorts sensibly in
// a database, and lets you grep for every permission touching a resource. Avoid
// names like "admin" — that is a role, not a permission, and conflating the two
// is how you end up unable to answer "what can this person actually do?".
type Permission struct {
	ID          uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Well-known role names, seeded by migrations/00004_seed_rbac.sql.
//
// These are constants rather than bare strings so that a typo ("amdin") is a
// compile error at the call site instead of a permission check that silently
// returns false and locks someone out.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Well-known permission names, seeded by migrations/00004_seed_rbac.sql.
const (
	PermissionUsersRead   = "users:read"
	PermissionUsersCreate = "users:create"
	PermissionUsersUpdate = "users:update"
	PermissionUsersDelete = "users:delete"

	PermissionRolesRead   = "roles:read"
	PermissionRolesAssign = "roles:assign"
)

// RefreshToken is a long-lived credential that can be exchanged for a new,
// short-lived access token.
//
// # Why the token itself is not stored
//
// TokenHash holds a SHA-256 digest of the token, never the token. If the
// database is exfiltrated, the attacker holds hashes, and a hash cannot be
// presented to the API. This is the same reasoning as password hashing, and it
// is why the refresh token is the only credential we can actually revoke:
// deleting the row invalidates it immediately.
//
// SHA-256 is correct here, whereas bcrypt is correct for passwords. The
// difference is entropy. A refresh token is 256 random bits, so brute-forcing
// the hash is infeasible regardless of speed; a password might be "hunter2",
// so its hash must be made deliberately slow to compute.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time

	// RevokedAt is set on logout, on password change, and on rotation.
	RevokedAt *time.Time

	CreatedAt time.Time
}

// IsUsable reports whether the token may still be exchanged.
func (t *RefreshToken) IsUsable(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}
