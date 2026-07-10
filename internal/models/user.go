// Package models holds the application's domain entities: the nouns the
// business talks about, independent of how they are stored or transmitted.
//
// # These types have no JSON tags. That is deliberate.
//
// If User had `json:"password_hash"` — or even just no tag, which makes
// encoding/json use the field name — then any code that reaches for
// json.Marshal(user) leaks the password hash. Someone will eventually write
// that line. Leaving JSON tags off means the compiler cannot be used to leak
// the entity: every response must be built explicitly in internal/dto/response,
// where a human decided, field by field, what the client may see.
//
// The cost is a mapping function per entity. That cost is the point: it is a
// deliberate, reviewable checkpoint between your database and the internet.
//
// # These types have no database tags either.
//
// Scanning is done column-by-column in the repository. A struct tag that maps
// a field to a column looks convenient right up to the first schema migration,
// where the compiler cannot help you and the failure appears at runtime.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User is a person who can authenticate.
type User struct {
	ID uuid.UUID

	// Email is stored and compared in lowercase. Normalisation happens once,
	// in the service layer, so the database can rely on a plain unique index
	// rather than a functional one.
	Email string

	// PasswordHash is a bcrypt digest. The plaintext password exists only
	// inside the request DTO and is never assigned to a model field.
	PasswordHash string

	FirstName string
	LastName  string

	// IsActive gates login without deleting the row. Deactivating is
	// reversible; deleting is not.
	IsActive bool

	// EmailVerifiedAt is nil until the user proves they own the address.
	// A pointer, not a zero time.Time, because "never verified" and
	// "verified at the zero instant" must not be the same value.
	EmailVerifiedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time

	// DeletedAt implements soft deletion.
	//
	// Trade-off, stated plainly: soft deletion keeps foreign keys intact
	// (audit rows that reference a deleted user still resolve) and makes
	// deletion reversible. The price is that EVERY read query must filter
	// `deleted_at IS NULL`, forever. Forget once and deleted users reappear.
	// This project pays that price in exactly one place — the repository —
	// and nowhere else.
	DeletedAt *time.Time

	// Roles is populated only by queries that explicitly join. A nil Roles
	// means "not loaded", not "no roles". Callers that need roles must use a
	// repository method that says so in its name.
	Roles []Role
}

// FullName is a domain method. Logic that belongs to the entity lives on the
// entity — not in a `utils.GetFullName(u)` free function that anything can
// call and nothing owns.
func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}

// IsEmailVerified reports whether the user has confirmed their address.
func (u *User) IsEmailVerified() bool {
	return u.EmailVerifiedAt != nil
}

// IsDeleted reports whether the user has been soft-deleted.
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// CanLogin centralises the rule for who may authenticate. Putting it here
// rather than inside the auth service means a second caller (an admin
// impersonation flow, a CLI) cannot forget half of it.
func (u *User) CanLogin() bool {
	return u.IsActive && !u.IsDeleted()
}

// HasPermission reports whether any of the user's loaded roles grants the
// named permission. It returns false when Roles has not been loaded, which is
// the safe direction to fail.
func (u *User) HasPermission(name string) bool {
	for _, role := range u.Roles {
		for _, p := range role.Permissions {
			if p.Name == name {
				return true
			}
		}
	}
	return false
}

// HasRole reports whether the user holds the named role.
func (u *User) HasRole(name string) bool {
	for _, role := range u.Roles {
		if role.Name == name {
			return true
		}
	}
	return false
}
