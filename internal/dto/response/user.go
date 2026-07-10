package response

import (
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/models"
)

// User is the public shape of a user account.
//
// Compare it to models.User: there is no PasswordHash field, and there cannot
// be, because this struct does not have one. That is the entire point of the
// DTO layer. Leaking the hash is not a mistake you can make here; it is a
// mistake you would have to deliberately write.
type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	FirstName       string     `json:"firstName"`
	LastName        string     `json:"lastName"`
	FullName        string     `json:"fullName"`
	IsActive        bool       `json:"isActive"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`

	// Roles is null when the caller did not request them, and an array
	// otherwise. Never an empty array standing in for "not loaded".
	Roles []Role `json:"roles"`
}

// Role is the public shape of a role.
type Role struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// Permission is the public shape of a permission.
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// NewUser maps a domain entity to its public representation.
//
// This function is the checkpoint between your database and the internet.
// Every field a client sees passes through here, by hand, on purpose.
//
// Timestamps are converted to UTC. pgx returns a TIMESTAMPTZ in the session's
// timezone, so createdAt would otherwise serialise as "+05:00" while the
// envelope's own timestamp serialises as "Z". Both denote the same instant and
// both parse correctly, but a response that mixes the two is a trap: the first
// person to compare them as strings, or to slice off the last character, gets a
// bug that only appears outside UTC.
func NewUser(u *models.User) User {
	return User{
		ID:              u.ID,
		Email:           u.Email,
		FirstName:       u.FirstName,
		LastName:        u.LastName,
		FullName:        u.FullName(),
		IsActive:        u.IsActive,
		EmailVerifiedAt: utcPtr(u.EmailVerifiedAt),
		CreatedAt:       u.CreatedAt.UTC(),
		UpdatedAt:       u.UpdatedAt.UTC(),
		Roles:           NewRoles(u.Roles),
	}
}

// utcPtr converts an optional timestamp to UTC, preserving nil.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

// NewUsers maps a slice, preserving nil-ness: a nil input yields a nil slice,
// which encodes as JSON null, not [].
func NewUsers(users []models.User) []User {
	if users == nil {
		return nil
	}
	out := make([]User, 0, len(users))
	for i := range users {
		out = append(out, NewUser(&users[i]))
	}
	return out
}

// NewRoles maps domain roles to their public representation, preserving a nil
// slice as nil so that "not loaded" encodes as null rather than [].
func NewRoles(roles []models.Role) []Role {
	if roles == nil {
		return nil
	}
	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		out = append(out, Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Permissions: NewPermissions(r.Permissions),
		})
	}
	return out
}

// NewPermissions maps domain permissions to their public representation.
func NewPermissions(perms []models.Permission) []Permission {
	if perms == nil {
		return nil
	}
	out := make([]Permission, 0, len(perms))
	for _, p := range perms {
		out = append(out, Permission{ID: p.ID, Name: p.Name, Description: p.Description})
	}
	return out
}

// Auth is returned by register, login and refresh.
type Auth struct {
	// TokenType is always "Bearer". Sent so the client can build the
	// Authorization header without hardcoding the scheme.
	TokenType string `json:"tokenType"`

	AccessToken string `json:"accessToken"`

	// RefreshToken is the ONLY time the raw token is ever transmitted. The
	// server stores only its SHA-256 hash and can never show it again.
	RefreshToken string `json:"refreshToken"`

	// ExpiresIn is the access token's lifetime in seconds. Clients should
	// refresh slightly before this elapses, rather than waiting for a 401.
	ExpiresIn int64 `json:"expiresIn"`

	User User `json:"user"`
}
