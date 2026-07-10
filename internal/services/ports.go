// Package services holds the application's business rules.
//
// A service answers "what should happen when a user registers?" — normalise
// the email, reject duplicates, hash the password, create the row, grant the
// default role, and do the last two atomically. It knows nothing about HTTP
// status codes and nothing about SQL.
//
// # Where the interfaces live, and why it matters
//
// This file declares the interfaces this package REQUIRES. They are declared
// here, by the consumer, not in the packages that implement them.
//
// Go has no `implements` keyword: *repositories.UserRepository satisfies
// AuthUserStore automatically, without importing it, without naming it, without
// knowing it exists. So the dependency arrow points from services to an
// interface that services owns — never from services to repositories.
//
// Concretely, this is what that buys:
//
//   - Dependency Inversion. The high-level policy (services) does not depend on
//     the low-level detail (Postgres). Both depend on the abstraction, and the
//     abstraction belongs to the policy.
//   - Testability. A test in this package writes a 20-line fake that satisfies
//     AuthUserStore. No database, no Docker, no mocking framework.
//   - Interface Segregation. AuthService cannot call UserStore.List, because
//     AuthUserStore does not have it. The compiler enforces the boundary.
//
// A central `interfaces/` package would invert all three: every consumer would
// depend on one fat interface it mostly does not use.
package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/backend/internal/models"
	"github.com/the-bughex-code/backend/internal/repositories"
)

// AuthUserStore is exactly what AuthService needs from user storage.
// Nothing more. It cannot list users, because listing is not authentication.
type AuthUserStore interface {
	Create(ctx context.Context, u *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}

// UserStore is exactly what UserService needs. Note the absence of Create and
// UpdatePassword: account creation belongs to registration, and password
// changes belong to authentication.
type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	List(ctx context.Context, f repositories.ListFilter) ([]models.User, int64, error)
	UpdateProfile(ctx context.Context, id uuid.UUID, firstName, lastName string) (*models.User, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// RoleStore covers role lookup and assignment.
type RoleStore interface {
	GetByName(ctx context.Context, name string) (*models.Role, error)
	ForUser(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	AssignToUser(ctx context.Context, userID, roleID uuid.UUID) error
	ListAll(ctx context.Context) ([]models.Role, error)
}

// RefreshTokenStore persists refresh-token hashes.
type RefreshTokenStore interface {
	Create(ctx context.Context, t *models.RefreshToken) error
	GetByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// TxRunner runs a function inside a database transaction.
//
// The service layer needs atomicity — "create the user AND grant the role, or
// neither" — but it must not know that atomicity is spelled BEGIN/COMMIT in
// Postgres. This one-method interface is the whole of what it needs to know.
//
// *database.DB satisfies it.
type TxRunner interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// Clock exists so tests can control time.
//
// Token expiry, refresh-token validity, and "was this revoked before it was
// used?" are all time-dependent. A test that must sleep for 15 minutes to check
// that an access token expired is not a test anybody runs. Injecting the clock
// makes that a one-line assertion.
type Clock interface {
	Now() time.Time
}

// realClock is the production implementation.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// SystemClock is the Clock to pass in main.
var SystemClock Clock = realClock{}
