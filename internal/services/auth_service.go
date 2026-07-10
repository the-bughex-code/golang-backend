package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/logger"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// TokenPair is what a successful authentication produces.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	ExpiresIn    int64 // seconds until AccessToken expires
}

// AuthService owns registration, login, token refresh, logout, and password
// change.
//
// Every field is an interface or a value. Nothing is fetched from a global.
// This is Dependency Injection: the thing that builds AuthService (main.go)
// decides what it talks to, and a test decides differently.
type AuthService struct {
	users        AuthUserStore
	roles        RoleStore
	refreshStore RefreshTokenStore
	tokens       *TokenService
	tx           TxRunner
	clock        Clock

	// verification sends the confirmation email after a successful signup.
	//
	// A one-method interface, so registration cannot reach into the rest of
	// VerificationService — and so the two services never import each other,
	// which they would otherwise have to do in a circle.
	verification VerificationSender

	// defaultRole is granted to every new account.
	defaultRole string
}

// NewAuthService builds the authentication service.
//
// Every parameter is an interface this package declares itself, except the
// concrete *TokenService, which has no alternative implementation worth
// abstracting over.
func NewAuthService(
	users AuthUserStore,
	roles RoleStore,
	refreshStore RefreshTokenStore,
	tokens *TokenService,
	tx TxRunner,
	clock Clock,
	verification VerificationSender,
) *AuthService {
	return &AuthService{
		users:        users,
		roles:        roles,
		refreshStore: refreshStore,
		tokens:       tokens,
		tx:           tx,
		clock:        clock,
		verification: verification,
		defaultRole:  models.RoleUser,
	}
}

// NormalizeEmail lowercases and trims.
//
// It lives in the service, not the repository, because "what counts as the same
// email" is a business rule. Postgres would happily store Bob@x.com and
// bob@x.com as two accounts; we decide they are one person.
//
// Note this does NOT do full RFC 5321 normalisation (stripping gmail dots,
// +suffixes). Those are provider-specific policies, and applying them would
// mean bob+work@gmail.com cannot have its own account — which some users
// legitimately want.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Register creates an account and grants it the default role.
//
// The user row and the role assignment are written in ONE transaction. Without
// that, a crash between the two statements leaves a user who exists but can do
// nothing, and no error anywhere says so.
func (s *AuthService) Register(ctx context.Context, email, password, firstName, lastName string) (*models.User, error) {
	email = NormalizeEmail(email)

	// A pre-check for a friendly error. It does NOT make the operation safe:
	// two concurrent registrations can both pass this check. The partial unique
	// index on users.email is what actually guarantees uniqueness, and
	// repositories.mapError turns its violation into the same EMAIL_TAKEN
	// error. This check exists only so the common case reads well.
	exists, err := s.users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, apperrors.Conflict("EMAIL_TAKEN", "An account with this email already exists").
			WithField("email", "This email is already registered")
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// UUIDv7: a 48-bit millisecond timestamp followed by randomness. Sorting by
	// id therefore sorts roughly by creation time, and new rows append to the
	// right edge of the primary-key B-tree instead of scattering through it.
	// uuid.NewV4 would work correctly but fragment the index.
	id, err := uuid.NewV7()
	if err != nil {
		return nil, apperrors.Internal(fmt.Errorf("services: generating user id: %w", err))
	}

	user := &models.User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		FirstName:    strings.TrimSpace(firstName),
		LastName:     strings.TrimSpace(lastName),
		IsActive:     true,
	}

	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.users.Create(ctx, user); err != nil {
			return err
		}

		role, err := s.roles.GetByName(ctx, s.defaultRole)
		if err != nil {
			// The 'user' role is seeded by migration 00004. If it is missing,
			// the database is not in the state the code expects. That is our
			// bug, not the caller's.
			return apperrors.Internal(fmt.Errorf("services: default role %q missing: %w", s.defaultRole, err))
		}
		return s.roles.AssignToUser(ctx, user.ID, role.ID)
	})
	if err != nil {
		return nil, err
	}

	// Reload roles so the caller can mint a token, or render the response,
	// without a second round trip through the handler.
	if user.Roles, err = s.roles.ForUser(ctx, user.ID); err != nil {
		return nil, err
	}

	log := logger.FromContext(ctx)
	log.Info("user registered", slog.String("user_id", user.ID.String()))

	// Send the verification email AFTER the transaction has committed, and do
	// not fail registration if it cannot be sent.
	//
	// The two failure modes are not equal. If the account exists and the email
	// does not arrive, the user presses "resend". If we roll the account back
	// because a mail server was briefly down, the user's signup silently
	// vanished and they have no idea why. The second is much worse.
	//
	// This is also why the email is not sent inside the transaction: a slow mail
	// server would hold a database transaction — and its locks — open for the
	// duration.
	if err := s.verification.SendFor(ctx, user); err != nil {
		log.Warn("could not send verification email; the account was still created",
			slog.String("user_id", user.ID.String()),
			slog.String("error", err.Error()))
	}

	return user, nil
}

// Login verifies credentials and issues a token pair.
//
// # The three failure branches all look identical from outside
//
//	unknown email     -> INVALID_CREDENTIALS (401)
//	wrong password    -> INVALID_CREDENTIALS (401)
//
// and they take the same amount of time, because the unknown-email branch runs
// a throwaway bcrypt comparison. A disabled account is the one exception: it
// returns 403, because the caller proved they own the account and deserves to
// know why they cannot get in.
func (s *AuthService) Login(ctx context.Context, email, password string) (*TokenPair, *models.User, error) {
	email = NormalizeEmail(email)

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			// Spend the same ~300ms the real path would spend, so response
			// time reveals nothing about whether this address has an account.
			burnPasswordTime(password)
			return nil, nil, errInvalidCredentials()
		}
		return nil, nil, err
	}

	if err := VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, nil, err
	}

	if !user.CanLogin() {
		return nil, nil, apperrors.Forbidden("ACCOUNT_DISABLED",
			"This account has been disabled. Contact support.")
	}

	if user.Roles, err = s.roles.ForUser(ctx, user.ID); err != nil {
		return nil, nil, err
	}

	pair, err := s.issueTokenPair(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	logger.FromContext(ctx).Info("user logged in", slog.String("user_id", user.ID.String()))
	return pair, user, nil
}

// Refresh exchanges a refresh token for a fresh pair, rotating the refresh
// token in the process.
//
// # Rotation and reuse detection
//
// Every refresh consumes the old token and issues a new one. So a given refresh
// token is valid exactly once.
//
// If a token that has ALREADY been revoked is presented, something is wrong:
// either an attacker stole a token and is using it after the real user rotated
// it, or the real user is replaying one the attacker rotated. We cannot tell
// which — so we revoke every session for that user and force a fresh login.
// This turns a silent, permanent compromise into a visible, bounded one.
func (s *AuthService) Refresh(ctx context.Context, rawToken string) (*TokenPair, *models.User, error) {
	log := logger.FromContext(ctx)
	hash := HashOpaqueToken(rawToken)

	stored, err := s.refreshStore.GetByHash(ctx, hash)
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			return nil, nil, apperrors.Unauthorized("REFRESH_TOKEN_INVALID", "Invalid refresh token")
		}
		return nil, nil, err
	}

	now := s.clock.Now()

	if stored.RevokedAt != nil {
		// Reuse of a revoked token. Assume compromise.
		log.Warn("refresh token reuse detected — revoking all sessions",
			slog.String("user_id", stored.UserID.String()),
			slog.String("token_id", stored.ID.String()))

		if err := s.refreshStore.RevokeAllForUser(ctx, stored.UserID); err != nil {
			return nil, nil, err
		}
		return nil, nil, apperrors.Unauthorized("REFRESH_TOKEN_REVOKED",
			"This session has been revoked. Please sign in again.")
	}

	if !stored.IsUsable(now) {
		return nil, nil, apperrors.Unauthorized("REFRESH_TOKEN_EXPIRED", "Refresh token has expired")
	}

	user, err := s.users.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, nil, err
	}
	if !user.CanLogin() {
		return nil, nil, apperrors.Forbidden("ACCOUNT_DISABLED", "This account has been disabled.")
	}
	if user.Roles, err = s.roles.ForUser(ctx, user.ID); err != nil {
		return nil, nil, err
	}

	var pair *TokenPair
	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		// Revoke first. If issuing the new token then fails, the transaction
		// rolls back and the old token survives — the user retries and nothing
		// is lost. The reverse order could leave two live tokens.
		if err := s.refreshStore.Revoke(ctx, stored.ID); err != nil {
			return err
		}

		// A fresh local, not the enclosing `err`. Assigning to a captured
		// variable from inside a closure works, but it means the value of `err`
		// after InTx returns depends on whether the closure ran at all.
		issued, err := s.issueTokenPair(ctx, user)
		if err != nil {
			return err
		}
		pair = issued
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return pair, user, nil
}

// Logout revokes a single refresh token, ending one session.
//
// An unknown token is not an error. Reporting "that token does not exist" would
// let an attacker probe which tokens are live, and there is nothing useful a
// client can do with the distinction anyway.
func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	stored, err := s.refreshStore.GetByHash(ctx, HashOpaqueToken(rawToken))
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			return nil
		}
		return err
	}
	return s.refreshStore.Revoke(ctx, stored.ID)
}

// ChangePassword updates the caller's password and ends every other session.
//
// Requiring the current password matters: an attacker holding only a stolen
// access token cannot use it to take over the account permanently.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := VerifyPassword(user.PasswordHash, currentPassword); err != nil {
		// Deliberately a different message from login's: the caller is already
		// authenticated, so there is no account to enumerate, and "your current
		// password is wrong" is the only useful thing to say.
		if apperrors.IsKind(err, apperrors.KindUnauthorized) {
			return apperrors.Unauthorized("CURRENT_PASSWORD_INCORRECT", "Current password is incorrect").
				WithField("currentPassword", "Incorrect password")
		}
		return err
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.users.UpdatePassword(ctx, userID, hash); err != nil {
			return err
		}
		// Changing a password must end sessions the attacker may hold. Access
		// tokens cannot be revoked, so they survive up to JWT_ACCESS_TTL; the
		// refresh tokens die now, which bounds the damage to that window.
		return s.refreshStore.RevokeAllForUser(ctx, userID)
	})
	if err != nil {
		return err
	}

	logger.FromContext(ctx).Info("password changed", slog.String("user_id", userID.String()))
	return nil
}

// issueTokenPair mints an access token and persists a new refresh token.
// The caller must have loaded user.Roles.
func (s *AuthService) issueTokenPair(ctx context.Context, user *models.User) (*TokenPair, error) {
	accessToken, expiresAt, err := s.tokens.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	rawRefresh, refreshHash, err := GenerateOpaqueToken()
	if err != nil {
		return nil, err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, apperrors.Internal(fmt.Errorf("services: generating refresh token id: %w", err))
	}

	record := &models.RefreshToken{
		ID:        id,
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: s.clock.Now().Add(s.tokens.RefreshTTL()),
	}
	if err := s.refreshStore.Create(ctx, record); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresAt:    expiresAt,
		ExpiresIn:    int64(s.tokens.AccessTTL().Seconds()),
	}, nil
}
