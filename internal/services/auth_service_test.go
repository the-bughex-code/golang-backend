package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/config"
)

// newTestAuthService assembles an AuthService from fakes. Every test starts
// from a clean, empty world.
//
// This is the composition root from main.go, in miniature — which is a good
// sign: if wiring for a test were harder than wiring for production, the
// dependencies would be wrong.
func newTestAuthService(t *testing.T) (*AuthService, *fakeUserStore, *fakeRoleStore, *fakeRefreshStore, *fakeTx) {
	t.Helper()

	users := newFakeUserStore()
	roles := newFakeRoleStore()
	refresh := newFakeRefreshStore()
	tx := &fakeTx{}

	clock := fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	tokens := NewTokenService(config.JWTConfig{
		Secret:     "test-secret-that-is-at-least-32-characters-long",
		Issuer:     "test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}, clock)

	return NewAuthService(users, roles, refresh, tokens, tx, clock), users, roles, refresh, tx
}

const testPassword = "correct-horse-battery-staple"

func TestRegister_Success(t *testing.T) {
	t.Parallel()
	auth, _, _, _, tx := newTestAuthService(t)

	user, err := auth.Register(context.Background(), "  Alice@Example.COM ", testPassword, "Alice", "Nguyen")
	require.NoError(t, err)

	assert.Equal(t, "alice@example.com", user.Email, "email must be trimmed and lowercased")
	assert.NotEmpty(t, user.PasswordHash)
	assert.NotEqual(t, testPassword, user.PasswordHash, "the plaintext password must never be stored")
	assert.True(t, user.IsActive)
	assert.Nil(t, user.EmailVerifiedAt, "a new account is not verified")

	// UUIDv7 embeds a timestamp in its high bits; version nibble is 7.
	assert.Equal(t, byte(7), user.ID[6]>>4, "user ids must be UUIDv7, not v4")

	require.Len(t, user.Roles, 1)
	assert.Equal(t, "user", user.Roles[0].Name, "new accounts get the default role")

	assert.Equal(t, 1, tx.calls, "user creation and role assignment must share one transaction")
}

func TestRegister_DuplicateEmail(t *testing.T) {
	t.Parallel()
	auth, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)

	// Different case, same address. Normalisation must catch it.
	_, err = auth.Register(ctx, "ALICE@example.com", testPassword, "Alice", "N")
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindConflict), "expected a 409-kind error, got %v", err)
}

func TestLogin_Success(t *testing.T) {
	t.Parallel()
	auth, _, _, refresh, _ := newTestAuthService(t)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)

	pair, user, err := auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)

	assert.Equal(t, registered.ID, user.ID)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, int64(900), pair.ExpiresIn, "15 minutes, in seconds")
	assert.Equal(t, 1, refresh.liveCount(user.ID), "login stores exactly one refresh token")
}

// The security property that matters most: a wrong password and an unknown
// account must be indistinguishable to the caller.
func TestLogin_WrongPasswordAndUnknownUser_AreIndistinguishable(t *testing.T) {
	t.Parallel()
	auth, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)

	_, _, wrongPwErr := auth.Login(ctx, "alice@example.com", "not-the-password")
	_, _, unknownErr := auth.Login(ctx, "nobody@example.com", "not-the-password")

	require.Error(t, wrongPwErr)
	require.Error(t, unknownErr)

	wrong := apperrors.From(wrongPwErr)
	unknown := apperrors.From(unknownErr)

	assert.Equal(t, wrong.Code, unknown.Code, "error codes must match")
	assert.Equal(t, wrong.Message, unknown.Message, "messages must match")
	assert.Equal(t, wrong.HTTPStatus(), unknown.HTTPStatus(), "status codes must match")
	assert.Equal(t, 401, wrong.HTTPStatus())
}

func TestLogin_DisabledAccount(t *testing.T) {
	t.Parallel()
	auth, users, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	user, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)

	users.byID[user.ID].IsActive = false
	users.byEmail[user.Email].IsActive = false

	_, _, err = auth.Login(ctx, "alice@example.com", testPassword)
	require.Error(t, err)

	// 403, not 401: the caller proved they own the account, so telling them it
	// is disabled reveals nothing they did not already know.
	assert.True(t, apperrors.IsKind(err, apperrors.KindForbidden))
	assert.Equal(t, 403, apperrors.From(err).HTTPStatus())
}

func TestRefresh_RotatesToken(t *testing.T) {
	t.Parallel()
	auth, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)
	first, _, err := auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)

	second, _, err := auth.Refresh(ctx, first.RefreshToken)
	require.NoError(t, err)

	assert.NotEqual(t, first.RefreshToken, second.RefreshToken,
		"every refresh must issue a new token; a reusable refresh token is a permanent credential")
}

// Reuse of an already-rotated refresh token means the token was copied. We
// cannot tell whether the attacker or the victim is holding the copy, so every
// session is destroyed.
func TestRefresh_ReuseDetection_RevokesEverySession(t *testing.T) {
	t.Parallel()
	auth, _, _, refresh, _ := newTestAuthService(t)
	ctx := context.Background()

	user, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)
	first, _, err := auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)

	second, _, err := auth.Refresh(ctx, first.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, 1, refresh.liveCount(user.ID))

	// Replay the consumed token.
	_, _, err = auth.Refresh(ctx, first.RefreshToken)
	require.Error(t, err)
	assert.Equal(t, "REFRESH_TOKEN_REVOKED", apperrors.From(err).Code)

	assert.Equal(t, 0, refresh.liveCount(user.ID), "all sessions must be revoked")

	// The legitimately-rotated token must be dead too.
	_, _, err = auth.Refresh(ctx, second.RefreshToken)
	require.Error(t, err)
}

func TestRefresh_UnknownToken(t *testing.T) {
	t.Parallel()
	auth, _, _, _, _ := newTestAuthService(t)

	_, _, err := auth.Refresh(context.Background(), "this-token-was-never-issued")
	require.Error(t, err)
	assert.Equal(t, "REFRESH_TOKEN_INVALID", apperrors.From(err).Code)
}

func TestLogout_RevokesOnlyThatSession(t *testing.T) {
	t.Parallel()
	auth, _, _, refresh, _ := newTestAuthService(t)
	ctx := context.Background()

	user, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)

	phone, _, err := auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)
	_, _, err = auth.Login(ctx, "alice@example.com", testPassword) // laptop
	require.NoError(t, err)
	require.Equal(t, 2, refresh.liveCount(user.ID))

	require.NoError(t, auth.Logout(ctx, phone.RefreshToken))
	assert.Equal(t, 1, refresh.liveCount(user.ID), "signing out on one device must not sign out the others")
}

// Logging out with a token that does not exist is a no-op, not an error.
// Reporting "no such token" would let an attacker probe which tokens are live.
func TestLogout_UnknownTokenIsNotAnError(t *testing.T) {
	t.Parallel()
	auth, _, _, _, _ := newTestAuthService(t)

	assert.NoError(t, auth.Logout(context.Background(), "never-issued"))
}

func TestChangePassword_RevokesAllSessions(t *testing.T) {
	t.Parallel()
	auth, _, _, refresh, _ := newTestAuthService(t)
	ctx := context.Background()

	user, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)
	_, _, err = auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)
	_, _, err = auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)
	require.Equal(t, 2, refresh.liveCount(user.ID))

	const newPassword = "an-entirely-different-password"
	require.NoError(t, auth.ChangePassword(ctx, user.ID, testPassword, newPassword))

	assert.Equal(t, 0, refresh.liveCount(user.ID),
		"changing a password must end every session, including an attacker's")

	// Old password no longer works; new one does.
	_, _, err = auth.Login(ctx, "alice@example.com", testPassword)
	require.Error(t, err)

	_, _, err = auth.Login(ctx, "alice@example.com", newPassword)
	require.NoError(t, err)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	t.Parallel()
	auth, _, _, refresh, _ := newTestAuthService(t)
	ctx := context.Background()

	user, err := auth.Register(ctx, "alice@example.com", testPassword, "Alice", "N")
	require.NoError(t, err)
	_, _, err = auth.Login(ctx, "alice@example.com", testPassword)
	require.NoError(t, err)

	err = auth.ChangePassword(ctx, user.ID, "wrong-current", "a-new-password-here")
	require.Error(t, err)
	assert.Equal(t, "CURRENT_PASSWORD_INCORRECT", apperrors.From(err).Code)
	assert.Equal(t, 1, refresh.liveCount(user.ID), "a failed change must not revoke sessions")
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	// Table-driven tests are the Go convention: one case per row, one failure
	// message per row, and adding a case costs one line.
	cases := []struct {
		name, in, want string
	}{
		{"lowercases", "Alice@Example.COM", "alice@example.com"},
		{"trims", "  alice@example.com  ", "alice@example.com"},
		{"both", "\t Alice@EXAMPLE.com \n", "alice@example.com"},
		{"already clean", "alice@example.com", "alice@example.com"},
		{"preserves plus addressing", "alice+work@example.com", "alice+work@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, NormalizeEmail(tc.in))
		})
	}
}
