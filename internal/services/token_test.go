package services

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/config"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

const testSecret = "a-test-signing-secret-of-at-least-32-chars"

func testJWTConfig() config.JWTConfig {
	return config.JWTConfig{
		Secret:     testSecret,
		Issuer:     "test-issuer",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
}

func testUser() *models.User {
	return &models.User{
		ID:    uuid.MustParse("019405b0-0000-7000-8000-000000000001"),
		Email: "alice@example.com",
		Roles: []models.Role{{
			Name: models.RoleAdmin,
			Permissions: []models.Permission{
				{Name: models.PermissionUsersRead},
				{Name: models.PermissionUsersDelete},
			},
		}},
	}
}

func TestGenerateAndParseAccessToken(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)
	user := testUser()

	token, expiresAt, err := svc.GenerateAccessToken(user)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), expiresAt, 5*time.Second)

	claims, err := svc.ParseAccessToken(token)
	require.NoError(t, err)

	gotID, err := claims.UserID()
	require.NoError(t, err)
	assert.Equal(t, user.ID, gotID)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.NotEmpty(t, claims.ID, "jti must be set so a token can be named in a deny-list")

	assert.True(t, claims.HasRole(models.RoleAdmin))
	assert.True(t, claims.HasPermission(models.PermissionUsersRead))
	assert.False(t, claims.HasPermission("invoices:approve"))
}

// Two roles granting the same permission must not repeat it in the token.
func TestGenerateAccessToken_DeduplicatesPermissions(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	user := &models.User{
		ID: uuid.Must(uuid.NewV7()),
		Roles: []models.Role{
			{Name: "a", Permissions: []models.Permission{{Name: models.PermissionUsersRead}}},
			{Name: "b", Permissions: []models.Permission{{Name: models.PermissionUsersRead}}},
		},
	}

	token, _, err := svc.GenerateAccessToken(user)
	require.NoError(t, err)

	claims, err := svc.ParseAccessToken(token)
	require.NoError(t, err)
	assert.Len(t, claims.Permissions, 1)
}

// ---------------------------------------------------------------------------
// Attack tests. Each one is a real, published JWT vulnerability.
// ---------------------------------------------------------------------------

// The `alg: none` attack.
//
// An attacker takes a valid token, rewrites its header to {"alg":"none"}, drops
// the signature, and sends it. A library that obeys the token's own header
// performs NO verification and accepts it. jwt.WithValidMethods is what stops
// this, and this test proves the option is actually in effect.
func TestParseAccessToken_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	b64 := func(v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	header := b64(map[string]string{"alg": "none", "typ": "JWT"})
	payload := b64(map[string]any{
		"iss": "test-issuer",
		"sub": uuid.Must(uuid.NewV7()).String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// "alg":"none" tokens carry an empty signature segment.
	forged := header + "." + payload + "."

	_, err := svc.ParseAccessToken(forged)
	require.Error(t, err, "a token signed with 'none' must never be accepted")
	assert.Equal(t, 401, apperrors.From(err).HTTPStatus())
}

// A token signed with the right algorithm but the wrong key.
func TestParseAccessToken_RejectsWrongSignature(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   uuid.Must(uuid.NewV7()).String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Roles: []string{models.RoleAdmin},
	})
	signed, err := forged.SignedString([]byte("the-attackers-own-secret-key-here"))
	require.NoError(t, err)

	_, err = svc.ParseAccessToken(signed)
	require.Error(t, err)
	assert.Equal(t, "TOKEN_INVALID", apperrors.From(err).Code)
}

// A token minted by a different environment must not be replayable here, even
// if the two share a signing key by mistake.
func TestParseAccessToken_RejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	staging := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "staging",
			Subject:   uuid.Must(uuid.NewV7()).String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	signed, err := staging.SignedString([]byte(testSecret))
	require.NoError(t, err)

	_, err = svc.ParseAccessToken(signed)
	require.Error(t, err)
}

// A token with no `exp` claim is a permanent credential.
func TestParseAccessToken_RejectsMissingExpiry(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	eternal := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "test-issuer",
			Subject: uuid.Must(uuid.NewV7()).String(),
		},
	})
	signed, err := eternal.SignedString([]byte(testSecret))
	require.NoError(t, err)

	_, err = svc.ParseAccessToken(signed)
	require.Error(t, err, "WithExpirationRequired must reject a token that never expires")
}

// Expiry is enforced. The injected clock mints a token in the past, so no test
// has to sleep for fifteen minutes.
func TestParseAccessToken_RejectsExpired(t *testing.T) {
	t.Parallel()

	past := fixedClock{t: time.Now().Add(-2 * time.Hour)}
	minter := NewTokenService(testJWTConfig(), past)

	token, _, err := minter.GenerateAccessToken(testUser())
	require.NoError(t, err)

	// Verify with the real clock: the token expired 105 minutes ago.
	verifier := NewTokenService(testJWTConfig(), SystemClock)
	_, err = verifier.ParseAccessToken(token)

	require.Error(t, err)
	assert.Equal(t, "TOKEN_EXPIRED", apperrors.From(err).Code,
		"clients branch on this code to decide whether to refresh or re-login")
}

func TestParseAccessToken_RejectsGarbage(t *testing.T) {
	t.Parallel()
	svc := NewTokenService(testJWTConfig(), SystemClock)

	for _, bad := range []string{"", "not-a-jwt", "a.b.c", "....", "eyJhbGciOiJIUzI1NiJ9"} {
		_, err := svc.ParseAccessToken(bad)
		assert.Error(t, err, "input %q must be rejected", bad)
	}
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

func TestGenerateOpaqueToken(t *testing.T) {
	t.Parallel()

	raw, hash, err := GenerateOpaqueToken()
	require.NoError(t, err)

	// 32 random bytes, base64url without padding = 43 characters.
	assert.Len(t, raw, 43)
	assert.Len(t, hash, 64, "sha256 hex digest is 64 characters")
	assert.NotEqual(t, raw, hash)

	// Hashing is deterministic, which is what lets us look the token up.
	assert.Equal(t, hash, HashOpaqueToken(raw))
}

func TestGenerateRefreshToken_IsUnpredictable(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 500)
	for range 500 {
		raw, _, err := GenerateOpaqueToken()
		require.NoError(t, err)
		_, dup := seen[raw]
		require.False(t, dup, "crypto/rand produced a duplicate token — this must never happen")
		seen[raw] = struct{}{}
	}
}

func TestRefreshToken_IsUsable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Hour)

	cases := []struct {
		name  string
		token models.RefreshToken
		want  bool
	}{
		{"live", models.RefreshToken{ExpiresAt: now.Add(time.Hour)}, true},
		{"expired", models.RefreshToken{ExpiresAt: now.Add(-time.Second)}, false},
		{"expires exactly now", models.RefreshToken{ExpiresAt: now}, false},
		{"revoked", models.RefreshToken{ExpiresAt: now.Add(time.Hour), RevokedAt: &revoked}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.token.IsUsable(now))
		})
	}
}
