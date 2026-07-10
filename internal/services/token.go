package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/config"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// Claims is the payload of an access token.
//
// # What belongs in a JWT, and what does not
//
// A JWT is SIGNED, not ENCRYPTED. Anyone holding the token can read every
// claim by base64-decoding the middle segment — no key required. Paste one into
// jwt.io and see. Therefore: never put a password, a secret, or anything you
// would not print on a postcard into a claim.
//
// Roles and permissions ARE here, and that is a deliberate trade-off:
//
//	Advantage    The auth middleware answers "may this user do X?" from the
//	             token alone. Zero database queries on the hot path. At 1,000
//	             requests/second that is 1,000 queries/second you do not run.
//
//	Disadvantage The token is a SNAPSHOT. Revoke someone's admin role and they
//	             keep it until their access token expires. That window is
//	             exactly JWT_ACCESS_TTL — 15 minutes by default.
//
//	When to use  Almost always. 15 minutes of stale authorisation is acceptable
//	             for nearly every application.
//
//	When not to  When a revoked permission must take effect instantly (banking,
//	             emergency lockout). Then either shrink the TTL to ~60s, or look
//	             the permissions up per-request and cache them in Redis.
type Claims struct {
	jwt.RegisteredClaims

	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// UserID parses the standard `sub` claim back into a UUID.
func (c *Claims) UserID() (uuid.UUID, error) {
	return uuid.Parse(c.Subject)
}

// HasPermission reports whether the token grants the named permission.
func (c *Claims) HasPermission(name string) bool {
	for _, p := range c.Permissions {
		if p == name {
			return true
		}
	}
	return false
}

// HasRole reports whether the token carries the named role.
func (c *Claims) HasRole(name string) bool {
	for _, r := range c.Roles {
		if r == name {
			return true
		}
	}
	return false
}

// TokenService mints and verifies tokens.
type TokenService struct {
	cfg   config.JWTConfig
	clock Clock
}

// NewTokenService builds the token minter and verifier. clock is injected so
// that expiry can be tested without sleeping.
func NewTokenService(cfg config.JWTConfig, clock Clock) *TokenService {
	return &TokenService{cfg: cfg, clock: clock}
}

// AccessTTL exposes the configured lifetime so handlers can report expiresIn.
func (s *TokenService) AccessTTL() time.Duration { return s.cfg.AccessTTL }

// RefreshTTL exposes the refresh lifetime.
func (s *TokenService) RefreshTTL() time.Duration { return s.cfg.RefreshTTL }

// GenerateAccessToken mints a signed, short-lived access token for u.
//
// u.Roles must be loaded, or the token will carry no permissions and the user
// will be silently unable to do anything.
func (s *TokenService) GenerateAccessToken(u *models.User) (string, time.Time, error) {
	now := s.clock.Now()
	expiresAt := now.Add(s.cfg.AccessTTL)

	roles := make([]string, 0, len(u.Roles))
	permSet := make(map[string]struct{})
	for _, role := range u.Roles {
		roles = append(roles, role.Name)
		for _, p := range role.Permissions {
			permSet[p.Name] = struct{}{}
		}
	}
	// Flatten to a de-duplicated slice: two roles may grant the same
	// permission, and repeating it only bloats the token.
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			// sub: who the token is about.
			Subject: u.ID.String(),
			// iss: who minted it. Verified on parse, so a token from staging
			// cannot be replayed against production.
			Issuer: s.cfg.Issuer,
			// exp: when it stops being valid. The only thing standing between
			// a stolen token and permanent access.
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			// nbf: not valid before now. Guards against clock skew games.
			NotBefore: jwt.NewNumericDate(now),
			// jti: a unique id per token, so a future deny-list can name one.
			ID: uuid.NewString(),
		},
		Email:       u.Email,
		Roles:       roles,
		Permissions: perms,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return "", time.Time{}, apperrors.Internal(fmt.Errorf("services: signing access token: %w", err))
	}
	return signed, expiresAt, nil
}

// ParseAccessToken verifies a token's signature, issuer and expiry, and returns
// its claims.
func (s *TokenService) ParseAccessToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (any, error) {
			// This callback supplies the verification key. Returning the key
			// unconditionally is safe ONLY because WithValidMethods below has
			// already rejected any algorithm other than HS256.
			return []byte(s.cfg.Secret), nil
		},

		// ── The two most important lines in this file ──────────────────────
		//
		// WithValidMethods pins the signing algorithm.
		//
		// Without it, an attacker rewrites the token header to {"alg":"none"},
		// strips the signature, and the library — obeying the token — performs
		// no verification at all. Or, if you ever verify RS256 tokens, they set
		// alg=HS256 and sign the token with your PUBLIC key as the HMAC secret;
		// a naive keyfunc hands back that public key and the signature checks
		// out. Both are real CVEs, filed against many JWT libraries.
		//
		// The rule: never let the token tell you how to verify the token.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),

		// Reject a token minted by a different service or environment.
		jwt.WithIssuer(s.cfg.Issuer),

		// Reject a token that has no exp claim. A JWT without an expiry is a
		// permanent credential.
		jwt.WithExpirationRequired(),
		// ──────────────────────────────────────────────────────────────────

		jwt.WithLeeway(5*time.Second), // tolerate small clock skew between hosts
	)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			// A distinct code so the client knows to refresh rather than to
			// send the user back to the login screen.
			return nil, apperrors.Unauthorized("TOKEN_EXPIRED", "Access token has expired")
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, apperrors.Unauthorized("TOKEN_NOT_YET_VALID", "Access token is not valid yet")
		default:
			// Malformed, wrong signature, wrong issuer, wrong algorithm. The
			// client learns only that the token is invalid; the reason is
			// logged, not returned, because it would help an attacker iterate.
			return nil, apperrors.Wrap(err, apperrors.KindUnauthorized,
				"TOKEN_INVALID", "Invalid access token")
		}
	}

	return claims, nil
}

// ---------------------------------------------------------------------------
// Opaque tokens
//
// An opaque token is NOT a JWT. It is 256 bits of randomness with no structure
// and no claims. It carries no information, so there is nothing to leak, and it
// is meaningful only because a matching row exists in the database — which is
// precisely what makes it revocable.
//
// Refresh tokens and email-verification tokens are both opaque tokens. They
// differ only in which table stores the hash and how long it lives, so they
// share one generator. Two copies of this code would eventually drift, and the
// one nobody looked at would be the one using math/rand.
// ---------------------------------------------------------------------------

// opaqueTokenBytes is 32 bytes = 256 bits of entropy. Guessing one is as hard
// as guessing an AES-256 key.
const opaqueTokenBytes = 32

// GenerateOpaqueToken returns (rawToken, tokenHash).
//
// The raw token is handed out exactly once — in a response body, or in a link
// inside an email — and never stored. The hash is stored and never handed out.
// Neither can be derived from the other in the wrong direction.
func GenerateOpaqueToken() (raw, hash string, err error) {
	b := make([]byte, opaqueTokenBytes)

	// crypto/rand, never math/rand. math/rand is a deterministic PRNG: seed it
	// the same way and it produces the same "random" tokens. crypto/rand reads
	// the operating system's CSPRNG.
	if _, err := rand.Read(b); err != nil {
		return "", "", apperrors.Internal(fmt.Errorf("services: generating opaque token: %w", err))
	}

	// URL-safe, unpadded: the token travels in JSON, in headers, and in the
	// query string of a link inside an email.
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashOpaqueToken(raw), nil
}

// HashOpaqueToken returns the SHA-256 hex digest used as the database key.
//
// SHA-256, not bcrypt. bcrypt is deliberately slow to defeat dictionary attacks
// on LOW-entropy secrets (human passwords). An opaque token has 256 bits of
// entropy: there is no dictionary, and a slow hash would only mean every token
// exchange costs 300ms of CPU. Fast is correct here.
func HashOpaqueToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
