package services

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

const testBaseURL = "https://app.example.com"

type verifyFixture struct {
	svc    *VerificationService
	users  *fakeUserStore
	tokens *fakeVerificationTokenStore
	mailer *fakeMailer
	clock  fixedClock
}

func newTestVerificationService(t *testing.T) *verifyFixture {
	t.Helper()

	f := &verifyFixture{
		users:  newFakeUserStore(),
		tokens: newFakeVerificationTokenStore(),
		mailer: &fakeMailer{},
		clock:  fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
	}
	f.svc = NewVerificationService(f.users, f.tokens, f.mailer, &fakeTx{}, f.clock, testBaseURL, 24*time.Hour)
	return f
}

// seedUser inserts an unverified account.
func (f *verifyFixture) seedUser(t *testing.T, email string) *models.User {
	t.Helper()

	u := &models.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        email,
		PasswordHash: "irrelevant",
		FirstName:    "Alice",
		LastName:     "Nguyen",
		IsActive:     true,
	}
	require.NoError(t, f.users.Create(context.Background(), u))
	return u
}

// tokenFromEmail extracts the raw token out of the link in the message body.
// This is exactly what a user's browser does, so the test exercises the real
// round trip rather than reaching into the store for a hash.
var linkTokenRE = regexp.MustCompile(`token=([A-Za-z0-9_%\-]+)`)

func tokenFromEmail(t *testing.T, body string) string {
	t.Helper()

	m := linkTokenRE.FindStringSubmatch(body)
	require.Len(t, m, 2, "the email must contain a ?token= link, got:\n%s", body)

	raw, err := url.QueryUnescape(m[1])
	require.NoError(t, err)
	return raw
}

func TestSendFor_IssuesATokenAndEmailsTheLink(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")

	require.NoError(t, f.svc.SendFor(context.Background(), user))

	require.Equal(t, 1, f.mailer.count())
	sent := f.mailer.last()
	assert.Equal(t, "alice@example.com", sent.to)
	assert.Contains(t, sent.subject, "Verify")
	assert.Contains(t, sent.body, testBaseURL+"/verify-email?token=")
	assert.Contains(t, sent.body, "Alice", "the email should greet the user by name")

	assert.Equal(t, 1, f.tokens.liveCount(user.ID))

	// The raw token must never be what we stored.
	raw := tokenFromEmail(t, sent.body)
	stored, err := f.tokens.GetByHash(context.Background(), HashOpaqueToken(raw))
	require.NoError(t, err, "the emailed token must hash to a stored row")
	assert.NotEqual(t, raw, stored.TokenHash, "the raw token must never be stored")
	assert.Len(t, stored.TokenHash, 64, "sha256 hex digest")
}

// Clicking "resend" three times must not leave three live links, each an
// independent way into the account.
func TestSendFor_InvalidatesPreviousTokens(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.svc.SendFor(ctx, user))
	first := tokenFromEmail(t, f.mailer.last().body)

	require.NoError(t, f.svc.SendFor(ctx, user))
	second := tokenFromEmail(t, f.mailer.last().body)

	require.NotEqual(t, first, second)
	assert.Equal(t, 1, f.tokens.liveCount(user.ID), "only the newest link may be live")

	// The old link no longer works.
	_, err := f.svc.Verify(ctx, first)
	require.Error(t, err)
	assert.Equal(t, "VERIFICATION_TOKEN_INVALID", apperrors.From(err).Code)

	// The new one does.
	_, err = f.svc.Verify(ctx, second)
	assert.NoError(t, err)
}

func TestSendFor_AlreadyVerifiedSendsNothing(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	verified := f.clock.Now()
	user.EmailVerifiedAt = &verified

	require.NoError(t, f.svc.SendFor(context.Background(), user))
	assert.Zero(t, f.mailer.count(), "no email for an address that is already confirmed")
}

func TestSendFor_MailFailureIsReportedButTheTokenSurvives(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	f.mailer.err = errors.New("smtp: connection refused")

	err := f.svc.SendFor(context.Background(), user)

	require.Error(t, err)
	assert.Equal(t, "MAIL_SEND_FAILED", apperrors.From(err).Code)
	assert.Equal(t, 503, apperrors.From(err).HTTPStatus())

	// The token was committed before the send was attempted, so a resend is not
	// required to make the account verifiable — only a working mail server.
	assert.Equal(t, 1, f.tokens.liveCount(user.ID))
}

func TestVerify_MarksTheUserVerifiedAndConsumesTheToken(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.svc.SendFor(ctx, user))
	raw := tokenFromEmail(t, f.mailer.last().body)

	verified, err := f.svc.Verify(ctx, raw)
	require.NoError(t, err)

	assert.True(t, verified.IsEmailVerified())
	require.NotNil(t, verified.EmailVerifiedAt)
	assert.Equal(t, f.clock.Now(), *verified.EmailVerifiedAt)

	// It really persisted.
	fromStore, err := f.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, fromStore.IsEmailVerified())

	assert.Zero(t, f.tokens.liveCount(user.ID), "the token must be consumed")
}

// An email sits in an inbox for years. A link that keeps working is a permanent
// account-takeover vector for whoever later reads that mailbox.
//
// # Why the second attempt is an error rather than a friendly no-op
//
// It would be kinder to answer "you are already verified" when someone clicks
// the link twice. But a consumed token that still returns success is a
// permanent oracle: anyone holding an old email can ask, forever, whether that
// account exists and is verified.
//
// A single-use token means single use. The frontend turns
// VERIFICATION_TOKEN_INVALID into "this link has already been used — try
// signing in", which is the same kindness without the oracle.
func TestVerify_TokenWorksExactlyOnce(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.svc.SendFor(ctx, user))
	raw := tokenFromEmail(t, f.mailer.last().body)

	verified, err := f.svc.Verify(ctx, raw)
	require.NoError(t, err)
	require.True(t, verified.IsEmailVerified())

	// Second redemption of the same link is rejected, with the same error an
	// unknown token produces.
	_, err = f.svc.Verify(ctx, raw)
	require.Error(t, err)
	assert.Equal(t, "VERIFICATION_TOKEN_INVALID", apperrors.From(err).Code)

	// The account stays verified, of course.
	fromStore, err := f.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, fromStore.IsEmailVerified())
}

func TestVerify_ExpiredToken(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.svc.SendFor(ctx, user))
	raw := tokenFromEmail(t, f.mailer.last().body)

	// Move the service's clock past the 24h TTL. No sleeping.
	future := fixedClock{t: f.clock.Now().Add(25 * time.Hour)}
	expired := NewVerificationService(f.users, f.tokens, f.mailer, &fakeTx{}, future, testBaseURL, 24*time.Hour)

	_, err := expired.Verify(ctx, raw)
	require.Error(t, err)
	assert.Equal(t, "VERIFICATION_TOKEN_INVALID", apperrors.From(err).Code)

	fromStore, err := f.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, fromStore.IsEmailVerified())
}

// An unknown token, an expired one and a used one must be indistinguishable.
// Otherwise a token guesser learns which of their guesses had once been real.
func TestVerify_UnknownTokenLooksExactlyLikeAnExpiredOne(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)

	_, unknownErr := f.svc.Verify(context.Background(), "this-token-was-never-issued")
	require.Error(t, unknownErr)

	unknown := apperrors.From(unknownErr)
	assert.Equal(t, "VERIFICATION_TOKEN_INVALID", unknown.Code)
	assert.Equal(t, 400, unknown.HTTPStatus())
	assert.Zero(t, f.mailer.count())
}

// Resend must never reveal whether an address has an account here.
func TestResend_UnknownAddressReportsSuccessAndSendsNothing(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)

	err := f.svc.Resend(context.Background(), "nobody@example.com")

	assert.NoError(t, err, "reporting 'no such user' would enumerate accounts")
	assert.Zero(t, f.mailer.count())
}

func TestResend_AlreadyVerifiedReportsSuccessAndSendsNothing(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.users.MarkEmailVerified(ctx, user.ID, f.clock.Now()))

	assert.NoError(t, f.svc.Resend(ctx, "alice@example.com"))
	assert.Zero(t, f.mailer.count(), "a verified address needs no new link")
}

func TestResend_NormalisesTheAddress(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	f.seedUser(t, "alice@example.com")

	require.NoError(t, f.svc.Resend(context.Background(), "  Alice@Example.COM  "))
	assert.Equal(t, 1, f.mailer.count())
	assert.Equal(t, "alice@example.com", f.mailer.last().to)
}

// The token travels in a query string, so it must survive being parsed back out
// of the URL exactly as a browser would parse it.
func TestVerificationEmail_LinkRoundTripsThroughURLParsing(t *testing.T) {
	t.Parallel()
	f := newTestVerificationService(t)
	user := f.seedUser(t, "alice@example.com")
	ctx := context.Background()

	require.NoError(t, f.svc.SendFor(ctx, user))
	body := f.mailer.last().body

	const prefix = testBaseURL + "/verify-email?token="
	start := strings.Index(body, prefix)
	require.GreaterOrEqual(t, start, 0, "link not found in body:\n%s", body)

	rest := body[start:]
	if end := strings.IndexAny(rest, " \n\r\t"); end >= 0 {
		rest = rest[:end]
	}

	parsed, err := url.Parse(rest)
	require.NoError(t, err)

	raw := parsed.Query().Get("token")
	require.NotEmpty(t, raw)

	// The token pulled out of the URL actually verifies. If QueryEscape were
	// missing and the token happened to contain a '+' or '=', this would fail.
	_, err = f.svc.Verify(ctx, raw)
	assert.NoError(t, err)
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   time.Duration
		want string
	}{
		{24 * time.Hour, "1 day"},
		{48 * time.Hour, "2 days"},
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{30 * time.Minute, "30 minutes"},
		{time.Minute, "1 minute"},
		{90 * time.Minute, "90 minutes"}, // not "1h30m0s"
		{90 * time.Second, "1m30s"},      // no whole unit fits; fall back rather than lie
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, humanDuration(tc.in))
		})
	}
}
