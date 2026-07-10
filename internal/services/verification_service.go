package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/logger"
	"github.com/the-bughex-code/golang-backend/internal/models"
)

// VerificationService issues and redeems email-verification tokens.
type VerificationService struct {
	users  VerificationUserStore
	tokens VerificationTokenStore
	mailer Mailer
	tx     TxRunner
	clock  Clock

	baseURL string
	ttl     time.Duration
}

// NewVerificationService builds the service. baseURL is the public address of
// the application, used to construct the link in the email.
func NewVerificationService(
	users VerificationUserStore,
	tokens VerificationTokenStore,
	mail Mailer,
	tx TxRunner,
	clock Clock,
	baseURL string,
	ttl time.Duration,
) *VerificationService {
	return &VerificationService{
		users: users, tokens: tokens, mailer: mail, tx: tx, clock: clock,
		baseURL: baseURL, ttl: ttl,
	}
}

// Compile-time proof that VerificationService is a VerificationSender. main.go
// passes it to NewAuthService as one, and this line makes a signature drift a
// build error here rather than a confusing error there.
var _ VerificationSender = (*VerificationService)(nil)

// SendFor issues a fresh verification token for the user and emails it.
//
// Any outstanding tokens are invalidated first, inside the same transaction.
// A user who clicks "resend" three times must not end up with three live links,
// each an independent way into their account.
//
// The email is sent AFTER the transaction commits. Sending inside it would mean
// that a commit failure still delivered a mail containing a token that does not
// exist — and, worse, that a slow mail server holds a database transaction open.
func (s *VerificationService) SendFor(ctx context.Context, user *models.User) error {
	if user.IsEmailVerified() {
		// Nothing to do. Not an error: a caller that re-sends for an already
		// verified account has simply raced with the user.
		return nil
	}

	raw, hash, err := GenerateOpaqueToken()
	if err != nil {
		return err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return apperrors.Internal(fmt.Errorf("services: generating verification token id: %w", err))
	}

	now := s.clock.Now()
	record := &models.EmailVerificationToken{
		ID:        id,
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.ttl),
	}

	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.tokens.InvalidateAllForUser(ctx, user.ID, now); err != nil {
			return err
		}
		return s.tokens.Create(ctx, record)
	})
	if err != nil {
		return err
	}

	subject := "Verify your email address"
	body := s.verificationEmailBody(user, raw)

	if err := s.mailer.Send(ctx, user.Email, subject, body); err != nil {
		// The token exists and is valid; only delivery failed. Surfacing this
		// as an error lets the caller decide. Register logs it and carries on,
		// because losing the account would be a worse outcome than losing the
		// email — the user can always ask for another.
		return apperrors.Wrap(err, apperrors.KindUnavailable, "MAIL_SEND_FAILED",
			"We could not send the verification email. Please try again shortly.")
	}

	logger.FromContext(ctx).Info("verification email sent",
		slog.String("user_id", user.ID.String()))
	return nil
}

// Verify redeems a token and marks the user's address confirmed.
func (s *VerificationService) Verify(ctx context.Context, rawToken string) (*models.User, error) {
	stored, err := s.tokens.GetByHash(ctx, HashOpaqueToken(rawToken))
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			// One error for "never existed", "already used", and "expired".
			// Distinguishing them would tell an attacker guessing tokens which
			// of their guesses had once been real.
			return nil, errInvalidVerificationToken()
		}
		return nil, err
	}

	now := s.clock.Now()
	if !stored.IsUsable(now) {
		return nil, errInvalidVerificationToken()
	}

	user, err := s.users.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, err
	}
	if user.IsEmailVerified() {
		// The token is still live but the address was confirmed some other way
		// — an administrator, a data migration. Consuming the token would be
		// pointless; reporting an error would be a lie.
		//
		// Note this is NOT the "clicked the link twice" case. That token is
		// already used, so IsUsable() above rejected it. A single-use token
		// means single use: a consumed link that still answered "verified" would
		// be a permanent oracle for anyone holding an old email.
		return user, nil
	}

	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		// MarkUsed carries `AND used_at IS NULL`, so if two requests redeem the
		// same token at once, exactly one updates a row and the other gets a
		// not-found. That is the concurrency guard; it lives in SQL, where the
		// database can actually enforce it.
		if err := s.tokens.MarkUsed(ctx, stored.ID, now); err != nil {
			if apperrors.IsKind(err, apperrors.KindNotFound) {
				return errInvalidVerificationToken()
			}
			return err
		}
		return s.users.MarkEmailVerified(ctx, user.ID, now)
	})
	if err != nil {
		return nil, err
	}

	user.EmailVerifiedAt = &now
	logger.FromContext(ctx).Info("email verified", slog.String("user_id", user.ID.String()))
	return user, nil
}

// Resend issues a new verification email for the address, if it needs one.
//
// # It always reports success
//
// An unknown address, an already-verified address, and a genuine resend all
// return nil. Otherwise this endpoint becomes a free oracle: an attacker submits
// a million addresses and learns which have accounts here, and which of those
// have not verified yet.
//
// The rate limiter on /auth/* is what stops it being used as a mail cannon
// against a third party.
func (s *VerificationService) Resend(ctx context.Context, email string) error {
	user, err := s.users.GetByEmail(ctx, NormalizeEmail(email))
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			logger.FromContext(ctx).Info("verification resend requested for unknown address")
			return nil
		}
		return err
	}

	if user.IsEmailVerified() {
		return nil
	}
	return s.SendFor(ctx, user)
}

// verificationEmailBody renders the message.
//
// # The link is a POST target, not a GET link
//
// It points at your frontend, which reads the token from the query string and
// POSTs it to /api/v1/auth/verify-email.
//
// It deliberately does NOT point at a GET endpoint that verifies on visit.
// Corporate mail scanners, link-preview bots and antivirus proxies fetch every
// URL in an incoming email before the human ever sees it. A GET that consumes a
// single-use token is therefore consumed by a robot, and the user clicks a dead
// link. This is a real and very common bug.
//
// The rule: a GET must never change state.
func (s *VerificationService) verificationEmailBody(user *models.User, rawToken string) string {
	link := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, url.QueryEscape(rawToken))

	return fmt.Sprintf(
		"Hi %s,\n\n"+
			"Please confirm your email address by opening this link:\n\n  %s\n\n"+
			"The link expires in %s and can be used once.\n\n"+
			"If you did not create an account, you can ignore this message.\n",
		user.FirstName, link, humanDuration(s.ttl),
	)
}

// humanDuration renders a TTL for a human reader.
//
// time.Duration.String() produces "24h0m0s", which is fine in a log and looks
// like a machine talking in an email. This produces "24 hours".
func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return plural(int(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute")
	default:
		// An unusual TTL such as 90m. Better an odd-looking string than a wrong
		// one; the operator who configured it will recognise their own value.
		return d.String()
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// errInvalidVerificationToken is the only error Verify ever returns for a bad
// token, whatever the reason.
func errInvalidVerificationToken() error {
	return apperrors.BadRequest("VERIFICATION_TOKEN_INVALID",
		"This verification link is invalid or has expired. Request a new one.")
}
