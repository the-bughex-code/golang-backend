// Package mailer sends outbound email.
//
// # Why this package exists at all, with only one implementation
//
// It exists so that `services` never imports an SMTP client. The service layer
// declares a one-method interface it needs (see services.Mailer); this package
// provides something that satisfies it. Swapping the log implementation for
// Postmark, SES, or net/smtp is then a one-line change in cmd/api/main.go, and
// nothing above it moves.
//
// That is the same seam as the repository: a boundary drawn where an external
// system begins.
//
// # Why development sends nothing
//
// LogMailer writes the message to your structured log instead of sending it.
// Development therefore needs no SMTP server, no API key, no mail account, and
// no risk of emailing a real person while you test. The verification link is
// right there in your terminal, ready to copy.
//
// The alternative — pointing development at a real mail provider — means your
// first bad loop mails a customer a thousand times.
package mailer

import (
	"context"
	"log/slog"
)

// LogMailer writes each message to the log rather than sending it.
type LogMailer struct {
	log  *slog.Logger
	from string
}

// NewLogMailer builds the development mailer.
func NewLogMailer(log *slog.Logger, from string) *LogMailer {
	return &LogMailer{log: log, from: from}
}

// Send records the message. It never fails, which is deliberate: a developer
// running `make dev` must not have registration break because a mail server is
// unreachable.
//
// The body is logged at INFO so it appears with the default LOG_LEVEL. A
// verification link nobody can find is a feature nobody can test.
func (m *LogMailer) Send(ctx context.Context, to, subject, textBody string) error {
	// slog's redaction rules replace any attribute whose key contains "token".
	// The body legitimately contains one, and in development that is exactly
	// what we want to read, so the attribute is named "body".
	m.log.InfoContext(ctx, "email (not actually sent — LogMailer)",
		slog.String("from", m.from),
		slog.String("to", to),
		slog.String("subject", subject),
		slog.String("body", textBody),
	)
	return nil
}
