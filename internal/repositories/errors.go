package repositories

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
)

// PostgreSQL SQLSTATE codes we care about.
//
// These are five-character strings defined by the SQL standard and documented
// at postgresql.org/docs/current/errcodes-appendix.html. They are stable across
// versions and across locales, which is exactly why we branch on them instead
// of on the error message — the message is translated, the code is not.
const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
	sqlstateNotNullViolation    = "23502"
	sqlstateCheckViolation      = "23514"
)

// Named constraints. Mapping a constraint name to a message is what turns a
// generic "duplicate key" into "email already registered". If you add a unique
// index, add its name here.
const (
	constraintUsersEmail = "users_email_unique"
)

// pgxNoRows lets an UPDATE or DELETE that matched zero rows reuse the exact
// same not-found path as a SELECT that returned zero rows. Postgres treats
// "updated nothing" as success; the application does not.
var pgxNoRows = pgx.ErrNoRows

// mapError converts a storage error into an application error.
//
// This function is the seam between "Postgres" and "the rest of the program".
// Above it, nobody knows what pgx is. Below it, nobody knows what HTTP is.
//
// resource is the singular noun used in a not-found message, e.g. "user".
func mapError(err error, resource string) error {
	if err == nil {
		return nil
	}

	// pgx returns ErrNoRows from QueryRow().Scan() when the query matched
	// nothing. It is not an exceptional condition — it is the normal answer to
	// "is there a user with this id?" — so it becomes a clean 404 rather than
	// an internal error.
	if errors.Is(err, pgx.ErrNoRows) {
		return apperrors.NotFound(resource)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case sqlstateUniqueViolation:
			return uniqueViolation(pgErr, resource)

		case sqlstateForeignKeyViolation:
			// The client referenced something that does not exist, e.g.
			// assigning a role id that was deleted. That is a 409, not a 500:
			// the request is well-formed but conflicts with current state.
			return apperrors.Wrap(err, apperrors.KindConflict, "REFERENCE_NOT_FOUND",
				"A referenced record does not exist")

		case sqlstateNotNullViolation, sqlstateCheckViolation:
			// A NOT NULL or CHECK constraint fired. Validation should have
			// caught this before the query ran, so reaching here means our
			// validation and our schema disagree. That is our bug — hence
			// Internal, which logs loudly — but we still answer 400 rather
			// than 500 because the client did send something we rejected.
			return apperrors.Wrap(err, apperrors.KindBadRequest, "CONSTRAINT_VIOLATION",
				"The submitted data violates a database constraint")
		}
	}

	// Anything else — a dropped connection, a syntax error in our own SQL, a
	// deadlock — is our problem. Internal() keeps the real cause for the logs
	// and tells the client nothing.
	return apperrors.Internal(err)
}

// uniqueViolation turns a constraint name into a message a user can act on.
func uniqueViolation(pgErr *pgconn.PgError, resource string) error {
	switch pgErr.ConstraintName {
	case constraintUsersEmail:
		// Note the deliberate wording. "Email already registered" is a user
		// enumeration disclosure: it confirms to an attacker that an address
		// has an account here.
		//
		// We accept that disclosure at REGISTRATION, because the alternative
		// (silently pretending to succeed, then emailing the real owner) is a
		// large amount of machinery, and because a signup form that cannot say
		// "you already have an account" is genuinely bad for real users.
		//
		// We do NOT accept it at LOGIN. See auth_service.go, where a missing
		// user and a wrong password produce the identical response.
		return apperrors.Wrap(pgErr, apperrors.KindConflict, "EMAIL_TAKEN",
			"An account with this email already exists").
			WithField("email", "This email is already registered")
	default:
		return apperrors.Wrap(pgErr, apperrors.KindConflict, "DUPLICATE_RECORD",
			"This "+resource+" already exists")
	}
}
