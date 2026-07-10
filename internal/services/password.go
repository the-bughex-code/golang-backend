package services

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
)

// bcryptCost is the work factor: bcrypt runs 2^cost rounds.
//
// Each increment DOUBLES the time to hash — and therefore doubles an
// attacker's cost per guess. The number is stored inside the hash itself, so
// raising it later does not invalidate existing passwords; they simply keep
// their old cost until the user next changes their password.
//
// # Choosing the number
//
// The standard advice is "as high as you can tolerate". Tolerable means: a
// login must stay fast enough for a human, and an attacker who floods your
// login endpoint must not be able to exhaust your CPU. Cost 12 lands around
// 200-400ms on modern hardware — imperceptible to a user, brutally expensive
// at scale for an attacker.
//
// Measure on your own production hardware before changing it:
//
//	go test -bench=BenchmarkHashPassword ./internal/services/
//
// # Why bcrypt and not argon2id
//
// Argon2id is the current first choice in the OWASP guidance, because it
// resists GPU and ASIC attacks better by being memory-hard. bcrypt is the
// pragmatic second choice: it is in golang.org/x/crypto, it has no tuning
// parameters to get wrong, and it has survived 25 years of scrutiny.
//
// Migrating later is straightforward — store the algorithm alongside the hash
// and re-hash on next successful login. The password_hash column is TEXT
// precisely so that this needs no migration.
//
// # Why NOT SHA-256, MD5, or any general-purpose hash
//
// They are designed to be fast. A modern GPU computes billions of SHA-256
// hashes per second, so a stolen table of SHA-256 password hashes is
// effectively a table of plaintext passwords. bcrypt is designed to be slow
// and cannot be meaningfully accelerated by a GPU.
const bcryptCost = 12

// maxPasswordBytes is bcrypt's hard limit. Input beyond 72 bytes is ignored by
// the algorithm. Go's implementation returns ErrPasswordTooLong rather than
// silently truncating (some other languages truncate, which makes
// "correcthorsebattery" and "correcthorsebatteryXXXXX" the same password).
//
// Validation rejects this before we get here; the check below is defence in
// depth for any future caller that forgets.
const maxPasswordBytes = 72

// dummyHash is a valid bcrypt hash of a password nobody knows.
//
// It exists to defeat a user-enumeration timing attack. Without it, a login
// attempt for an unknown email returns in microseconds (one indexed SELECT),
// while an attempt for a known email takes ~300ms (the bcrypt comparison).
// An attacker who can time your responses can therefore discover which of a
// million email addresses have accounts, without ever guessing a password.
//
// By comparing against dummyHash when the user does not exist, both paths cost
// the same. See AuthService.Login.
//
// sync.OnceValue computes it on first use, not at package init, so that
// starting the process does not pay 300ms for something a health check will
// never need.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("a-password-that-is-never-correct"), bcryptCost)
	if err != nil {
		// Unreachable: the input is a valid length and the cost is in range.
		panic(fmt.Sprintf("services: generating dummy hash: %v", err))
	}
	return h
})

// HashPassword returns the bcrypt digest of a plaintext password.
//
// bcrypt generates its own random 16-byte salt and embeds it in the output, so
// there is no salt to store, and two users with the same password get different
// hashes. You do not need to — and must not — add your own salt.
func HashPassword(plain string) (string, error) {
	if len(plain) > maxPasswordBytes {
		return "", apperrors.Validation("The submitted data is invalid",
			apperrors.FieldError{Field: "password", Message: "Must be at most 72 characters"})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", apperrors.Internal(fmt.Errorf("services: hashing password: %w", err))
	}
	return string(hash), nil
}

// VerifyPassword reports whether plain matches hash.
//
// It returns nil on a match and an Unauthorized error on a mismatch. The error
// message is deliberately identical to the one returned when the user does not
// exist at all.
func VerifyPassword(hash, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err == nil {
		return nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return errInvalidCredentials()
	}
	// A malformed hash in the database, or a cost the library cannot handle.
	// This is corruption, not a wrong password, and must be investigated.
	return apperrors.Internal(fmt.Errorf("services: comparing password hash: %w", err))
}

// burnPasswordTime performs a bcrypt comparison whose result is discarded.
//
// Called on the "user does not exist" branch of login so that the branch costs
// the same wall-clock time as the "user exists, wrong password" branch.
func burnPasswordTime(plain string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(plain))
}

// errInvalidCredentials is the ONLY error login ever returns.
//
// "Email not found" and "wrong password" must be indistinguishable to a client.
// The moment they differ, your login endpoint becomes a free oracle for
// checking whether an address has an account — useful for phishing, credential
// stuffing, and simply learning who your customers are.
func errInvalidCredentials() error {
	return apperrors.Unauthorized("INVALID_CREDENTIALS", "Invalid email or password")
}
