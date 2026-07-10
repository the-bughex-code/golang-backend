package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/the-bughex-code/backend/internal/apperrors"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct-horse-battery-staple")
	require.NoError(t, err)

	assert.NotEqual(t, "correct-horse-battery-staple", hash)
	assert.True(t, strings.HasPrefix(hash, "$2a$12$"),
		"the hash encodes its own cost factor, so raising bcryptCost never invalidates old passwords")

	cost, err := bcrypt.Cost([]byte(hash))
	require.NoError(t, err)
	assert.Equal(t, bcryptCost, cost)
}

// bcrypt generates its own random salt and embeds it in the output. Two users
// with the same password therefore get different hashes, which defeats rainbow
// tables. You must not add your own salt.
func TestHashPassword_SaltsAreRandom(t *testing.T) {
	t.Parallel()

	a, err := HashPassword("same-password")
	require.NoError(t, err)
	b, err := HashPassword("same-password")
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "identical passwords must produce different hashes")

	// Both must still verify.
	assert.NoError(t, VerifyPassword(a, "same-password"))
	assert.NoError(t, VerifyPassword(b, "same-password"))
}

func TestHashPassword_RejectsOver72Bytes(t *testing.T) {
	t.Parallel()

	// bcrypt ignores input past 72 bytes. Some language implementations
	// silently truncate, making "aaa...a"(72) and "aaa...a"(100) the same
	// password. We reject instead.
	_, err := HashPassword(strings.Repeat("a", 73))
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindValidation))

	// Exactly 72 is fine.
	_, err = HashPassword(strings.Repeat("a", 72))
	assert.NoError(t, err)
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("the-real-password")
	require.NoError(t, err)

	assert.NoError(t, VerifyPassword(hash, "the-real-password"))

	err = VerifyPassword(hash, "the-wrong-password")
	require.Error(t, err)
	assert.Equal(t, "INVALID_CREDENTIALS", apperrors.From(err).Code)
	assert.Equal(t, 401, apperrors.From(err).HTTPStatus())
}

// A corrupted hash in the database is not a wrong password. It must surface as
// a 500 that gets investigated, not a 401 that locks a user out silently.
func TestVerifyPassword_CorruptHashIsInternalError(t *testing.T) {
	t.Parallel()

	err := VerifyPassword("this-is-not-a-bcrypt-hash", "anything")
	require.Error(t, err)
	assert.True(t, apperrors.IsKind(err, apperrors.KindInternal))
	assert.Equal(t, 500, apperrors.From(err).HTTPStatus())
}

// BenchmarkHashPassword tells you what bcryptCost actually costs on THIS
// hardware. Run it before changing the constant:
//
//	go test -bench=BenchmarkHashPassword -benchtime=10x ./internal/services/
//
// Aim for 200-400ms per hash. Much faster and an attacker guesses cheaply;
// much slower and your login endpoint becomes a self-inflicted DoS, because
// every attempt — including every wrong one — occupies a CPU core.
func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		if _, err := HashPassword("a-representative-password"); err != nil {
			b.Fatal(err)
		}
	}
}

// The dummy-hash comparison on the unknown-user path must cost the same as a
// real comparison, or login response times leak which emails have accounts.
func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := HashPassword("a-representative-password")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		_ = VerifyPassword(hash, "a-wrong-password")
	}
}

func BenchmarkBurnPasswordTime(b *testing.B) {
	burnPasswordTime("warm-up") // pay the sync.OnceValue cost outside the timer
	b.ResetTimer()
	for b.Loop() {
		burnPasswordTime("a-wrong-password")
	}
}
