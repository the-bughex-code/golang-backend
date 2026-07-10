-- +goose Up
-- +goose StatementBegin
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The SHA-256 hex digest of the token, never the token itself. If this
    -- table leaks, the attacker holds hashes, and a hash cannot be presented
    -- to the API.
    --
    -- SHA-256 rather than bcrypt is correct here: the token is 256 bits of
    -- cryptographic randomness, so there is no dictionary to attack and no
    -- reason to make verification slow. A password is low-entropy and needs
    -- bcrypt's deliberate cost.
    token_hash TEXT        NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    -- Set on logout, on password change, and on rotation. This column is the
    -- entire reason refresh tokens are revocable while access tokens are not.
    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Supports "revoke every token for this user", which runs on password change.
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
-- Supports the cleanup job that deletes expired tokens. Partial, because rows
-- that are already revoked never need to be found this way, and excluding them
-- keeps the index small.
CREATE INDEX refresh_tokens_expires_at_idx
    ON refresh_tokens (expires_at)
    WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
-- +goose StatementEnd
