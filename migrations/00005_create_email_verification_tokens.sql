-- +goose Up
-- +goose StatementBegin
CREATE TABLE email_verification_tokens (
    id         UUID PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- SHA-256 hex digest of the token, never the token itself. Same reasoning
    -- as refresh_tokens: if this table leaks, the attacker holds hashes, and a
    -- hash cannot be presented to the API.
    --
    -- SHA-256 rather than bcrypt, again for the same reason: the token is 256
    -- bits of cryptographic randomness, so there is no dictionary to attack.
    token_hash TEXT        NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    -- Set the moment the token is redeemed. A verification token must work
    -- exactly once: an email sits in an inbox for years, and a link that stays
    -- live forever is a permanent account-takeover vector for anyone who later
    -- gains access to that mailbox.
    --
    -- This column also serves as "invalidated": issuing a new token marks every
    -- older one used, so only the most recent link works.
    used_at    TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Supports "invalidate every outstanding token for this user", which runs each
-- time a new verification email is sent.
CREATE INDEX email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
-- Supports the cleanup job that deletes expired tokens. Partial, because a row
-- that is already used never needs to be found this way, and excluding those
-- rows keeps the index small.
CREATE INDEX email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at)
    WHERE used_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_verification_tokens;
-- +goose StatementEnd
