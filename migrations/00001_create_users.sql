-- +goose Up
-- +goose StatementBegin

-- Keeping updated_at correct is the database's job, not the application's.
-- If a DBA runs an UPDATE by hand, or a second service writes to this table,
-- an application-side timestamp is simply wrong. A trigger cannot be bypassed.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE users (
    -- UUID, not BIGSERIAL.
    --
    -- A sequential integer id in a public URL leaks information: /users/1 is
    -- your first customer, and /users/50000 tells a competitor how many you
    -- have. It also makes enumeration trivial. UUIDs cost 16 bytes instead of
    -- 8 and are not human-friendly, which is the price.
    --
    -- The application generates UUIDv7 (time-ordered), NOT the v4 that
    -- gen_random_uuid() would produce. v4 is fully random, so inserts land in
    -- random leaf pages of the primary key's B-tree, fragmenting it. v7 puts a
    -- millisecond timestamp in the high bits, so new rows append to the right
    -- edge, exactly like an integer sequence.
    --
    -- There is deliberately no DEFAULT. Identity is owned by the application,
    -- which needs the id before the INSERT (for logging and domain events).
    id                UUID PRIMARY KEY,

    -- Stored lowercase. Normalisation happens once, in the service layer,
    -- which lets the unique index below be a plain one rather than a
    -- functional index on lower(email).
    email             TEXT        NOT NULL,

    -- A bcrypt digest, always 60 ASCII characters. TEXT rather than
    -- CHAR(60) so that migrating to argon2id later does not require an
    -- ALTER TABLE.
    password_hash     TEXT        NOT NULL,

    first_name        TEXT        NOT NULL,
    last_name         TEXT        NOT NULL,

    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMPTZ,

    -- TIMESTAMPTZ, never TIMESTAMP.
    --
    -- TIMESTAMP stores no timezone, so the same value means different instants
    -- depending on who reads it. TIMESTAMPTZ stores a real instant (UTC
    -- internally) and converts on the way out. There is no performance
    -- difference. Using TIMESTAMP is almost always a bug waiting for a
    -- daylight-saving transition.
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Soft deletion. NULL means alive.
    deleted_at        TIMESTAMPTZ
);
-- +goose StatementEnd

-- +goose StatementBegin
-- A PARTIAL unique index: uniqueness applies only to rows that are not
-- soft-deleted. This means an email frees up again once its account is
-- deleted, which is what users expect. A plain UNIQUE(email) would block
-- re-registration forever.
--
-- The index name matters: the repository maps constraint name
-- 'users_email_unique' to a friendly "email already registered" error.
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS users_set_updated_at ON users;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS set_updated_at();
-- +goose StatementEnd
