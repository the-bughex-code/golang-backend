-- +goose Up
-- +goose StatementBegin
CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    -- Convention: resource:action, e.g. 'users:read'.
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Join table: which users hold which roles.
--
-- ON DELETE CASCADE means removing a role removes its assignments. That is
-- safe here because the assignment has no meaning without the role. Never use
-- CASCADE on a table whose rows carry independent value (invoices, audit logs).
CREATE TABLE user_roles (
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id    UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
-- The composite primary key already indexes (user_id, role_id), and a B-tree
-- can be searched by any LEFTMOST prefix of its columns. So "which roles does
-- this user have?" is fast for free.
--
-- "Which users have this role?" is NOT: role_id is not a leftmost prefix.
-- That query needs its own index. This asymmetry catches people constantly.
CREATE INDEX user_roles_role_id_idx ON user_roles (role_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Same reasoning: "which roles grant this permission?" needs its own index.
CREATE INDEX role_permissions_permission_id_idx ON role_permissions (permission_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER roles_set_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER permissions_set_updated_at
    BEFORE UPDATE ON permissions
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
-- +goose StatementEnd
