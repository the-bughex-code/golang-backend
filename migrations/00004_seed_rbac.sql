-- +goose Up
--
-- Seed the roles and permissions the application's code refers to by name
-- (see internal/models/rbac.go).
--
-- Why seed in a migration rather than in application startup code:
--   * It runs exactly once, tracked in goose's version table.
--   * It is reviewable in a pull request, like any other schema change.
--   * A fresh developer database and production converge to the same state.
--
-- gen_random_uuid() is used here rather than application-generated UUIDv7
-- because these rows have no natural insertion order to preserve, and SQL has
-- no v7 generator built in. Both are valid UUIDs.

-- +goose StatementBegin
INSERT INTO roles (id, name, description) VALUES
    (gen_random_uuid(), 'admin', 'Full administrative access'),
    (gen_random_uuid(), 'user',  'Standard authenticated user')
ON CONFLICT (name) DO NOTHING;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO permissions (id, name, description) VALUES
    (gen_random_uuid(), 'users:read',   'List and view user accounts'),
    (gen_random_uuid(), 'users:create', 'Create user accounts'),
    (gen_random_uuid(), 'users:update', 'Modify user accounts'),
    (gen_random_uuid(), 'users:delete', 'Delete user accounts'),
    (gen_random_uuid(), 'roles:read',   'List and view roles'),
    (gen_random_uuid(), 'roles:assign', 'Assign roles to users')
ON CONFLICT (name) DO NOTHING;
-- +goose StatementEnd

-- +goose StatementBegin
-- The admin role receives every permission that exists. Written as a query
-- rather than a list so that adding a permission above does not require
-- remembering to grant it here.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- The 'user' role receives NO permissions, deliberately.
--
-- Reading your own profile is not permission-gated: it is gated by being
-- authenticated at all. Permissions exist to answer "may this person act on
-- OTHER people's data?". Granting 'users:read' to every user would let any
-- account enumerate the whole user table.

-- +goose Down
-- +goose StatementBegin
DELETE FROM role_permissions
WHERE role_id IN (SELECT id FROM roles WHERE name IN ('admin', 'user'));

DELETE FROM permissions
WHERE name IN ('users:read', 'users:create', 'users:update', 'users:delete',
               'roles:read', 'roles:assign');

DELETE FROM roles WHERE name IN ('admin', 'user');
-- +goose StatementEnd
