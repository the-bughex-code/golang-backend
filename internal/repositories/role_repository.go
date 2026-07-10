package repositories

import (
	"context"

	"github.com/google/uuid"

	"github.com/the-bughex-code/backend/internal/database"
	"github.com/the-bughex-code/backend/internal/models"
)

// RoleRepository reads roles and permissions, and manages role assignment.
type RoleRepository struct {
	db *database.DB
}

// NewRoleRepository returns a repository backed by the given pool.
func NewRoleRepository(db *database.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// GetByName looks a role up by its stable name ("admin", "user").
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*models.Role, error) {
	const q = `SELECT id, name, description, created_at, updated_at FROM roles WHERE name = $1`

	var role models.Role
	err := r.db.Querier(ctx).QueryRow(ctx, q, name).
		Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, mapError(err, "role")
	}
	return &role, nil
}

// ListAll returns every role, without permissions.
func (r *RoleRepository) ListAll(ctx context.Context) ([]models.Role, error) {
	const q = `SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name`

	rows, err := r.db.Querier(ctx).Query(ctx, q)
	if err != nil {
		return nil, mapError(err, "role")
	}
	defer rows.Close()

	roles := make([]models.Role, 0, 8)
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, mapError(err, "role")
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err, "role")
	}
	return roles, nil
}

// ForUser returns every role held by the user, each with its permissions
// populated.
//
// # Why two queries and not one
//
// A single JOIN across users → roles → permissions returns one row per
// (role, permission) pair, so a user with 2 roles and 6 permissions each comes
// back as 12 rows with the role columns repeated 6 times. You then de-duplicate
// in Go. That works, but it moves more bytes and the stitching code is fiddly.
//
// Two queries move less data and read more clearly. The second uses
// `= ANY($1)`, which sends the whole role-id list as ONE array parameter, so
// this is two round-trips regardless of how many roles the user has. It is not
// an N+1.
func (r *RoleRepository) ForUser(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	const rolesQ = `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		ORDER BY r.name`

	rows, err := r.db.Querier(ctx).Query(ctx, rolesQ, userID)
	if err != nil {
		return nil, mapError(err, "role")
	}
	defer rows.Close()

	roles := make([]models.Role, 0, 4)
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, mapError(err, "role")
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err, "role")
	}
	if len(roles) == 0 {
		return roles, nil
	}

	// Collect the ids, then fetch every permission for all of them at once.
	roleIDs := make([]uuid.UUID, 0, len(roles))
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	const permsQ = `
		SELECT rp.role_id, p.id, p.name, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = ANY($1)
		ORDER BY p.name`

	permRows, err := r.db.Querier(ctx).Query(ctx, permsQ, roleIDs)
	if err != nil {
		return nil, mapError(err, "permission")
	}
	defer permRows.Close()

	// Index roles by id so each permission can be attached in O(1).
	byID := make(map[uuid.UUID]*models.Role, len(roles))
	for i := range roles {
		byID[roles[i].ID] = &roles[i]
	}

	for permRows.Next() {
		var roleID uuid.UUID
		var p models.Permission
		if err := permRows.Scan(&roleID, &p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, mapError(err, "permission")
		}
		if role, ok := byID[roleID]; ok {
			role.Permissions = append(role.Permissions, p)
		}
	}
	if err := permRows.Err(); err != nil {
		return nil, mapError(err, "permission")
	}

	return roles, nil
}

// AssignToUser grants a role. Re-granting an existing role is a no-op rather
// than an error, which makes the operation idempotent — safe to retry.
func (r *RoleRepository) AssignToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	const q = `
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING`

	_, err := r.db.Querier(ctx).Exec(ctx, q, userID, roleID)
	return mapError(err, "role assignment")
}

// RevokeFromUser removes a role assignment.
func (r *RoleRepository) RevokeFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	const q = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

	tag, err := r.db.Querier(ctx).Exec(ctx, q, userID, roleID)
	if err != nil {
		return mapError(err, "role assignment")
	}
	if tag.RowsAffected() == 0 {
		return mapError(pgxNoRows, "role assignment")
	}
	return nil
}
