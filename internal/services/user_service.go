package services

import (
	"context"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/logger"
	"github.com/the-bughex-code/golang-backend/internal/models"
	"github.com/the-bughex-code/golang-backend/internal/repositories"
)

// UserService owns everything about user records that is not authentication.
type UserService struct {
	users UserStore
	roles RoleStore
}

// NewUserService builds the user service from the two stores it needs.
func NewUserService(users UserStore, roles RoleStore) *UserService {
	return &UserService{users: users, roles: roles}
}

// GetByID returns one user with roles and permissions loaded.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user.Roles, err = s.roles.ForUser(ctx, user.ID); err != nil {
		return nil, err
	}
	return user, nil
}

// ListParams describes a page request in the language of the business, not of
// SQL. The service translates it into a repositories.ListFilter, which is what
// keeps LIMIT/OFFSET out of the handler.
type ListParams struct {
	Page    int
	PerPage int
	Search  string
}

// List returns a page of users and the total count.
//
// Roles are NOT loaded, deliberately. Loading them would issue two extra
// queries per user — the classic N+1 — turning a 20-row page into 41 round
// trips. A caller who needs roles for one user calls GetByID.
func (s *UserService) List(ctx context.Context, p ListParams) ([]models.User, int64, error) {
	return s.users.List(ctx, repositories.ListFilter{
		Limit:  p.PerPage,
		Offset: (p.Page - 1) * p.PerPage,
		Search: strings.TrimSpace(p.Search),
	})
}

// UpdateProfile changes the caller's own name fields.
func (s *UserService) UpdateProfile(ctx context.Context, id uuid.UUID, firstName, lastName string) (*models.User, error) {
	user, err := s.users.UpdateProfile(ctx, id, strings.TrimSpace(firstName), strings.TrimSpace(lastName))
	if err != nil {
		return nil, err
	}
	if user.Roles, err = s.roles.ForUser(ctx, user.ID); err != nil {
		return nil, err
	}
	return user, nil
}

// Delete soft-deletes a user.
//
// actorID is the person performing the deletion. Refusing self-deletion is a
// business rule, and it lives here — not in the handler, where a second caller
// (an admin CLI, a batch job) would forget it.
func (s *UserService) Delete(ctx context.Context, actorID, targetID uuid.UUID) error {
	if actorID == targetID {
		return apperrors.BadRequest("CANNOT_DELETE_SELF", "You cannot delete your own account")
	}
	if err := s.users.SoftDelete(ctx, targetID); err != nil {
		return err
	}

	logger.FromContext(ctx).Info("user deleted",
		slog.String("target_user_id", targetID.String()),
		slog.String("actor_user_id", actorID.String()))
	return nil
}

// AssignRole grants a role to a user by role name.
func (s *UserService) AssignRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	// Confirm the user exists before granting. Without this, assigning a role
	// to a nonexistent id would surface as a foreign-key violation — a 409 that
	// says "a referenced record does not exist" when the truthful answer is
	// "that user does not exist" (404).
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		return err
	}

	role, err := s.roles.GetByName(ctx, roleName)
	if err != nil {
		if apperrors.IsKind(err, apperrors.KindNotFound) {
			return apperrors.NotFound("role").WithField("roleName", "No such role")
		}
		return err
	}

	if err := s.roles.AssignToUser(ctx, userID, role.ID); err != nil {
		return err
	}

	logger.FromContext(ctx).Info("role assigned",
		slog.String("user_id", userID.String()),
		slog.String("role", roleName))
	return nil
}

// ListRoles returns every role in the system.
func (s *UserService) ListRoles(ctx context.Context) ([]models.Role, error) {
	return s.roles.ListAll(ctx)
}
