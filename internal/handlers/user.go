package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/dto/request"
	"github.com/the-bughex-code/golang-backend/internal/dto/response"
	"github.com/the-bughex-code/golang-backend/internal/middlewares"
	"github.com/the-bughex-code/golang-backend/internal/services"
	"github.com/the-bughex-code/golang-backend/internal/validators"
)

// UserHandler serves administrative operations on OTHER users' records.
// Every route is behind a permission check. See routes.go.
type UserHandler struct {
	users     *services.UserService
	validator *validators.Validator
}

// NewUserHandler wires the administrative user routes to their service.
func NewUserHandler(users *services.UserService, v *validators.Validator) *UserHandler {
	return &UserHandler{users: users, validator: v}
}

// List returns a page of users.
//
// GET /api/v1/users?page=1&perPage=20&search=bob
// Requires: users:read
//
//	@Summary		List users
//	@Description	Offset-paginated. Requires the `users:read` permission.
//	@Tags			users
//	@Produce		json
//	@Security		BearerAuth
//	@Param			page	query		int		false	"Page number, 1-based"	default(1)
//	@Param			perPage	query		int		false	"Rows per page, max 100"	default(20)
//	@Param			search	query		string	false	"Match against email, first or last name"
//	@Success		200		{object}	response.Envelope{data=[]response.User,pagination=response.Pagination}
//	@Failure		403		{object}	response.Envelope	"PERMISSION_DENIED"
//	@Router			/api/v1/users [get]
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	// Query parameters are strings and always optional. Parsing them by hand —
	// rather than through bind, which reads the body — is the one place a
	// handler does data conversion.
	q := r.URL.Query()

	req := request.ListUsers{
		Page:    atoiOrZero(q.Get("page")),
		PerPage: atoiOrZero(q.Get("perPage")),
		Search:  q.Get("search"),
	}
	// Defaults BEFORE validation: a missing page is 1, not an error.
	req.ApplyDefaults()

	if err := h.validator.Struct(&req); err != nil {
		response.Error(w, r, err)
		return
	}

	users, total, err := h.users.List(r.Context(), services.ListParams{
		Page:    req.Page,
		PerPage: req.PerPage,
		Search:  req.Search,
	})
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.Paginated(w, r, "Users retrieved successfully",
		response.NewUsers(users),
		response.NewPagination(req.Page, req.PerPage, total))
}

// GetByID returns one user.
//
// GET /api/v1/users/{id}
// Requires: users:read
//
//	@Summary		Get a user by id
//	@Description	Requires the `users:read` permission.
//	@Tags			users
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"User UUID"
//	@Success		200	{object}	response.Envelope{data=response.User}
//	@Failure		400	{object}	response.Envelope	"INVALID_ID"
//	@Failure		403	{object}	response.Envelope	"PERMISSION_DENIED"
//	@Failure		404	{object}	response.Envelope	"NOT_FOUND"
//	@Router			/api/v1/users/{id} [get]
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		response.Error(w, r, err)
		return
	}

	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "User retrieved successfully", response.NewUser(user))
}

// Delete soft-deletes a user.
//
// DELETE /api/v1/users/{id}
// Requires: users:delete
//
//	@Summary		Delete a user
//	@Description	Soft-deletes the account: the row survives so foreign keys still resolve,
//	@Description	but it is invisible to every read, and the email becomes reusable.
//	@Description	Requires the `users:delete` permission. You cannot delete yourself.
//	@Tags			users
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"User UUID"
//	@Success		200	{object}	response.Envelope
//	@Failure		400	{object}	response.Envelope	"CANNOT_DELETE_SELF or INVALID_ID"
//	@Failure		403	{object}	response.Envelope	"PERMISSION_DENIED"
//	@Failure		404	{object}	response.Envelope	"NOT_FOUND"
//	@Router			/api/v1/users/{id} [delete]
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	targetID, err := pathUUID(r, "id")
	if err != nil {
		response.Error(w, r, err)
		return
	}

	// The actor comes from the token, never from the request. Otherwise a
	// caller could claim to be someone else and defeat the self-deletion rule.
	actorID, err := middlewares.UserIDFromContext(r.Context())
	if err != nil {
		response.Error(w, r, err)
		return
	}

	if err := h.users.Delete(r.Context(), actorID, targetID); err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "User deleted successfully", nil)
}

// AssignRole grants a role to a user.
//
// POST /api/v1/users/{id}/roles
// Requires: roles:assign
//
//	@Summary		Assign a role to a user
//	@Description	Idempotent. Requires the `roles:assign` permission.
//	@Description	The change takes effect for the target user on their next login or token refresh.
//	@Tags			roles
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string				true	"User UUID"
//	@Param			body	body		request.AssignRole	true	"Role name"
//	@Success		200		{object}	response.Envelope
//	@Failure		403		{object}	response.Envelope	"PERMISSION_DENIED"
//	@Failure		404		{object}	response.Envelope	"NOT_FOUND"
//	@Router			/api/v1/users/{id}/roles [post]
func (h *UserHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	userID, err := pathUUID(r, "id")
	if err != nil {
		response.Error(w, r, err)
		return
	}

	var req request.AssignRole
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	if err := h.users.AssignRole(r.Context(), userID, req.RoleName); err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Role assigned successfully", nil)
}

// ListRoles returns every role.
//
// GET /api/v1/roles
// Requires: roles:read
//
//	@Summary		List all roles
//	@Description	Requires the `roles:read` permission.
//	@Tags			roles
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	response.Envelope{data=[]response.Role}
//	@Failure		403	{object}	response.Envelope	"PERMISSION_DENIED"
//	@Router			/api/v1/roles [get]
func (h *UserHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.users.ListRoles(r.Context())
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Roles retrieved successfully", response.NewRoles(roles))
}

// ---------------------------------------------------------------------------
// Small parsing helpers, shared by handlers in this package.
// ---------------------------------------------------------------------------

// pathUUID reads a URL path parameter and parses it as a UUID.
//
// An unparseable id is a 400, not a 404. "abc" is not an id that failed to
// match a row; it is not an id at all. Reporting 404 would mean querying the
// database with garbage first.
func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	raw := chi.URLParam(r, name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, apperrors.BadRequest("INVALID_ID", "The provided id is not a valid UUID").
			WithField(name, "Must be a valid UUID")
	}
	return id, nil
}

// atoiOrZero converts a query parameter to an int, treating anything
// unparseable as absent. The validator, not this function, decides whether
// absent is acceptable.
func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
