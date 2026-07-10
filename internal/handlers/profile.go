package handlers

import (
	"net/http"

	"github.com/the-bughex-code/golang-backend/internal/dto/request"
	"github.com/the-bughex-code/golang-backend/internal/dto/response"
	"github.com/the-bughex-code/golang-backend/internal/middlewares"
	"github.com/the-bughex-code/golang-backend/internal/services"
	"github.com/the-bughex-code/golang-backend/internal/validators"
)

// ProfileHandler serves the authenticated caller's own record.
//
// Every route here derives the user id from the VERIFIED TOKEN, never from the
// URL or the body. That is what makes them safe without a permission check:
// there is no id a caller could supply to reach someone else's data.
//
// The moment a handler reads an id from the request and acts on it, it needs an
// authorisation check. Compare UserHandler.Delete.
type ProfileHandler struct {
	users     *services.UserService
	auth      *services.AuthService
	validator *validators.Validator
}

// NewProfileHandler wires the self-service routes to their services.
func NewProfileHandler(users *services.UserService, auth *services.AuthService, v *validators.Validator) *ProfileHandler {
	return &ProfileHandler{users: users, auth: auth, validator: v}
}

// Me returns the caller's own profile, with roles and permissions.
//
// GET /api/v1/profile
//
//	@Summary		Get my profile
//	@Description	Returns the caller's own account, with roles and permissions.
//	@Tags			profile
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	response.Envelope{data=response.User}
//	@Failure		401	{object}	response.Envelope	"TOKEN_MISSING or TOKEN_EXPIRED"
//	@Router			/api/v1/profile [get]
func (h *ProfileHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := middlewares.UserIDFromContext(r.Context())
	if err != nil {
		response.Error(w, r, err)
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Profile retrieved successfully", response.NewUser(user))
}

// Update changes the caller's own name.
//
// PATCH /api/v1/profile
//
//	@Summary		Update my profile
//	@Description	Changes the caller's own name. Email, roles and active status cannot be
//	@Description	changed here; those fields do not exist on the request type.
//	@Tags			profile
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		request.UpdateProfile	true	"New name"
//	@Success		200		{object}	response.Envelope{data=response.User}
//	@Failure		401		{object}	response.Envelope
//	@Failure		422		{object}	response.Envelope	"VALIDATION_FAILED"
//	@Router			/api/v1/profile [patch]
func (h *ProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID, err := middlewares.UserIDFromContext(r.Context())
	if err != nil {
		response.Error(w, r, err)
		return
	}

	var req request.UpdateProfile
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	user, err := h.users.UpdateProfile(r.Context(), userID, req.FirstName, req.LastName)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Profile updated successfully", response.NewUser(user))
}

// ChangePassword updates the caller's password and revokes every other session.
//
// POST /api/v1/profile/change-password
//
//	@Summary		Change my password
//	@Description	Requires the current password. On success, EVERY refresh token for this
//	@Description	user is revoked, including the caller's own, so all devices must sign in again.
//	@Tags			profile
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		request.ChangePassword	true	"Current and new password"
//	@Success		200		{object}	response.Envelope
//	@Failure		401		{object}	response.Envelope	"CURRENT_PASSWORD_INCORRECT"
//	@Failure		422		{object}	response.Envelope	"VALIDATION_FAILED"
//	@Router			/api/v1/profile/change-password [post]
func (h *ProfileHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, err := middlewares.UserIDFromContext(r.Context())
	if err != nil {
		response.Error(w, r, err)
		return
	}

	var req request.ChangePassword
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	if err := h.auth.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		response.Error(w, r, err)
		return
	}

	// The caller's own refresh token was revoked too. Telling them to sign in
	// again is not a courtesy; it is the only thing that will work.
	response.OK(w, r, "Password changed successfully. Please sign in again.", nil)
}
