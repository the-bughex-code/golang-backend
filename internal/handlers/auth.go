package handlers

import (
	"net/http"

	"github.com/the-bughex-code/backend/internal/dto/request"
	"github.com/the-bughex-code/backend/internal/dto/response"
	"github.com/the-bughex-code/backend/internal/services"
	"github.com/the-bughex-code/backend/internal/validators"
)

// AuthHandler exposes registration, login, refresh and logout.
//
// Its dependencies are injected, not constructed. That means a test can hand it
// a stubbed AuthService, and main.go decides — in one place — what the real one
// talks to.
type AuthHandler struct {
	auth      *services.AuthService
	validator *validators.Validator
}

// NewAuthHandler wires the authentication routes to their service.
func NewAuthHandler(auth *services.AuthService, v *validators.Validator) *AuthHandler {
	return &AuthHandler{auth: auth, validator: v}
}

// Register creates an account and immediately signs the user in.
//
// POST /api/v1/auth/register
//
//	@Summary		Register a new account
//	@Description	Creates a user, grants the default `user` role, and returns the account.
//	@Description	The email is trimmed and lowercased before validation.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		request.Register	true	"Registration payload"
//	@Success		201		{object}	response.Envelope{data=response.User}
//	@Failure		409		{object}	response.Envelope	"EMAIL_TAKEN"
//	@Failure		422		{object}	response.Envelope	"VALIDATION_FAILED"
//	@Failure		429		{object}	response.Envelope	"RATE_LIMITED"
//	@Router			/api/v1/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req request.Register
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	user, err := h.auth.Register(r.Context(), req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	// 201 Created, not 200. The request created a resource that did not exist.
	response.Created(w, r, "Account created successfully", response.NewUser(user))
}

// Login exchanges credentials for an access + refresh token pair.
//
// POST /api/v1/auth/login
//
//	@Summary		Sign in
//	@Description	Returns an access token (short-lived, stateless) and a refresh token
//	@Description	(long-lived, revocable). An unknown email and a wrong password return
//	@Description	the identical error, in the same amount of time.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		request.Login	true	"Credentials"
//	@Success		200		{object}	response.Envelope{data=response.Auth}
//	@Failure		401		{object}	response.Envelope	"INVALID_CREDENTIALS"
//	@Failure		403		{object}	response.Envelope	"ACCOUNT_DISABLED"
//	@Failure		429		{object}	response.Envelope	"RATE_LIMITED"
//	@Router			/api/v1/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req request.Login
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	pair, user, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		// The handler does not distinguish "no such user" from "wrong
		// password". It cannot: the service returns one error for both.
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Signed in successfully", response.Auth{
		TokenType:    "Bearer",
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
		User:         response.NewUser(user),
	})
}

// Refresh rotates a refresh token and issues a new access token.
//
// POST /api/v1/auth/refresh
//
// This route is deliberately UNAUTHENTICATED. The whole point is that the
// client's access token has already expired; requiring a valid one would make
// the endpoint unreachable exactly when it is needed. The refresh token in the
// body is the credential.
//
//	@Summary		Refresh the access token
//	@Description	Consumes the refresh token and issues a NEW one (rotation). Presenting an
//	@Description	already-consumed token revokes every session for that user, because it
//	@Description	means the token was copied.
//	@Description	This endpoint is intentionally unauthenticated: the access token has expired.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		request.Refresh	true	"Refresh token"
//	@Success		200		{object}	response.Envelope{data=response.Auth}
//	@Failure		401		{object}	response.Envelope	"REFRESH_TOKEN_INVALID, REFRESH_TOKEN_EXPIRED or REFRESH_TOKEN_REVOKED"
//	@Router			/api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req request.Refresh
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	pair, user, err := h.auth.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Token refreshed successfully", response.Auth{
		TokenType:    "Bearer",
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
		User:         response.NewUser(user),
	})
}

// Logout revokes one refresh token, ending one session.
//
// POST /api/v1/auth/logout
//
// The access token is NOT invalidated, and cannot be: it is stateless and
// self-verifying. It stops working when it expires, at most JWT_ACCESS_TTL from
// now. The client should discard it immediately. If you need instant global
// logout, you need a token deny-list, which means a database read on every
// request — the exact cost stateless tokens exist to avoid.
//
//	@Summary		Sign out
//	@Description	Revokes one refresh token, ending that session. The access token remains
//	@Description	valid until it expires; the client must discard it.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		request.Logout	true	"Refresh token"
//	@Success		200		{object}	response.Envelope
//	@Router			/api/v1/auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req request.Logout
	if err := bind(w, r, h.validator, &req); err != nil {
		response.Error(w, r, err)
		return
	}

	if err := h.auth.Logout(r.Context(), req.RefreshToken); err != nil {
		response.Error(w, r, err)
		return
	}

	response.OK(w, r, "Signed out successfully", nil)
}
