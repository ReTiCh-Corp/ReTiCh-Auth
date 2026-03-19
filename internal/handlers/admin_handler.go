package handlers

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/retich-corp/auth/internal/repository"
	oauthservice "github.com/retich-corp/auth/internal/service/oauth"
	"github.com/retich-corp/auth/internal/validator"
	"github.com/retich-corp/auth/pkg/apperrors"
	"github.com/retich-corp/auth/pkg/response"
)

type AdminHandler struct {
	oauthSvc   *oauthservice.Service
	adminAPIKey string
}

func NewAdminHandler(oauthSvc *oauthservice.Service, adminAPIKey string) *AdminHandler {
	return &AdminHandler{oauthSvc: oauthSvc, adminAPIKey: adminAPIKey}
}

// POST /api/v1/admin/clients
// Registers a new OAuth client application. Requires X-Admin-Key header.
func (h *AdminHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	var body struct {
		Name         string   `json:"name"         validate:"required,min=2,max=100"`
		LogoURL      string   `json:"logo_url"`
		RedirectURIs []string `json:"redirect_uris" validate:"required,min=1,dive,uri"`
		Scopes       []string `json:"scopes"`
	}

	errs, err := validator.Decode(r.Body, &body)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if errs != nil {
		response.ValidationError(w, errs)
		return
	}

	if len(body.Scopes) == 0 {
		body.Scopes = []string{"openid", "email", "profile"}
	}

	client, rawSecret, err := h.oauthSvc.RegisterClient(r.Context(), body.Name, body.LogoURL, body.RedirectURIs, body.Scopes)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "failed to create client")
		return
	}

	response.Success(w, http.StatusCreated, "OAuth client created. Save the client_secret — it will not be shown again.", map[string]any{
		"client_id":     client.ClientID,
		"client_secret": rawSecret,
		"name":          client.Name,
		"redirect_uris": client.RedirectURIs,
		"scopes":        client.AllowedScopes,
	})
}

// GET /api/v1/admin/clients
func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	clients, err := h.oauthSvc.ListClients(r.Context())
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "failed to list clients")
		return
	}

	response.Success(w, http.StatusOK, "clients", clients)
}

// GET /api/v1/admin/clients/{id}
func (h *AdminHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	id := mux.Vars(r)["id"]
	client, err := h.oauthSvc.GetClient(r.Context(), id)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			response.Error(w, http.StatusNotFound, "client not found")
			return
		}
		response.Error(w, http.StatusInternalServerError, "failed to get client")
		return
	}

	response.Success(w, http.StatusOK, "client", client)
}

// PATCH /api/v1/admin/clients/{id}
func (h *AdminHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	id := mux.Vars(r)["id"]

	var body struct {
		Name         string   `json:"name"          validate:"required,min=2,max=100"`
		LogoURL      string   `json:"logo_url"`
		RedirectURIs []string `json:"redirect_uris" validate:"required,min=1,dive,uri"`
		Scopes       []string `json:"scopes"`
		IsActive     bool     `json:"is_active"`
	}

	errs, err := validator.Decode(r.Body, &body)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if errs != nil {
		response.ValidationError(w, errs)
		return
	}

	if len(body.Scopes) == 0 {
		body.Scopes = []string{"openid", "email", "profile"}
	}

	client, err := h.oauthSvc.UpdateClient(r.Context(), id, body.Name, body.LogoURL, body.RedirectURIs, body.Scopes, body.IsActive)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			response.Error(w, http.StatusNotFound, "client not found")
			return
		}
		response.Error(w, http.StatusInternalServerError, "failed to update client")
		return
	}

	response.Success(w, http.StatusOK, "client updated", client)
}

// POST /api/v1/admin/clients/{id}/activate
func (h *AdminHandler) ActivateClient(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	id := mux.Vars(r)["id"]
	if err := h.oauthSvc.ActivateClient(r.Context(), id); err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			response.Error(w, http.StatusNotFound, "client not found")
			return
		}
		response.Error(w, http.StatusInternalServerError, "failed to activate client")
		return
	}

	response.Success(w, http.StatusOK, "client activated", nil)
}

// GET /api/v1/admin/clients/{id}/users
func (h *AdminHandler) ListClientUsers(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	id := mux.Vars(r)["id"]
	users, err := h.oauthSvc.ListClientUsers(r.Context(), id)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			response.Error(w, http.StatusNotFound, "client not found")
			return
		}
		response.Error(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	if users == nil {
		users = make([]*repository.ClientUser, 0)
	}

	response.Success(w, http.StatusOK, "users", users)
}

// DELETE /api/v1/admin/clients/{id}
func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Key") != h.adminAPIKey || h.adminAPIKey == "" {
		response.Error(w, http.StatusUnauthorized, "invalid or missing X-Admin-Key")
		return
	}

	id := mux.Vars(r)["id"]
	if err := h.oauthSvc.DeactivateClient(r.Context(), id); err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			response.Error(w, http.StatusNotFound, "client not found")
			return
		}
		response.Error(w, http.StatusInternalServerError, "failed to delete client")
		return
	}

	response.Success(w, http.StatusOK, "client deactivated", nil)
}
