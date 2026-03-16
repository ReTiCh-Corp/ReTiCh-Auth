package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/retich-corp/auth/internal/middleware"
	"github.com/retich-corp/auth/internal/repository"
	"github.com/retich-corp/auth/pkg/response"
)

type ProfileHandler struct {
	userRepo *repository.UserRepository
}

func NewProfileHandler(userRepo *repository.UserRepository) *ProfileHandler {
	return &ProfileHandler{userRepo: userRepo}
}

// GET /api/v1/auth/me  [protected]
func (h *ProfileHandler) Me(w http.ResponseWriter, r *http.Request) {
	userIDStr := middleware.UserIDFromContext(r.Context())

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userRepo.FindByID(r.Context(), userID)
	if err != nil {
		response.Error(w, http.StatusNotFound, "user not found")
		return
	}

	response.Success(w, http.StatusOK, "User profile", user)
}
