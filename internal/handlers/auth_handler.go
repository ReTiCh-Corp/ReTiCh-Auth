package handlers

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/google/uuid"
	authservice "github.com/retich-corp/auth/internal/service/auth"
	tokenservice "github.com/retich-corp/auth/internal/service/token"

	"github.com/retich-corp/auth/internal/middleware"
	"github.com/retich-corp/auth/internal/validator"
	"github.com/retich-corp/auth/pkg/apperrors"
	"github.com/retich-corp/auth/pkg/response"
)

//go:embed templates/verify_email.html
var verifyEmailTpl string

//go:embed templates/reset_password.html
var resetPasswordTpl string

//go:embed templates/magic_link.html
var magicLinkTpl string

type AuthHandler struct {
	authSvc *authservice.Service
	jwtSvc  *tokenservice.JWTService
}

func NewAuthHandler(authSvc *authservice.Service, jwtSvc *tokenservice.JWTService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, jwtSvc: jwtSvc}
}

// POST /api/v1/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email" validate:"required,email"`
		Password    string `json:"password" validate:"required,min=8,max=128"`
		RedirectURL string `json:"redirect_url"` // optional: base URL for the verify-email link
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

	if msg := validator.StrongPassword(body.Password); msg != "" {
		response.ValidationError(w, map[string]string{"password": msg})
		return
	}

	if err := h.authSvc.Register(r.Context(), body.Email, body.Password, body.RedirectURL); err != nil {
		switch {
		case errors.Is(err, apperrors.ErrEmailTaken):
			response.Error(w, http.StatusConflict, "email already in use")
		default:
			response.Error(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	response.Success(w, http.StatusCreated, "Account created. Please check your email to verify your account.", nil)
}

// POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
		Audience string `json:"audience"` // optional, e.g. "app-shop"
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

	result, err := h.authSvc.Login(r.Context(), body.Email, body.Password, body.Audience, r)
	if err != nil {
		switch {
		case errors.Is(err, apperrors.ErrInvalidCredentials):
			response.Error(w, http.StatusUnauthorized, "invalid email or password")
		case errors.Is(err, apperrors.ErrAccountNotVerified):
			response.Error(w, http.StatusForbidden, "please verify your email before logging in")
		case errors.Is(err, apperrors.ErrAccountLocked):
			response.Error(w, http.StatusLocked, "account is temporarily locked due to too many failed attempts")
		case errors.Is(err, apperrors.ErrAccountInactive):
			response.Error(w, http.StatusForbidden, "account is disabled")
		default:
			response.Error(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	response.Success(w, http.StatusOK, "Login successful", result)
}

// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
		Audience     string `json:"audience"` // should match the audience used at login
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

	result, err := h.authSvc.RefreshToken(r.Context(), body.RefreshToken, body.Audience, r)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	response.Success(w, http.StatusOK, "Token refreshed", result)
}

// GET /api/v1/auth/verify-email?token=xxx[&redirect=https://app.com]
// Always serves an HTML page unless the client explicitly requests JSON (Accept: application/json).
// With redirect: page shows a 3-second countdown then redirects to the frontend.
// Without redirect: page shows the result with no auto-redirect.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	redirectParam := r.URL.Query().Get("redirect")

	// API clients (e.g. Postman) that explicitly want JSON
	if r.Header.Get("Accept") == "application/json" {
		if token == "" {
			response.Error(w, http.StatusBadRequest, "missing token parameter")
			return
		}
		if err := h.authSvc.VerifyEmail(r.Context(), token); err != nil {
			response.Error(w, http.StatusBadRequest, "invalid or expired verification token")
			return
		}
		response.Success(w, http.StatusOK, "Email verified successfully. You can now log in.", nil)
		return
	}

	// Everyone else (browser) → HTML page
	data := struct {
		Title       string
		Subtitle    string
		Icon        template.HTML
		IconColor   string
		RedirectURL string // empty = no auto-redirect
	}{}

	var redirectURL string
	if redirectParam != "" {
		redirectURL = h.authSvc.ResolveRedirectURL(redirectParam)
	}

	if token == "" {
		data.Title = "Lien invalide"
		data.Subtitle = "Le lien de vérification est incomplet ou corrompu."
		data.Icon = "&#10007;"
		data.IconColor = "#ef4444"
		if redirectURL != "" {
			data.RedirectURL = redirectURL + "?error=missing_token"
		}
	} else if err := h.authSvc.VerifyEmail(r.Context(), token); err != nil {
		data.Title = "Lien expiré"
		data.Subtitle = "Ce lien de vérification est invalide ou a déjà été utilisé."
		data.Icon = "&#10007;"
		data.IconColor = "#ef4444"
		if redirectURL != "" {
			data.RedirectURL = redirectURL + "?error=invalid_token"
		}
	} else {
		data.Title = "Email vérifié !"
		data.Subtitle = "Votre adresse email a été confirmée avec succès. Vous pouvez maintenant vous connecter."
		data.Icon = "&#10003;"
		data.IconColor = "#22c55e"
		if redirectURL != "" {
			data.RedirectURL = redirectURL + "?verified=true"
		}
	}

	tpl := template.Must(template.New("verify_email").Parse(verifyEmailTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /api/v1/auth/resend-verification
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email" validate:"required,email"`
		RedirectURL string `json:"redirect_url"`
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

	_ = h.authSvc.ResendVerification(r.Context(), body.Email, body.RedirectURL)
	response.Success(w, http.StatusOK, "If your account exists and is unverified, a new verification email has been sent.", nil)
}

// POST /api/v1/auth/forgot-password
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email" validate:"required,email"`
		RedirectURL string `json:"redirect_url"`
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

	_ = h.authSvc.ForgotPassword(r.Context(), body.Email, body.RedirectURL)
	response.Success(w, http.StatusOK, "If an account with that email exists, a password reset link has been sent.", nil)
}

// GET /api/v1/auth/reset-password?token=xxx  — HTML form
func (h *AuthHandler) ResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	data := struct {
		Token   string
		Invalid bool
	}{Token: token}

	if token == "" || h.authSvc.ValidateResetToken(r.Context(), token) != nil {
		data.Invalid = true
	}

	tpl := template.Must(template.New("reset_password").Parse(resetPasswordTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /api/v1/auth/reset-password
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token           string `json:"token" validate:"required"`
		Password        string `json:"password" validate:"required,min=8,max=128"`
		PasswordConfirm string `json:"password_confirm" validate:"required,eqfield=Password"`
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

	if msg := validator.StrongPassword(body.Password); msg != "" {
		response.ValidationError(w, map[string]string{"password": msg})
		return
	}

	if err := h.authSvc.ResetPassword(r.Context(), body.Token, body.Password); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid or expired reset token")
		return
	}

	response.Success(w, http.StatusOK, "Password reset successfully. Please log in with your new password.", nil)
}

// POST /api/v1/auth/magic-link
// Sends a one-time login link to the given email. Always returns 200 (anti-enumeration).
func (h *AuthHandler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email" validate:"required,email"`
		Audience    string `json:"audience"`
		RedirectURL string `json:"redirect_url"`
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

	_ = h.authSvc.RequestMagicLink(r.Context(), body.Email, body.RedirectURL)
	response.Success(w, http.StatusOK, "If an account with that email exists, a login link has been sent.", nil)
}

// GET /api/v1/auth/magic-link/verify?token=xxx[&redirect=xxx][&audience=xxx]
// Validates the magic link and issues tokens.
// Browser → HTML page (with optional redirect). API (Accept: application/json) → JSON.
func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	rawToken := r.URL.Query().Get("token")
	redirectParam := r.URL.Query().Get("redirect")
	audience := r.URL.Query().Get("audience")

	result, err := h.authSvc.VerifyMagicLink(r.Context(), rawToken, audience, r)

	// API clients → JSON
	if r.Header.Get("Accept") == "application/json" {
		if err != nil {
			response.Error(w, http.StatusBadRequest, "invalid or expired magic link")
			return
		}
		response.Success(w, http.StatusOK, "Login successful", result)
		return
	}

	// Browser → HTML page
	data := struct {
		Title       string
		Subtitle    string
		Icon        template.HTML
		IconColor   string
		RedirectURL string
	}{}

	if err != nil {
		data.Title = "Lien invalide ou expiré"
		data.Subtitle = "Ce lien de connexion est invalide, a déjà été utilisé ou a expiré. Veuillez faire une nouvelle demande."
		data.Icon = "&#10007;"
		data.IconColor = "#ef4444"
	} else {
		data.Title = "Connexion réussie !"
		data.Subtitle = "Vous avez été connecté avec succès."
		data.Icon = "&#10003;"
		data.IconColor = "#22c55e"

		// Build redirect URL with tokens embedded as fragment (not in server logs)
		if redirectParam != "" {
			safe := h.authSvc.ResolveRedirectURL(redirectParam)
			data.RedirectURL = safe + "#access_token=" + result.AccessToken + "&refresh_token=" + result.RefreshToken
		}
	}

	tpl := template.Must(template.New("magic_link").Parse(magicLinkTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /api/v1/auth/logout  [protected]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
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

	jti := middleware.JTIFromContext(r.Context())
	jwtTTL := h.remainingJWTTTL(r)

	_ = h.authSvc.Logout(r.Context(), body.RefreshToken, jti, jwtTTL)
	response.Success(w, http.StatusOK, "Logged out successfully", nil)
}

// POST /api/v1/auth/logout-all  [protected]
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userIDStr := middleware.UserIDFromContext(r.Context())
	jti := middleware.JTIFromContext(r.Context())

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	jwtTTL := h.remainingJWTTTL(r)

	_ = h.authSvc.LogoutAll(r.Context(), userID, jti, jwtTTL)
	response.Success(w, http.StatusOK, "All sessions terminated", nil)
}

func (h *AuthHandler) remainingJWTTTL(r *http.Request) time.Duration {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 {
		return 0
	}
	claims, err := h.jwtSvc.ParseAccessToken(authHeader[7:])
	if err != nil {
		return 0
	}
	return tokenservice.ExpirationFromClaims(claims)
}
