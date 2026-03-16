package handlers

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/retich-corp/auth/internal/middleware"
	"github.com/retich-corp/auth/internal/repository"
	authservice "github.com/retich-corp/auth/internal/service/auth"
	oauthservice "github.com/retich-corp/auth/internal/service/oauth"
	sessionsvc "github.com/retich-corp/auth/internal/service/session"
	"github.com/retich-corp/auth/pkg/response"
)

//go:embed templates/consent.html
var consentTpl string

//go:embed templates/oauth_login.html
var oauthLoginTpl string

//go:embed templates/oauth_register.html
var oauthRegisterTpl string

//go:embed templates/oauth_forgot_password.html
var oauthForgotPasswordTpl string

//go:embed templates/playground.html
var playgroundTpl string

type OAuthHandler struct {
	oauthSvc   *oauthservice.Service
	authSvc    *authservice.Service
	userRepo   *repository.UserRepository
	sessionSvc *sessionsvc.Service
	appURL     string
}

func NewOAuthHandler(oauthSvc *oauthservice.Service, authSvc *authservice.Service, userRepo *repository.UserRepository, sessionSvc *sessionsvc.Service, appURL string) *OAuthHandler {
	return &OAuthHandler{
		oauthSvc:   oauthSvc,
		authSvc:    authSvc,
		userRepo:   userRepo,
		sessionSvc: sessionSvc,
		appURL:     appURL,
	}
}

// GET /oauth/authorize
// Validates the OAuth request. If the user is not logged in, redirects to the login page.
// If logged in and consent already exists, auto-approves. Otherwise shows the consent page.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	req := oauthservice.AuthRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
	}

	// Parse and validate scopes
	scopeParam := q.Get("scope")
	if scopeParam != "" {
		req.Scopes = strings.Fields(scopeParam)
	}

	if q.Get("response_type") != "code" {
		h.oauthError(w, r, req.RedirectURI, req.State, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	client, err := h.oauthSvc.ValidateAuthRequest(r.Context(), req)
	if err != nil {
		// Before redirect_uri is validated, we cannot redirect — show a plain error
		http.Error(w, "invalid_request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check browser session
	userIDStr, sessionErr := h.sessionSvc.GetUserID(r)
	if sessionErr != nil {
		// Not logged in — save pending auth params and redirect to login
		pendingKey, err := h.oauthSvc.StorePendingAuth(r.Context(), req)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		loginURL := "/oauth/login?return_to=" + pendingKey
		if client.Name != "" {
			loginURL += "&app=" + client.Name
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.sessionSvc.DestroySession(w)
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return
	}

	// Store pending auth to generate consent data
	pendingKey, err := h.oauthSvc.StorePendingAuth(r.Context(), req)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// If user has already consented to all scopes, auto-approve
	if h.oauthSvc.HasExistingConsent(r.Context(), userID, req.ClientID, req.Scopes) {
		_, redirectURI, err := h.oauthSvc.Approve(r.Context(), userID, pendingKey, "", req.Scopes)
		if err == nil {
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
	}

	// Show consent page
	data, err := h.oauthSvc.GetConsentData(r.Context(), pendingKey)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	tpl := template.Must(template.New("consent").Parse(consentTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /oauth/authorize
// Handles user's approve or deny action from the consent page.
func (h *OAuthHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	pendingKey := r.FormValue("pending_key")
	csrfToken := r.FormValue("csrf_token")
	action := r.FormValue("action")

	userIDStr, err := h.sessionSvc.GetUserID(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login?return_to="+pendingKey, http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	if action == "deny" {
		redirectURI, err := h.oauthSvc.Deny(r.Context(), pendingKey)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	// Collect approved scopes from form
	scopes := r.Form["scope"]

	_, redirectURI, err := h.oauthSvc.Approve(r.Context(), userID, pendingKey, csrfToken, scopes)
	if err != nil {
		http.Error(w, "server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// GET /oauth/login — Show the OAuth login form
func (h *OAuthHandler) LoginForm(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	appName := r.URL.Query().Get("app")

	data := struct {
		ReturnTo string
		AppName  string
		Error    string
		Email    string
	}{ReturnTo: returnTo, AppName: appName}

	tpl := template.Must(template.New("oauth_login").Parse(oauthLoginTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /oauth/login — Process login, then redirect back to the consent page
func (h *OAuthHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	returnTo := r.FormValue("return_to")
	appName := r.FormValue("app")

	result, err := h.authSvc.Login(r.Context(), email, password, "", r)
	if err != nil {
		data := struct {
			ReturnTo string
			AppName  string
			Error    string
			Email    string
		}{ReturnTo: returnTo, AppName: appName, Error: "Email ou mot de passe incorrect.", Email: email}

		tpl := template.Must(template.New("oauth_login").Parse(oauthLoginTpl))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = tpl.Execute(w, data)
		return
	}

	// Create browser session cookie
	h.sessionSvc.CreateSession(w, result.UserID)

	// Redirect back to the consent flow
	if returnTo != "" {
		// Load pending auth and go back to authorize endpoint
		req, err := h.oauthSvc.LoadPendingAuth(r.Context(), returnTo)
		if err == nil {
			_ = req // pending auth exists, redirect to authorize which will now find the session
			authorizeURL := "/oauth/authorize?" +
				"client_id=" + req.ClientID +
				"&redirect_uri=" + req.RedirectURI +
				"&response_type=code" +
				"&scope=" + strings.Join(req.Scopes, "+") +
				"&state=" + req.State +
				"&code_challenge=" + req.CodeChallenge +
				"&code_challenge_method=" + req.CodeChallengeMethod
			if req.Nonce != "" {
				authorizeURL += "&nonce=" + req.Nonce
			}
			http.Redirect(w, r, authorizeURL, http.StatusFound)
			return
		}
	}

	// Fallback: redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// GET /oauth/register — Show the OAuth registration form
func (h *OAuthHandler) RegisterForm(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	appName := r.URL.Query().Get("app")

	data := struct {
		ReturnTo string
		AppName  string
		Error    string
		Email    string
		Success  bool
	}{ReturnTo: returnTo, AppName: appName}

	tpl := template.Must(template.New("oauth_register").Parse(oauthRegisterTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /oauth/register — Process registration, then show success or error
func (h *OAuthHandler) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	returnTo := r.FormValue("return_to")
	appName := r.FormValue("app")

	renderErr := func(errMsg string) {
		data := struct {
			ReturnTo string
			AppName  string
			Error    string
			Email    string
			Success  bool
		}{ReturnTo: returnTo, AppName: appName, Error: errMsg, Email: email}
		tpl := template.Must(template.New("oauth_register").Parse(oauthRegisterTpl))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = tpl.Execute(w, data)
	}

	if password != confirm {
		renderErr("Les mots de passe ne correspondent pas.")
		return
	}

	redirectURL := h.appURL + "/oauth/login?return_to=" + returnTo
	if err := h.authSvc.Register(r.Context(), email, password, redirectURL); err != nil {
		renderErr("Erreur lors de la création du compte : " + err.Error())
		return
	}

	data := struct {
		ReturnTo string
		AppName  string
		Error    string
		Email    string
		Success  bool
	}{ReturnTo: returnTo, AppName: appName, Email: email, Success: true}

	tpl := template.Must(template.New("oauth_register").Parse(oauthRegisterTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// GET /oauth/forgot-password — Show the forgot password form
func (h *OAuthHandler) ForgotPasswordForm(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")

	data := struct {
		ReturnTo string
		Error    string
		Email    string
		Success  bool
	}{ReturnTo: returnTo}

	tpl := template.Must(template.New("oauth_forgot_password").Parse(oauthForgotPasswordTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /oauth/forgot-password — Send the password reset email
func (h *OAuthHandler) ForgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	returnTo := r.FormValue("return_to")

	// Always show success to avoid email enumeration
	resetURL := h.appURL + "/api/v1/auth/reset-password"
	_ = h.authSvc.ForgotPassword(r.Context(), email, resetURL)

	data := struct {
		ReturnTo string
		Error    string
		Email    string
		Success  bool
	}{ReturnTo: returnTo, Email: email, Success: true}

	tpl := template.Must(template.New("oauth_forgot_password").Parse(oauthForgotPasswordTpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}

// POST /oauth/token
// Supports grant_type=authorization_code and grant_type=refresh_token.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "could not parse form")
		return
	}

	grantType := r.FormValue("grant_type")

	// Support both client_secret_post (body) and client_secret_basic (Authorization header)
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID = id
			clientSecret = secret
		}
	}

	switch grantType {
	case "authorization_code":
		req := oauthservice.TokenRequest{
			GrantType:    grantType,
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			ClientID:     clientID,
			ClientSecret: clientSecret,
			CodeVerifier: r.FormValue("code_verifier"),
		}

		resp, err := h.oauthSvc.ExchangeCode(r.Context(), req)
		if err != nil {
			tokenError(w, "invalid_grant", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)

	case "refresh_token":
		rawToken := r.FormValue("refresh_token")

		resp, err := h.oauthSvc.RefreshOAuthToken(r.Context(), rawToken, clientID, clientSecret)
		if err != nil {
			tokenError(w, "invalid_grant", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)

	default:
		tokenError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

// GET /oauth/userinfo — Returns user info for the authenticated access token.
func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userIDStr := middleware.UserIDFromContext(r.Context())
	if userIDStr == "" {
		response.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":            user.ID.String(),
		"email":          user.Email,
		"email_verified": user.IsVerified,
	})
}

// GET /.well-known/openid-configuration
func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	base := h.appURL
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"claims_supported":                      []string{"sub", "email", "email_verified"},
		"code_challenge_methods_supported":       []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
}

// GET /oauth/playground — Interactive test UI for the OAuth flow.
func (h *OAuthHandler) Playground(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(playgroundTpl))
}

// --- helpers ---

func (h *OAuthHandler) oauthError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	if redirectURI == "" {
		http.Error(w, errCode+": "+desc, http.StatusBadRequest)
		return
	}
	u := redirectURI + "?error=" + errCode
	if state != "" {
		u += "&state=" + state
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func tokenError(w http.ResponseWriter, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
