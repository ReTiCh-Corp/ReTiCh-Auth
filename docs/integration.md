# ReTiCh Auth — Guide d'intégration

Ce document décrit comment intégrer **ReTiCh Auth** dans une application tierce (frontend, mobile, service backend).

---

## Base URL

```
http://localhost:8081   ← développement
https://auth.yourdomain.com   ← production
```

Toutes les routes API sont préfixées par `/api/v1`.

---

## Format des réponses

Toutes les réponses JSON suivent ce format :

```json
{
  "status": "success" | "error",
  "message": "Description lisible",
  "data": { ... } | null
}
```

En cas d'erreur de validation :

```json
{
  "status": "error",
  "message": "Validation failed",
  "errors": {
    "email": "invalid email format",
    "password": "password must be at least 8 characters"
  }
}
```

---

## Authentification par mot de passe

### 1. Inscription

```
POST /api/v1/auth/register
```

**Body**

```json
{
  "email": "user@example.com",
  "password": "SecurePass1-!",
  "redirect_url": "https://app.example.com/auth/callback"
}
```

> `redirect_url` est optionnel. Après vérification de l'email, l'utilisateur sera redirigé vers cette URL avec `?verified=true`. L'URL doit être dans la whitelist `ALLOWED_REDIRECT_URLS`.

**Réponse 201**

```json
{
  "status": "success",
  "message": "Account created. Please check your email to verify your account."
}
```

**Règles du mot de passe** : min. 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial (`!@#$%^&*-` etc.).

---

### 2. Vérification de l'email

L'utilisateur reçoit un email avec un lien :

```
GET /api/v1/auth/verify-email?token=<TOKEN>[&redirect=https://app.example.com/auth/callback]
```

- **Sans `redirect`** : page de confirmation HTML (pas de redirection automatique).
- **Avec `redirect`** : page HTML avec compte à rebours 3 s, puis redirection vers `<redirect>?verified=true`.

Pour les clients API (Postman, backend) :

```
GET /api/v1/auth/verify-email?token=<TOKEN>
Accept: application/json
```

**Réponse 200**

```json
{
  "status": "success",
  "message": "Email verified successfully. You can now log in."
}
```

---

### 3. Connexion

```
POST /api/v1/auth/login
```

**Body**

```json
{
  "email": "user@example.com",
  "password": "SecurePass1-!",
  "audience": "my-app"
}
```

> `audience` est optionnel. Permet de différencier les tokens par application (utile si plusieurs apps utilisent le même service auth).

**Réponse 200**

```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
    "expires_in": 900
  }
}
```

| Champ | Description |
|-------|-------------|
| `access_token` | JWT valide **15 minutes**. À envoyer dans chaque requête protégée. |
| `refresh_token` | Token opaque valide **7 jours**. À stocker côté client (cookie httpOnly recommandé). |
| `expires_in` | Durée de validité de l'access token en secondes. |

**Erreurs possibles**

| Code HTTP | Cause |
|-----------|-------|
| 401 | Identifiants incorrects |
| 403 | Email non vérifié |
| 423 | Compte temporairement verrouillé (5 tentatives échouées → 15 min) |

---

### 4. Utiliser l'access token

Toutes les routes protégées nécessitent ce header :

```
Authorization: Bearer <access_token>
```

---

### 5. Renouveler le token (refresh)

À faire avant l'expiration de l'access token ou quand vous recevez un 401.

```
POST /api/v1/auth/refresh
```

**Body**

```json
{
  "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
  "audience": "my-app"
}
```

**Réponse 200** — Identique à la connexion (nouveaux access + refresh tokens).

> Le refresh token précédent est **révoqué** (rotation automatique). Stockez le nouveau.

---

### 6. Déconnexion

**Session courante uniquement**

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
```

```json
{ "refresh_token": "550e8400-e29b-41d4-a716-446655440000" }
```

**Toutes les sessions (tous les appareils)**

```
POST /api/v1/auth/logout-all
Authorization: Bearer <access_token>
```

---

## Authentification sans mot de passe (Magic Link)

Flux recommandé pour les apps qui ne veulent pas gérer les mots de passe.

### 1. Demander un magic link

```
POST /api/v1/auth/magic-link
```

```json
{
  "email": "user@example.com",
  "redirect_url": "https://app.example.com/auth/callback"
}
```

Toujours réponse **200** (anti-énumération — ne révèle pas si l'email existe).

```json
{
  "status": "success",
  "message": "If an account with that email exists, a login link has been sent."
}
```

> Le lien expire dans **15 minutes** et est **à usage unique**.

---

### 2. Vérification du magic link

L'utilisateur clique sur le lien dans l'email :

```
GET /api/v1/auth/magic-link/verify?token=<TOKEN>[&redirect=https://app.example.com/auth/callback][&audience=my-app]
```

**Comportement navigateur (sans `Accept: application/json`)** :

- Succès + `redirect` : page HTML 3 s → redirection vers `<redirect>#access_token=...&refresh_token=...`
- Succès sans `redirect` : page HTML de confirmation.
- Erreur : page HTML d'erreur.

> Les tokens sont dans le **fragment d'URL** (`#...`) et ne transitent pas par les logs serveur. Lisez-les avec `window.location.hash` côté client.

**Exemple de lecture des tokens côté frontend**

```javascript
const hash = new URLSearchParams(window.location.hash.slice(1));
const accessToken = hash.get("access_token");
const refreshToken = hash.get("refresh_token");
// Stocker et utiliser les tokens
```

**Pour les clients API :**

```
GET /api/v1/auth/magic-link/verify?token=<TOKEN>
Accept: application/json
```

**Réponse 200**

```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGc...",
    "refresh_token": "...",
    "expires_in": 900
  }
}
```

---

## Réinitialisation du mot de passe

### 1. Demander un reset

```
POST /api/v1/auth/forgot-password
```

```json
{ "email": "user@example.com" }
```

Toujours réponse **200** (anti-énumération). L'utilisateur reçoit un email avec un lien valide **1 heure**.

---

### 2. Soumettre le nouveau mot de passe

Le lien dans l'email redirige vers un formulaire HTML.

Pour les clients API :

```
POST /api/v1/auth/reset-password
```

```json
{
  "token": "<TOKEN_DU_LIEN>",
  "password": "NewSecurePass1-!",
  "password_confirm": "NewSecurePass1-!"
}
```

**Réponse 200**

```json
{
  "status": "success",
  "message": "Password reset successfully. Please log in with your new password."
}
```

> Après un reset, **toutes les sessions actives** sont révoquées. L'utilisateur doit se reconnecter sur tous ses appareils.

---

## Renvoyer l'email de vérification

```
POST /api/v1/auth/resend-verification
```

```json
{
  "email": "user@example.com",
  "redirect_url": "https://app.example.com/auth/callback"
}
```

Toujours réponse **200**.

---

## Profil utilisateur

```
GET /api/v1/auth/me
Authorization: Bearer <access_token>
```

**Réponse 200**

```json
{
  "status": "success",
  "message": "User profile",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "is_verified": true,
    "is_active": true,
    "created_at": "2026-01-01T10:00:00Z",
    "updated_at": "2026-01-15T14:30:00Z"
  }
}
```

---

## Rate limiting

| Endpoint | Limite |
|----------|--------|
| `POST /register` | 5 req / min / IP |
| `POST /login` | 10 req / min / IP |
| `POST /forgot-password` | 3 req / min / IP |
| `POST /resend-verification` | 3 req / min / IP |
| `POST /magic-link` | 3 req / min / IP |

Dépassement → **HTTP 429 Too Many Requests**.

---

## CORS

Le service accepte les requêtes cross-origin des origines configurées dans `ALLOWED_ORIGINS`.

En développement : `http://localhost:3000` par défaut.

---

## Sécurité — Redirect URL

Pour éviter les attaques de phishing, les `redirect_url` doivent être explicitement déclarées dans la variable d'environnement `ALLOWED_REDIRECT_URLS` :

```env
ALLOWED_REDIRECT_URLS=https://app.example.com,https://admin.example.com
```

Toute URL non listée sera ignorée (pas de redirection).

---

## Flux typiques côté frontend

### Inscription + vérification email

```
[User] → POST /register { email, password, redirect_url: "https://app.com/verified" }
[Server] → Envoie email avec lien /verify-email?token=...&redirect=https://app.com/verified
[User] → Clique le lien → Page HTML → Redirection vers https://app.com/verified?verified=true
[App] → Affiche "Email vérifié ✓"
```

### Connexion classique

```
[User] → POST /login { email, password }
[Server] → { access_token, refresh_token, expires_in }
[App] → Stocke les tokens
[App] → GET /me avec Authorization: Bearer <access_token>
// Quand access_token expire :
[App] → POST /refresh { refresh_token }
[Server] → Nouveau { access_token, refresh_token }
```

### Magic link (passwordless)

```
[User] → POST /magic-link { email, redirect_url: "https://app.com/auth" }
[Server] → Envoie email avec lien /magic-link/verify?token=...&redirect=https://app.com/auth
[User] → Clique le lien → Page HTML → Redirection vers https://app.com/auth#access_token=...&refresh_token=...
[App] → Lit window.location.hash → Extrait les tokens → Stocke
```

---

## Healthcheck

```
GET /health   → 200 { "status": "ok" }
GET /ready    → 200 { "status": "ready" } | 503 si DB/Redis indisponible
```
