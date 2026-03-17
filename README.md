# ReTiCh Auth

Service d'authentification OAuth 2.0 / OIDC auto-hébergé. Fonctionne comme "Se connecter avec Google" mais sur ta propre infrastructure.

## Fonctionnalités

- Inscription / Connexion par email + mot de passe
- Authentification JWT RS256 avec refresh tokens rotatifs
- Vérification email et réinitialisation de mot de passe
- **OAuth 2.0 Authorization Code Flow + PKCE**
- **OIDC Discovery** (`/.well-known/openid-configuration`, JWKS)
- Pages de consentement hébergées (login, register, mot de passe oublié)
- Gestion des clients OAuth via API admin
- Protection brute-force, rate limiting Redis, sessions browser httpOnly

---

## Déploiement

### Local (Docker)

**Prérequis :** Docker + Docker Compose

```bash
cp .env.example .env   # ajuster les variables si besoin
docker compose up -d
curl http://localhost:8081/health   # {"status":"ok"}
```

- Auth service : `http://localhost:8081`
- PostgreSQL : port `5433` (externe)
- Redis : port `6379`

Les migrations sont appliquées automatiquement au démarrage.

### Azure (production)

**Prérequis :** Azure CLI (`az login`)

```bash
# Exporter les secrets
export POSTGRES_PASSWORD="..."
export RSA_PRIVATE_KEY="$(openssl genrsa 2048 | awk 'NF {sub(/\r/,""); printf "%s\\n",$0}')"
export ADMIN_API_KEY="$(openssl rand -hex 32)"
export RESEND_API_KEY="re_..."
export SESSION_SECRET="$(openssl rand -base64 32)"
export APP_URL="https://ton-domaine.com"
export ALLOWED_ORIGINS="https://ton-frontend.com"
export ALLOWED_REDIRECT_URLS="https://ton-frontend.com/callback"
export RESEND_FROM_EMAIL="noreply@tondomaine.com"

./azure-deploy.sh
```

Ressources créées : Azure Container Apps, PostgreSQL Flexible Server, Azure Cache for Redis, Container Registry.

> **Note Azure :** Les extensions PostgreSQL `uuid-ossp` et `pgcrypto` sont activées automatiquement. Le domaine Resend doit être vérifié sur [resend.com/domains](https://resend.com/domains).

**Production URL :** affiché à la fin du script.

**Console admin :** projet `retich-console` (Next.js) — configurer `RETICH_AUTH_URL` et `ADMIN_API_KEY`.

---

## Configuration

Copier `.env.example` → `.env` :

| Variable | Description |
|----------|-------------|
| `PORT` | Port du serveur (défaut `8081`) |
| `DATABASE_URL` | DSN PostgreSQL |
| `REDIS_URL` | URL Redis (`redis://localhost:6379`) |
| `RSA_PRIVATE_KEY` | Clé privée RSA PEM (RS256). Vide en dev → clé éphémère générée |
| `JWT_EXPIRATION` | Durée de vie access token (défaut `15m`) |
| `REFRESH_TOKEN_EXPIRATION` | Durée de vie refresh token (défaut `168h`) |
| `APP_URL` | URL publique du service — utilisé comme `iss` dans les JWT |
| `ADMIN_API_KEY` | Clé secrète pour l'API admin (`X-Admin-Key`) |
| `SESSION_SECRET` | Secret HMAC pour les cookies de session (min 32 chars) |
| `ALLOWED_ORIGINS` | CORS — origines autorisées (séparées par virgule) |
| `ALLOWED_REDIRECT_URLS` | URLs autorisées pour les liens email (vérification, reset) |
| `RESEND_API_KEY` | Clé API Resend (envoi d'emails) |
| `RESEND_FROM_EMAIL` | Expéditeur des emails (domaine doit être vérifié sur Resend) |
| `RESEND_FROM_NAME` | Nom affiché dans les emails |
| `REQUIRE_EMAIL_VERIFICATION` | `true` = connexion bloquée tant que l'email n'est pas vérifié |

---

## API Admin

Toutes les routes admin nécessitent le header `X-Admin-Key`.

### Créer un client OAuth

```bash
curl -X POST http://localhost:8081/api/v1/admin/clients \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: <ADMIN_API_KEY>" \
  -d '{
    "name": "Mon App",
    "redirect_uris": ["http://localhost:3001/api/auth/callback/retich"],
    "scopes": ["openid", "email", "profile"]
  }'
```

> **Important** : sauvegarder le `client_secret` immédiatement — il n'est affiché qu'une seule fois.

### Endpoints admin

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/v1/admin/clients` | Créer un client OAuth |
| `GET` | `/api/v1/admin/clients` | Lister tous les clients |
| `GET` | `/api/v1/admin/clients/{id}` | Détail d'un client |
| `PATCH` | `/api/v1/admin/clients/{id}` | Modifier un client (nom, URIs, scopes, statut) |
| `POST` | `/api/v1/admin/clients/{id}/activate` | Réactiver un client désactivé |
| `DELETE` | `/api/v1/admin/clients/{id}` | Désactiver un client |

---

## Routes exposées

### OAuth 2.0 / OIDC (browser)

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Démarre le flow Authorization Code |
| `POST /oauth/authorize` | Traite l'action du formulaire de consentement |
| `GET /oauth/login` | Page de connexion hébergée |
| `POST /oauth/login` | Traitement de la connexion |
| `GET /oauth/register` | Page d'inscription hébergée |
| `POST /oauth/register` | Traitement de l'inscription |
| `GET /oauth/forgot-password` | Page "mot de passe oublié" hébergée |
| `POST /oauth/forgot-password` | Envoi de l'email de réinitialisation |
| `POST /oauth/token` | Échange code → tokens / refresh |
| `GET /oauth/userinfo` | Infos utilisateur (JWT requis) |
| `GET /oauth/playground` | Interface de test interactive |

### OIDC Discovery

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | Métadonnées OIDC |
| `GET /.well-known/jwks.json` | Clé publique RS256 |

### Auth (email links)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/auth/verify-email` | Validation de l'email |
| `GET /api/v1/auth/reset-password` | Formulaire de nouveau mot de passe |
| `POST /api/v1/auth/reset-password` | Enregistrement du nouveau mot de passe |

### Routes protégées (JWT requis)

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/logout` | Invalider le refresh token actuel |
| `POST /api/v1/auth/logout-all` | Invalider tous les refresh tokens |
| `GET /api/v1/auth/me` | Profil de l'utilisateur connecté |

---

## Intégration OIDC (NextAuth / Auth.js)

```ts
// auth.ts
import NextAuth from "next-auth"

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [{
    id: "retich",
    name: "ReTiCh Auth",
    type: "oidc",
    issuer: process.env.RETICH_AUTH_URL,   // ex: http://localhost:8081
    clientId: process.env.RETICH_CLIENT_ID,
    clientSecret: process.env.RETICH_CLIENT_SECRET,
    checks: ["pkce", "state", "nonce"],
    authorization: { params: { scope: "openid email" } },
  }],
})
```

La `redirect_uri` NextAuth à enregistrer : `{NEXTAUTH_URL}/api/auth/callback/retich`

---

## Base de données

| Migration | Contenu |
|-----------|---------|
| `000001` | Tables `users`, `refresh_tokens`, `verification_tokens`, `sessions` |
| `000002` | Colonne `ip_address` en TEXT |
| `000003` | Table `oauth_clients` |
| `000004` | Table `authorization_codes` |
| `000005` | Table `oauth_consents` |

---

## Sécurité

| Mécanisme | Détail |
|-----------|--------|
| PKCE obligatoire | `code_challenge_method=S256` requis |
| JWT RS256 | Vérifiables via JWKS public, sans secret partagé |
| `iss` claim | Validé par les clients OIDC (valeur = `APP_URL`) |
| Refresh token rotation | Chaque refresh invalide l'ancien token |
| Rate limiting | Redis — par IP et par action |
| Verrouillage de compte | Après N tentatives échouées (configurable) |
| Sessions browser | Cookie httpOnly signé HMAC |
| `client_secret_basic` | Supporté en plus de `client_secret_post` |

---

## Licence

MIT
