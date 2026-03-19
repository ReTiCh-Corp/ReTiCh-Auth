# ReTiCh Auth

Service d'authentification OAuth 2.0 / OIDC auto-hébergé. Fonctionne comme "Se connecter avec Google" mais sur ta propre infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Tes applications                      │
│          (NextAuth, Auth.js, SDK custom, curl…)              │
└────────────────────────────┬────────────────────────────────┘
                             │  OAuth 2.0 / OIDC
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     retich-auth  :8081                       │
│  Authorization Code + PKCE  ·  JWT RS256  ·  OIDC Discovery │
│  Pages hébergées : login, register, consent                  │
└──────────┬──────────────────────────────────────────────────┘
           │
           ▼
     PostgreSQL                       In-memory cache
   (users, tokens,                   (rate limiting,
    oauth clients)                   sessions, CSRF)

┌─────────────────────────────────────────────────────────────┐
│                   retich-console  :3000                      │
│         Interface admin pour gérer les clients OAuth         │
└─────────────────────────────────────────────────────────────┘
```

## Fonctionnalités

- Inscription / Connexion par email + mot de passe
- Authentification JWT RS256 avec refresh tokens rotatifs
- Vérification email et réinitialisation de mot de passe
- **OAuth 2.0 Authorization Code Flow + PKCE**
- **OIDC Discovery** (`/.well-known/openid-configuration`, JWKS)
- Pages de consentement hébergées (login, register, mot de passe oublié)
- Gestion des clients OAuth via API admin et console web
- Protection brute-force, rate limiting in-memory, sessions browser httpOnly

---

## Déploiement

### Local (Docker)

**Prérequis :** Docker + Docker Compose

```bash
cp .env.example .env   # ajuster les variables si besoin
docker compose up -d
curl http://localhost:8081/health   # {"status":"ok"}
```

| Service | URL |
|---------|-----|
| Auth service | `http://localhost:8081` |
| PostgreSQL | port `5433` |

Les migrations sont appliquées automatiquement au démarrage.

### Azure (production)

**Prérequis :** [Azure CLI](https://learn.microsoft.com/fr-fr/cli/azure/install-azure-cli) + `az login`

**1. Déployer le service d'authentification**

```bash
cp .env.prod.example .env.prod   # remplir les valeurs
./azure-deploy.sh                # charge .env.prod automatiquement
```

Le script crée et configure automatiquement :
- Azure Container Registry (build + push de l'image)
- Azure PostgreSQL Flexible Server (avec extensions `uuid-ossp` et `pgcrypto`)
- Azure Container Apps Environment + App

> **Note :** Le domaine Resend doit être vérifié sur [resend.com/domains](https://resend.com/domains) avant que les emails fonctionnent.

**2. Déployer la console admin**

La console (`retich-console`) est un projet Next.js séparé. Pour la déployer sur le même ACR / Container Apps Environment :

```bash
cd retich-console

# Build et push vers le même ACR
TAG="$(date +%Y%m%d-%H%M%S)"
az acr build --registry retichauth \
  --image "retich-console:${TAG}" \
  --image "retich-console:latest" \
  --file Dockerfile .

# Récupérer le mot de passe ACR
ACR_PASSWORD=$(az acr credential show --name retichauth --query "passwords[0].value" -o tsv)

# Déployer la Container App
az containerapp create \
  --name retich-console \
  --resource-group rg-retich-auth \
  --environment retich-env \
  --image "retichauth.azurecr.io/retich-console:${TAG}" \
  --registry-server "retichauth.azurecr.io" \
  --registry-username "retichauth" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 3000 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 2 \
  --secrets \
    "admin-key=<ADMIN_API_KEY>" \
    "session-secret=<SESSION_SECRET>" \
  --env-vars \
    "PORT=3000" \
    "RETICH_AUTH_URL=https://<retich-auth-fqdn>" \
    "ADMIN_API_KEY=secretref:admin-key" \
    "SESSION_SECRET=secretref:session-secret"
```

**Mettre à jour une image existante**

```bash
TAG="$(date +%Y%m%d-%H%M%S)"

# Auth service
az acr build --registry retichauth \
  --image "retich-auth:${TAG}" --image "retich-auth:latest" \
  --file Dockerfile . \
  && az containerapp update --name retich-auth \
     --resource-group rg-retich-auth \
     --image "retichauth.azurecr.io/retich-auth:${TAG}"

# Console admin
cd retich-console
az acr build --registry retichauth \
  --image "retich-console:${TAG}" --image "retich-console:latest" \
  --file Dockerfile . \
  && az containerapp update --name retich-console \
     --resource-group rg-retich-auth \
     --image "retichauth.azurecr.io/retich-console:${TAG}"
```

---

## Configuration

### Auth service (`.env` / `.env.prod`)

| Variable | Description | Défaut |
|----------|-------------|--------|
| `PORT` | Port du serveur | `8081` |
| `DATABASE_URL` | DSN PostgreSQL | — |
| `RSA_PRIVATE_KEY` | Clé privée RSA PEM (RS256). Vide en dev → clé éphémère | — |
| `JWT_EXPIRATION` | Durée de vie access token | `15m` |
| `REFRESH_TOKEN_EXPIRATION` | Durée de vie refresh token | `168h` |
| `APP_URL` | URL publique du service — utilisé comme `iss` dans les JWT | — |
| `ADMIN_API_KEY` | Clé secrète pour l'API admin (`X-Admin-Key`) | — |
| `SESSION_SECRET` | Secret HMAC pour les cookies de session (min 32 chars) | — |
| `ALLOWED_ORIGINS` | CORS — origines autorisées (séparées par virgule) | — |
| `ALLOWED_REDIRECT_URLS` | URLs autorisées pour les liens email (vérification, reset) | — |
| `RESEND_API_KEY` | Clé API [Resend](https://resend.com) | — |
| `RESEND_FROM_EMAIL` | Expéditeur des emails (domaine vérifié sur Resend) | — |
| `RESEND_FROM_NAME` | Nom affiché dans les emails | — |
| `REQUIRE_EMAIL_VERIFICATION` | `true` = connexion bloquée tant que l'email n'est pas vérifié | `true` |
| `BCRYPT_COST` | Coût de hachage bcrypt | `12` |
| `ACCOUNT_LOCKOUT_ATTEMPTS` | Tentatives avant verrouillage du compte | `5` |
| `ACCOUNT_LOCKOUT_DURATION` | Durée du verrouillage | `15m` |

Générer les secrets :
```bash
# RSA key
openssl genrsa 2048 | awk 'NF {sub(/\r/,""); printf "%s\\n",$0}'

# ADMIN_API_KEY
openssl rand -hex 32

# SESSION_SECRET
openssl rand -base64 32
```

### Console admin (`.env.local`)

| Variable | Description |
|----------|-------------|
| `RETICH_AUTH_URL` | URL de l'auth service |
| `ADMIN_API_KEY` | Même clé que `ADMIN_API_KEY` du service |
| `SESSION_SECRET` | Secret pour les cookies de session de la console (min 32 chars) |

---

## Console admin (retich-console)

La console est une interface web Next.js pour gérer les clients OAuth sans passer par l'API.

**Accès :** `https://<retich-console-url>/login`
**Mot de passe :** la valeur de `ADMIN_API_KEY`

### Workflow complet

**1. Connexion**

Entrer l'`ADMIN_API_KEY` sur la page de login. La session est chiffrée dans un cookie httpOnly (iron-session) — valide jusqu'à fermeture du navigateur.

**2. Créer un projet (client OAuth)**

`Projets → + Nouveau projet`

| Champ | Description |
|-------|-------------|
| Nom | Nom affiché sur la page de consentement |
| Logo URL | Optionnel — affiché sur la page de consentement |
| Redirect URIs | Une par ligne. Doit correspondre **exactement** à la `redirect_uri` envoyée par l'app |
| Scopes | Séparés par virgule. Valeurs : `openid`, `email`, `profile` |

Après création, le `client_secret` est affiché **une seule fois** — le copier immédiatement.

**3. Utiliser les credentials dans ton app**

```bash
RETICH_AUTH_URL=https://retich-auth.ashyplant-a8bd2417.francecentral.azurecontainerapps.io
RETICH_CLIENT_ID=<client_id affiché>
RETICH_CLIENT_SECRET=<client_secret copié>
```

**4. Modifier un projet**

`Projets → [Nom du projet] → Éditer`

Modifier le nom, le logo, les redirect URIs ou les scopes. Le `client_id` et `client_secret` ne changent pas.

**5. Désactiver / Réactiver**

Depuis la fiche d'un projet → **Zone dangereuse** → Désactiver.
Un client désactivé ne peut plus émettre de tokens — les utilisateurs déjà connectés ne sont pas déconnectés (leurs tokens existants restent valides jusqu'à expiration).

Pour réactiver : fiche du projet → bouton **Réactiver**.

---

## Intégration OIDC

### NextAuth / Auth.js

**1. Créer un client OAuth**

```bash
curl -X POST https://<AUTH_URL>/api/v1/admin/clients \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: <ADMIN_API_KEY>" \
  -d '{
    "name": "Mon App",
    "redirect_uris": ["https://monapp.com/api/auth/callback/retich"],
    "scopes": ["openid", "email", "profile"]
  }'
```

> Sauvegarder le `client_secret` immédiatement — il n'est affiché qu'une seule fois.

**2. Configurer NextAuth**

```ts
// auth.ts
import NextAuth from "next-auth"

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [{
    id: "retich",
    name: "ReTiCh Auth",
    type: "oidc",
    issuer: process.env.RETICH_AUTH_URL,   // ex: https://auth.mondomaine.com
    clientId: process.env.RETICH_CLIENT_ID,
    clientSecret: process.env.RETICH_CLIENT_SECRET,
    checks: ["pkce", "state", "nonce"],
    authorization: { params: { scope: "openid email profile" } },
  }],
})
```

**3. Variables d'environnement de l'app**

```bash
RETICH_AUTH_URL=https://auth.mondomaine.com
RETICH_CLIENT_ID=<client_id>
RETICH_CLIENT_SECRET=<client_secret>
NEXTAUTH_URL=https://monapp.com
NEXTAUTH_SECRET=<openssl rand -base64 32>
```

La `redirect_uri` à enregistrer dans la console : `https://monapp.com/api/auth/callback/retich`

---

## API Admin

Toutes les routes nécessitent le header `X-Admin-Key: <ADMIN_API_KEY>`.

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/v1/admin/clients` | Créer un client OAuth |
| `GET` | `/api/v1/admin/clients` | Lister tous les clients |
| `GET` | `/api/v1/admin/clients/{id}` | Détail d'un client |
| `PATCH` | `/api/v1/admin/clients/{id}` | Modifier (nom, URIs, scopes, statut) |
| `POST` | `/api/v1/admin/clients/{id}/activate` | Réactiver un client désactivé |
| `DELETE` | `/api/v1/admin/clients/{id}` | Désactiver un client |

---

## Routes exposées

### OAuth 2.0 / OIDC

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | Métadonnées OIDC |
| `GET /.well-known/jwks.json` | Clé publique RS256 |
| `GET /oauth/authorize` | Démarre le flow Authorization Code |
| `POST /oauth/authorize` | Traite l'action de consentement |
| `POST /oauth/token` | Échange code → tokens / refresh |
| `GET /oauth/userinfo` | Infos utilisateur (Bearer JWT requis) |
| `GET /oauth/playground` | Interface de test interactive |

### Pages hébergées

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/login` | Page de connexion |
| `GET /oauth/register` | Page d'inscription |
| `GET /oauth/forgot-password` | Page "mot de passe oublié" |

### Auth (liens email)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/auth/verify-email` | Validation de l'email |
| `GET /api/v1/auth/reset-password` | Formulaire de nouveau mot de passe |
| `POST /api/v1/auth/reset-password` | Enregistrement du nouveau mot de passe |

### Routes protégées (Bearer JWT requis)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/auth/me` | Profil de l'utilisateur connecté |
| `POST /api/v1/auth/logout` | Invalider le refresh token actuel |
| `POST /api/v1/auth/logout-all` | Invalider tous les refresh tokens |

---

## Base de données

Migrations appliquées automatiquement au démarrage via `golang-migrate`.

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
| PKCE obligatoire | `code_challenge_method=S256` requis pour tous les flows |
| JWT RS256 | Vérifiables via JWKS public, sans secret partagé |
| `iss` claim | Validé par les clients OIDC (valeur = `APP_URL`) |
| Refresh token rotation | Chaque refresh invalide l'ancien token |
| Blacklist JWT | Tokens révoqués stockés en cache mémoire avec TTL |
| Rate limiting | In-memory — par IP et par action |
| Verrouillage de compte | Après N tentatives échouées (configurable) |
| Sessions browser | Cookie httpOnly signé HMAC |
| `client_secret_basic` | Supporté en plus de `client_secret_post` |

---

## Licence

MIT
