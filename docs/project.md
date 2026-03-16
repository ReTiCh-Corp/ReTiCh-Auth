# ReTiCh Auth — Documentation projet

Service d'authentification OAuth 2.0 / OIDC auto-hébergé. Fonctionne comme "Se connecter avec Google" mais sur ta propre infrastructure.

---

## Architecture

```
┌─────────────────────────────────────────┐
│              ReTiCh Auth                │
│                                         │
│  Go (Gorilla Mux)  ←→  Postgres        │
│         ↕               (users,         │
│       Redis              clients,       │
│  (sessions, rate         tokens)        │
│   limit, pending                        │
│     OAuth state)                        │
└─────────────────────────────────────────┘
```

| Composant | Rôle |
|-----------|------|
| Go / Gorilla Mux | API HTTP + pages hébergées OAuth |
| PostgreSQL | Stockage utilisateurs, OAuth clients, tokens |
| Redis | Sessions browser, rate limiting, état OAuth temporaire |

---

## Prérequis

- Docker + Docker Compose

---

## Lancer le service

```bash
docker compose up -d
```

- Auth service : `http://localhost:8081`
- PostgreSQL : port `5433` (externe), `5432` (interne)
- Redis : port `6379`

Vérifier que le service tourne :

```bash
curl http://localhost:8081/health
# {"status":"ok"}
```

---

## Variables d'environnement

Copier `.env.example` → `.env` et ajuster :

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | DSN PostgreSQL |
| `REDIS_URL` | URL Redis (`redis://localhost:6379`) |
| `JWT_PRIVATE_KEY_PATH` | Chemin vers la clé privée RSA (RS256) |
| `APP_URL` | URL publique du service (`http://localhost:8081`) |
| `ADMIN_API_KEY` | Clé secrète pour l'API admin (`X-Admin-Key`) |
| `SMTP_*` | Config email (host, port, user, password, from) |
| `ALLOWED_ORIGINS` | CORS — origines autorisées |

---

## Migrations

Les migrations sont appliquées automatiquement au démarrage via Docker.

Fichiers dans `migrations/` :

| Fichier | Contenu |
|---------|---------|
| `000001` | Table `users` |
| `000002` | Table `refresh_tokens` |
| `000003` | Table `oauth_clients` |
| `000004` | Table `authorization_codes` |
| `000005` | Table `oauth_consents` |

---

## API Admin

Protégée par le header `X-Admin-Key`.

### Créer un client OAuth

```bash
curl -X POST http://localhost:8081/api/v1/admin/clients \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: <ADMIN_API_KEY>" \
  -d '{
    "name": "Mon App",
    "redirect_uris": ["http://localhost:3000/api/auth/callback/retich"],
    "scopes": ["openid", "email", "profile"]
  }'
```

Réponse — **sauvegarder le `client_secret` immédiatement** :

```json
{
  "data": {
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "secret_ici"
  }
}
```

### Autres endpoints admin

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/api/v1/admin/clients` | Lister tous les clients |
| `GET` | `/api/v1/admin/clients/{id}` | Détail d'un client |
| `DELETE` | `/api/v1/admin/clients/{id}` | Désactiver un client |

---

## Routes exposées

### OAuth / OIDC (browser)

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Démarre le flow OAuth |
| `GET /oauth/login` | Page de connexion hébergée |
| `GET /oauth/register` | Page d'inscription hébergée |
| `GET /oauth/forgot-password` | Page "mot de passe oublié" hébergée |
| `POST /oauth/token` | Échange code → tokens / refresh |
| `GET /oauth/userinfo` | Infos utilisateur (JWT requis) |
| `GET /oauth/playground` | Interface de test interactive |

### OIDC Discovery

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | Métadonnées OIDC |
| `GET /.well-known/jwks.json` | Clé publique RS256 |

### Callbacks email (liens dans les emails)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/auth/verify-email` | Validation de l'email |
| `GET /api/v1/auth/reset-password` | Formulaire de nouveau mot de passe |

### Routes protégées (JWT requis)

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/logout` | Invalider le refresh token |
| `POST /api/v1/auth/logout-all` | Invalider tous les tokens |
| `GET /api/v1/auth/me` | Profil de l'utilisateur connecté |

---

## Sécurité

| Mécanisme | Détail |
|-----------|--------|
| PKCE obligatoire | `code_challenge_method=S256` requis sur tous les flows |
| Tokens JWT RS256 | Vérifiables sans secret partagé (JWKS public) |
| Refresh token rotation | Chaque refresh invalide l'ancien token |
| Rate limiting | Redis — par IP et par action |
| Verrouillage de compte | Après 5 tentatives échouées |
| Sessions browser | Cookie httpOnly, signé |
