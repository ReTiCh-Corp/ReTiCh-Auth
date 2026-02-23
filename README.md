# ReTiCh Auth Service

Service d'authentification pour la plateforme ReTiCh. Gère l'inscription, la connexion, les tokens JWT et les sessions.

## Fonctionnalités

- Inscription / Connexion
- Authentification JWT avec refresh tokens
- Vérification email
- Réinitialisation de mot de passe
- Gestion des sessions
- Protection contre le brute force

## Prérequis

- Go 1.22+
- PostgreSQL 16+
- Redis (optionnel, pour les sessions)
- Docker (optionnel)

## Démarrage rapide

### Avec Docker (recommandé)

```bash
# Depuis le repo ReTiCh-Infrastucture
make up
make migrate-auth
```

### Sans Docker

```bash
# Installer les dépendances
go mod download

# Configurer la base de données
export DATABASE_URL="postgres://retich:retich_secret@localhost:5433/retich_auth?sslmode=disable"

# Lancer les migrations
migrate -path migrations -database "$DATABASE_URL" up

# Lancer le serveur
go run cmd/server/main.go
```

### Développement avec hot-reload

```bash
# Installer Air
go install github.com/air-verse/air@latest

# Lancer avec hot-reload
air -c .air.toml
```

## Configuration

Variables d'environnement:

| Variable | Description | Défaut |
|----------|-------------|--------|
| `PORT` | Port du serveur | `8081` |
| `DATABASE_URL` | URL PostgreSQL | - |
| `REDIS_URL` | URL Redis | `redis:6379` |
| `JWT_SECRET` | Clé secrète JWT | - |
| `JWT_EXPIRATION` | Durée de vie du token | `24h` |
| `LOG_LEVEL` | Niveau de log | `info` |

## Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| POST | `/register` | Inscription |
| POST | `/login` | Connexion |
| POST | `/refresh` | Rafraîchir le token |
| POST | `/logout` | Déconnexion |
| POST | `/verify-email` | Vérifier l'email |
| POST | `/forgot-password` | Mot de passe oublié |
| POST | `/reset-password` | Réinitialiser le mot de passe |

## Base de données

### Schéma

```
users
├── id (UUID, PK)
├── email (UNIQUE)
├── password_hash
├── is_verified
├── is_active
├── failed_login_attempts
├── locked_until
├── last_login_at
└── timestamps

refresh_tokens
├── id (UUID, PK)
├── user_id (FK → users)
├── token_hash
├── device_info
├── ip_address
├── expires_at
└── revoked_at

verification_tokens
├── id (UUID, PK)
├── user_id (FK → users)
├── token_hash
├── token_type (email_verification, password_reset)
└── expires_at

sessions
├── id (UUID, PK)
├── user_id (FK → users)
├── refresh_token_id (FK)
├── device_info
├── ip_address
├── user_agent
└── expires_at
```

### Migrations

```bash
# Appliquer les migrations
migrate -path migrations -database "$DATABASE_URL" up

# Rollback
migrate -path migrations -database "$DATABASE_URL" down 1

# Version actuelle
migrate -path migrations -database "$DATABASE_URL" version
```

## Structure du projet

```
ReTiCh-Auth/
├── cmd/
│   └── server/
│       └── main.go         # Point d'entrée
├── internal/               # Code interne
├── migrations/
│   ├── 000001_init_schema.up.sql
│   └── 000001_init_schema.down.sql
├── Dockerfile              # Image production
├── Dockerfile.dev          # Image développement
├── .air.toml               # Config hot-reload
├── go.mod
└── go.sum
```

## Tests

```bash
# Lancer les tests
go test ./...

# Avec couverture
go test -cover ./...
```

## Sécurité

- Mots de passe hashés avec bcrypt
- Protection contre le brute force (verrouillage après N tentatives)
- Tokens JWT signés avec HS256
- Refresh tokens stockés hashés en base
- HTTPS obligatoire en production

## Licence

MIT
