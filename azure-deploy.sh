#!/usr/bin/env bash
# =============================================================================
# ReTiCh Auth — Déploiement Azure
# Usage: ./azure-deploy.sh
# Prérequis: az CLI installé et connecté (az login)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Charger les variables depuis .env.prod si présent
# ---------------------------------------------------------------------------
if [ -f ".env.prod" ]; then
  echo "==> Chargement de .env.prod"
  set -o allexport
  # shellcheck disable=SC1091
  source .env.prod
  set +o allexport
elif [ -f ".env" ]; then
  echo "==> .env.prod absent, chargement de .env"
  set -o allexport
  # shellcheck disable=SC1091
  source .env
  set +o allexport
fi

# ---------------------------------------------------------------------------
# CONFIGURATION — modifier ces valeurs avant de lancer
# ---------------------------------------------------------------------------
RESOURCE_GROUP="rg-retich-auth"
LOCATION="francesouth"                      # france south est moins cher que francecentral
ACR_NAME="retichauth"                      # doit être unique globalement (lowercase, pas de tirets)
CONTAINERAPP_ENV="retich-env"
CONTAINERAPP_NAME="retich-auth"
POSTGRES_SERVER="retich-postgres"
POSTGRES_DB="auth"
POSTGRES_USER="retich"
# Secrets (lus depuis les variables d'env pour ne pas les écrire en clair ici)
# Exporter avant de lancer :
#   export POSTGRES_PASSWORD="..."
#   export RSA_PRIVATE_KEY="$(cat retich.pem | awk 'NF {sub(/\r/,""); printf "%s\\n",$0}')"
#   export ADMIN_API_KEY="..."
#   export RESEND_API_KEY="..."
#   export SESSION_SECRET="..."
#   export APP_URL="https://auth.mondomaine.com"
#   export ALLOWED_ORIGINS="https://monapp.com"
#   export ALLOWED_REDIRECT_URLS="https://monapp.com/callback"
#   export RESEND_FROM_EMAIL="noreply@mondomaine.com"
: "${POSTGRES_PASSWORD:?Exporter POSTGRES_PASSWORD}"
: "${RSA_PRIVATE_KEY:?Exporter RSA_PRIVATE_KEY}"
: "${ADMIN_API_KEY:?Exporter ADMIN_API_KEY}"
: "${RESEND_API_KEY:?Exporter RESEND_API_KEY}"
: "${SESSION_SECRET:?Exporter SESSION_SECRET}"
: "${APP_URL:?Exporter APP_URL}"
: "${ALLOWED_ORIGINS:?Exporter ALLOWED_ORIGINS}"
: "${ALLOWED_REDIRECT_URLS:?Exporter ALLOWED_REDIRECT_URLS}"
RESEND_FROM_EMAIL="${RESEND_FROM_EMAIL:-noreply@mondomaine.com}"
RESEND_FROM_NAME="${RESEND_FROM_NAME:-ReTiCh Auth}"

IMAGE_TAG="${ACR_NAME}.azurecr.io/retich-auth:latest"

# ---------------------------------------------------------------------------
echo "==> 1. Création du resource group"
# ---------------------------------------------------------------------------
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# ---------------------------------------------------------------------------
echo "==> 2. Azure Container Registry"
# ---------------------------------------------------------------------------
az acr create \
  --name "$ACR_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --sku Basic \
  --admin-enabled true \
  --output none

echo "    Build et push de l'image..."
az acr build \
  --registry "$ACR_NAME" \
  --image "retich-auth:latest" \
  --file Dockerfile \
  .

# ---------------------------------------------------------------------------
echo "==> 3. PostgreSQL Flexible Server"
# ---------------------------------------------------------------------------
POSTGRES_EXISTS=$(az postgres flexible-server show \
  --name "$POSTGRES_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query state -o tsv 2>/dev/null || echo "")

if [ -z "$POSTGRES_EXISTS" ]; then
  az postgres flexible-server create \
    --name "$POSTGRES_SERVER" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --admin-user "$POSTGRES_USER" \
    --admin-password "$POSTGRES_PASSWORD" \
    --sku-name Standard_B1ms \
    --tier Burstable \
    --storage-size 32 \
    --version 16 \
    --public-access 0.0.0.0 \
    --performance-tier P4 \
    --output none
else
  echo "    Serveur PostgreSQL déjà existant, ignoré."
fi

DB_EXISTS=$(az postgres flexible-server db show \
  --server-name "$POSTGRES_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --database-name "$POSTGRES_DB" \
  --query name -o tsv 2>/dev/null || echo "")

if [ -z "$DB_EXISTS" ]; then
  az postgres flexible-server db create \
    --server-name "$POSTGRES_SERVER" \
    --resource-group "$RESOURCE_GROUP" \
    --database-name "$POSTGRES_DB" \
    --output none
else
  echo "    Base de données '${POSTGRES_DB}' déjà existante, ignorée."
fi

POSTGRES_HOST="${POSTGRES_SERVER}.postgres.database.azure.com"
DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}/${POSTGRES_DB}?sslmode=require"

# ---------------------------------------------------------------------------
echo "==> 4. Container Apps Environment"
# ---------------------------------------------------------------------------
az containerapp env create \
  --name "$CONTAINERAPP_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# ---------------------------------------------------------------------------
echo "==> 5. Déploiement Container App"
# ---------------------------------------------------------------------------
ACR_PASSWORD=$(az acr credential show \
  --name "$ACR_NAME" \
  --query passwords[0].value -o tsv)

CONTAINER_APP_ARGS=(
  --name "$CONTAINERAPP_NAME"
  --resource-group "$RESOURCE_GROUP"
  --environment "$CONTAINERAPP_ENV"
  --image "$IMAGE_TAG"
  --registry-server "${ACR_NAME}.azurecr.io"
  --registry-username "$ACR_NAME"
  --registry-password "$ACR_PASSWORD"
  --target-port 8081
  --ingress external
  --min-replicas 0
  --max-replicas 3
  --scale-rule-name "http-rule"
  --scale-rule-type "http"
  --scale-rule-http-concurrency 50
  --cpu 0.25
  --memory 0.5Gi
  --secrets
    "rsa-key=${RSA_PRIVATE_KEY}"
    "db-url=${DATABASE_URL}"
    "admin-key=${ADMIN_API_KEY}"
    "resend-key=${RESEND_API_KEY}"
    "session-secret=${SESSION_SECRET}"
  --env-vars
    "PORT=8081"
    "ENVIRONMENT=production"
    "DATABASE_URL=secretref:db-url"
    "RSA_PRIVATE_KEY=secretref:rsa-key"
    "ADMIN_API_KEY=secretref:admin-key"
    "RESEND_API_KEY=secretref:resend-key"
    "SESSION_SECRET=secretref:session-secret"
    "APP_URL=${APP_URL}"
    "ALLOWED_ORIGINS=${ALLOWED_ORIGINS}"
    "ALLOWED_REDIRECT_URLS=${ALLOWED_REDIRECT_URLS}"
    "RESEND_FROM_EMAIL=${RESEND_FROM_EMAIL}"
    "RESEND_FROM_NAME=${RESEND_FROM_NAME}"
    "JWT_EXPIRATION=15m"
    "REFRESH_TOKEN_EXPIRATION=168h"
    "BCRYPT_COST=12"
    "ACCOUNT_LOCKOUT_ATTEMPTS=5"
    "ACCOUNT_LOCKOUT_DURATION=15m"
    "EMAIL_VERIFICATION_EXPIRY=24h"
    "PASSWORD_RESET_EXPIRY=1h"
    "MAGIC_LINK_EXPIRY=15m"
    "REQUIRE_EMAIL_VERIFICATION=true"
  --output none
)

az containerapp create "${CONTAINER_APP_ARGS[@]}"

# ---------------------------------------------------------------------------
echo "==> 6. Résultat"
# ---------------------------------------------------------------------------
APP_FQDN=$(az containerapp show \
  --name "$CONTAINERAPP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv)

echo ""
echo "✓ Déploiement terminé"
echo "  URL : https://${APP_FQDN}"
echo "  Health : https://${APP_FQDN}/health"
echo "  JWKS : https://${APP_FQDN}/.well-known/jwks.json"
echo ""
echo "  Mettre à jour APP_URL dans les secrets si différent de ${APP_URL}"
echo "  az containerapp secret set --name ${CONTAINERAPP_NAME} --resource-group ${RESOURCE_GROUP} --secrets rsa-key=<nouvelle-valeur>"
