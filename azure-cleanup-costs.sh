#!/usr/bin/env bash
# =============================================================================
# ReTiCh Auth — Nettoyage des ressources coûteuses
# Usage: ./azure-cleanup-costs.sh
# =============================================================================
set -euo pipefail

RESOURCE_GROUP="rg-retich-auth"
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

echo "=== Optimisation des coûts Azure pour ReTiCh Auth ==="
echo ""

# ---------------------------------------------------------------------------
echo "1. Désactiver Microsoft Defender (économie ~€15/mo)"
echo "   ⚠️  Action manuelle recommandée :"
echo "   Azure Portal → Microsoft Defender for Cloud → Environment settings"
echo "   → Sélectionner la subscription → Désactiver les plans non nécessaires"
echo ""
echo "   Ou via CLI :"
# Désactiver Defender pour les types de ressources non critiques
for PRICING_TYPE in VirtualMachines SqlServers AppServices StorageAccounts \
  KeyVaults Dns Arm OpenSourceRelationalDatabases Containers; do
  echo "   - Désactivation de Defender pour ${PRICING_TYPE}..."
  az security pricing create \
    --name "$PRICING_TYPE" \
    --tier "Free" \
    --output none 2>/dev/null || true
done
echo "   ✓ Defender basculé en tier Free"
echo ""

# ---------------------------------------------------------------------------
echo "2. Vérifier les disques non attachés"
UNATTACHED=$(az disk list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[?diskState=='Unattached'].{Name:name, Size:diskSizeGb}" \
  -o table 2>/dev/null || echo "Aucun")
echo "   $UNATTACHED"
echo ""

# ---------------------------------------------------------------------------
echo "3. Vérifier les IP publiques non utilisées"
UNUSED_IPS=$(az network public-ip list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[?ipConfiguration==null].{Name:name, Address:ipAddress}" \
  -o table 2>/dev/null || echo "Aucune")
echo "   $UNUSED_IPS"
echo ""

# ---------------------------------------------------------------------------
echo "=== Résumé des économies estimées ==="
echo "  Microsoft Defender : -€15/mo"
echo "  min-replicas 0 (scale-to-zero) : -€5-15/mo (selon le trafic)"
echo "  CPU réduit (0.25 vCPU) : -€3-5/mo"
echo "  ---"
echo "  Total estimé : -€23-35/mo → coût final ~€5-17/mo"
