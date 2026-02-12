#!/bin/bash
#===============================================================================
# TYPOSQUATTING DETECTION PLATFORM - CLEANUP SCRIPT
#===============================================================================
# Deletes all resources created by deploy-all.sh
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#===============================================================================
#                         CONFIGURATION
#===============================================================================
# Must match values used in deploy-all.sh

RESOURCE_GROUP="dnstwist-rg-4"

# Delete entire resource group? (deletes EVERYTHING)
DELETE_RESOURCE_GROUP="false"

# Or delete individual resources:
DELETE_DNSTWIST_API="true"
DELETE_ORCHESTRATOR="true"
DELETE_WHOISDS="true"
DELETE_ACR="true"
DELETE_STORAGE_CONTAINERS="true"         # Only deletes containers, not the account
DELETE_STORAGE_ACCOUNT="false"           # WARNING: Deletes all data!
DELETE_APP_INSIGHTS="true"

# Resource names (from deployment-output.json or deploy-all.sh)
# Leave empty to auto-detect from deployment-output.json
DNSTWIST_API_NAME=""
ORCHESTRATOR_NAME=""
WHOISDS_FUNC_NAME=""
ACR_NAME=""
STORAGE_ACCOUNT_NAME=""

# Container names
DNSTWIST_RESULTS_CONTAINER="dnstwist-typosquatting"
WHOISDS_CONTAINER="whoisds-typosquatting"

#===============================================================================
#                    DO NOT MODIFY BELOW THIS LINE
#===============================================================================

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║        TYPOSQUATTING DETECTION PLATFORM - CLEANUP                    ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Try to load from deployment-output.json
if [ -f "deployment-output.json" ]; then
    echo -e "${BLUE}📄 Loading configuration from deployment-output.json${NC}"
    
    [ -z "$DNSTWIST_API_NAME" ] && DNSTWIST_API_NAME=$(jq -r '.dnstwist_api.name // empty' deployment-output.json 2>/dev/null)
    [ -z "$ORCHESTRATOR_NAME" ] && ORCHESTRATOR_NAME=$(jq -r '.orchestrator.name // empty' deployment-output.json 2>/dev/null)
    [ -z "$WHOISDS_FUNC_NAME" ] && WHOISDS_FUNC_NAME=$(jq -r '.whoisds.name // empty' deployment-output.json 2>/dev/null)
    [ -z "$ACR_NAME" ] && ACR_NAME=$(jq -r '.dnstwist_api.acr_name // empty' deployment-output.json 2>/dev/null)
    [ -z "$STORAGE_ACCOUNT_NAME" ] && STORAGE_ACCOUNT_NAME=$(jq -r '.storage.account_name // empty' deployment-output.json 2>/dev/null)
    
    echo ""
fi

# Display what will be deleted
echo "┌─────────────────────────────────────────────────────────────────────┐"
echo "│ Resources to DELETE                                                 │"
echo "├─────────────────────────────────────────────────────────────────────┤"
if [ "$DELETE_RESOURCE_GROUP" == "true" ]; then
echo -e "│ ${RED}⚠️  ENTIRE RESOURCE GROUP: $RESOURCE_GROUP${NC}"
else
    [ "$DELETE_DNSTWIST_API" == "true" ] && [ -n "$DNSTWIST_API_NAME" ] && echo "│ 🐳 Container App: $DNSTWIST_API_NAME"
    [ "$DELETE_DNSTWIST_API" == "true" ] && [ -n "$DNSTWIST_API_NAME" ] && echo "│ 🐳 Container Env: ${DNSTWIST_API_NAME}-env"
    [ "$DELETE_ACR" == "true" ] && [ -n "$ACR_NAME" ] && echo "│ 📦 Container Registry: $ACR_NAME"
    [ "$DELETE_ORCHESTRATOR" == "true" ] && [ -n "$ORCHESTRATOR_NAME" ] && echo "│ ⚡ Function App: $ORCHESTRATOR_NAME"
    [ "$DELETE_WHOISDS" == "true" ] && [ -n "$WHOISDS_FUNC_NAME" ] && echo "│ ⚡ Function App: $WHOISDS_FUNC_NAME"
    [ "$DELETE_STORAGE_CONTAINERS" == "true" ] && echo "│ 📁 Blob Container: $DNSTWIST_RESULTS_CONTAINER"
    [ "$DELETE_STORAGE_CONTAINERS" == "true" ] && echo "│ 📁 Blob Container: $WHOISDS_CONTAINER"
    [ "$DELETE_STORAGE_ACCOUNT" == "true" ] && [ -n "$STORAGE_ACCOUNT_NAME" ] && echo -e "│ ${RED}⚠️  Storage Account: $STORAGE_ACCOUNT_NAME${NC}"
    [ "$DELETE_APP_INSIGHTS" == "true" ] && echo "│ 📊 App Insights: ${RESOURCE_GROUP}-insights"
fi
echo "└─────────────────────────────────────────────────────────────────────┘"
echo ""

# Confirm
echo -e "${YELLOW}⚠️  This action is IRREVERSIBLE!${NC}"
read -p "Are you sure you want to delete these resources? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi
echo ""

#===============================================================================
# DELETE RESOURCES
#===============================================================================

if [ "$DELETE_RESOURCE_GROUP" == "true" ]; then
    echo "🗑️  Deleting entire resource group: $RESOURCE_GROUP"
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
    echo -e "${GREEN}✅ Resource group deletion initiated (async)${NC}"
    echo "   Run 'az group show -n $RESOURCE_GROUP' to check status"
    exit 0
fi

# Delete Container App
if [ "$DELETE_DNSTWIST_API" == "true" ] && [ -n "$DNSTWIST_API_NAME" ]; then
    echo "🗑️  Deleting Container App: $DNSTWIST_API_NAME"
    az containerapp delete \
        --name "$DNSTWIST_API_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --yes 2>/dev/null || echo "   (not found or already deleted)"
    
    # Delete environment
    CONTAINER_ENV_NAME="${DNSTWIST_API_NAME}-env"
    echo "🗑️  Deleting Container App Environment: $CONTAINER_ENV_NAME"
    az containerapp env delete \
        --name "$CONTAINER_ENV_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --yes 2>/dev/null || echo "   (not found or already deleted)"
fi

# Delete ACR
if [ "$DELETE_ACR" == "true" ] && [ -n "$ACR_NAME" ]; then
    echo "🗑️  Deleting Container Registry: $ACR_NAME"
    az acr delete \
        --name "$ACR_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --yes 2>/dev/null || echo "   (not found or already deleted)"
fi

# Delete Orchestrator
if [ "$DELETE_ORCHESTRATOR" == "true" ] && [ -n "$ORCHESTRATOR_NAME" ]; then
    echo "🗑️  Deleting Function App: $ORCHESTRATOR_NAME"
    az functionapp delete \
        --name "$ORCHESTRATOR_NAME" \
        --resource-group "$RESOURCE_GROUP" 2>/dev/null || echo "   (not found or already deleted)"
fi

# Delete WhoisDS
if [ "$DELETE_WHOISDS" == "true" ] && [ -n "$WHOISDS_FUNC_NAME" ]; then
    echo "🗑️  Deleting Function App: $WHOISDS_FUNC_NAME"
    az functionapp delete \
        --name "$WHOISDS_FUNC_NAME" \
        --resource-group "$RESOURCE_GROUP" 2>/dev/null || echo "   (not found or already deleted)"
fi

# Delete Storage Containers (not account)
if [ "$DELETE_STORAGE_CONTAINERS" == "true" ] && [ -n "$STORAGE_ACCOUNT_NAME" ]; then
    STORAGE_CONNECTION=$(az storage account show-connection-string \
        --name "$STORAGE_ACCOUNT_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query connectionString -o tsv 2>/dev/null || echo "")
    
    if [ -n "$STORAGE_CONNECTION" ]; then
        echo "🗑️  Deleting Container: $DNSTWIST_RESULTS_CONTAINER"
        az storage container delete \
            --name "$DNSTWIST_RESULTS_CONTAINER" \
            --connection-string "$STORAGE_CONNECTION" 2>/dev/null || echo "   (not found)"
        
        echo "🗑️  Deleting Container: $WHOISDS_CONTAINER"
        az storage container delete \
            --name "$WHOISDS_CONTAINER" \
            --connection-string "$STORAGE_CONNECTION" 2>/dev/null || echo "   (not found)"
    fi
fi

# Delete Storage Account
if [ "$DELETE_STORAGE_ACCOUNT" == "true" ] && [ -n "$STORAGE_ACCOUNT_NAME" ]; then
    echo "🗑️  Deleting Storage Account: $STORAGE_ACCOUNT_NAME"
    az storage account delete \
        --name "$STORAGE_ACCOUNT_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --yes 2>/dev/null || echo "   (not found or already deleted)"
fi

# Delete App Insights
if [ "$DELETE_APP_INSIGHTS" == "true" ]; then
    APPINSIGHTS_NAME="${RESOURCE_GROUP}-insights"
    echo "🗑️  Deleting App Insights: $APPINSIGHTS_NAME"
    az monitor app-insights component delete \
        --app "$APPINSIGHTS_NAME" \
        --resource-group "$RESOURCE_GROUP" 2>/dev/null || echo "   (not found or already deleted)"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ✅ CLEANUP COMPLETE!                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Clean up local files
if [ -f "deployment-output.json" ]; then
    read -p "Delete local deployment-output.json? [y/N]: " del_json
    if [[ "$del_json" =~ ^[Yy]$ ]]; then
        rm deployment-output.json
        echo "✅ Deleted deployment-output.json"
    fi
fi

echo ""
echo -e "${GREEN}🎉 Done!${NC}"
