#!/bin/bash
#===============================================================================
# TYPOSQUATTING DETECTION PLATFORM - DEPLOYMENT SCRIPT
#===============================================================================
# Creates all resources. Use clean.sh to delete everything.
#===============================================================================

set -e

#===============================================================================
#                         CONFIGURATION
#===============================================================================

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                          AZURE SETTINGS                                     │
# └─────────────────────────────────────────────────────────────────────────────┘
RESOURCE_GROUP="CSI-DomainTyposquatting"
LOCATION="uksouth"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                       STORAGE ACCOUNT                                       │
# └─────────────────────────────────────────────────────────────────────────────┘
# Option 1: Use existing storage account
USE_EXISTING_STORAGE="false"
STORAGE_ACCOUNT_NAME="csidomaintyposquatting"

# Option 2: Create new storage account (if USE_EXISTING_STORAGE="false")
NEW_STORAGE_ACCOUNT_NAME="csidomaintyposquatting"              # Leave empty to auto-generate
NEW_STORAGE_SKU="Standard_LRS"

# Container names
DNSTWIST_RESULTS_CONTAINER="dnstwist"
WHOISDS_CONTAINER="whoisds"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                    DNSTWIST API (Container App)                             │
# └─────────────────────────────────────────────────────────────────────────────┘
DNSTWIST_API_NAME="fuzzingapi"                        # Leave empty to auto-generate
DNSTWIST_API_KEY="5887da8e4a96156a408e0f9a9651b5eeacfefe354ee922c7296ff0ad7d9d6d62"                                        # Leave empty to auto-generate
ACR_NAME="fuzzingacr"                                 # Leave empty to auto-generate

# Container App Settings
CONTAINER_CPU="1.0"
CONTAINER_MEMORY="2.0Gi"
CONTAINER_MIN_REPLICAS="0"
CONTAINER_MAX_REPLICAS="3"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                    AZURE FUNCTIONS (Flex Consumption)                       │
# └─────────────────────────────────────────────────────────────────────────────┘
ORCHESTRATOR_NAME="fuzzing-orchestrator"                      # Leave empty to auto-generate
WHOISDS_FUNC_NAME="typosquatting-nrd-api"                       # Leave empty to auto-generate

# Python version for Azure Functions
PYTHON_VERSION="3.11"                                      # 3.9, 3.10, 3.11

# WhoisDS Credentials (optional - can set in portal later)
WHOISDS_EMAIL="osama.alsharif@wizardcyber.com"
WHOISDS_PASSWORD="1a2b3c4D"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                    STATIC WEB APP (Portal)                                  │
# └─────────────────────────────────────────────────────────────────────────────┘
PORTAL_NAME="portal"                             # Leave empty to auto-generate
PORTAL_LOCATION="westeurope"                               # Free tier available regions
SKIP_PORTAL="false"                                        # Set to "true" to skip

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                        DEPLOYMENT OPTIONS                                   │
# └─────────────────────────────────────────────────────────────────────────────┘

# Health Checks
ENABLE_HEALTH_CHECK="true"
HEALTH_CHECK_PATH="/api/health"

# Monitoring - ALL DISABLED BY DEFAULT
ENABLE_APP_INSIGHTS="false"

# Skip components (set to "true" to skip)
SKIP_DNSTWIST_API="false"
SKIP_ORCHESTRATOR="false"
SKIP_WHOISDS="false"

# Output file for all secrets and URLs
OUTPUT_FILE="deployment-output.json"

#===============================================================================
#                    DO NOT MODIFY BELOW THIS LINE
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if resource exists
resource_exists() {
    local type="$1"
    local name="$2"
    local rg="$3"
    
    case $type in
        "acr")
            az acr show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        "containerapp")
            az containerapp show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        "containerapp-env")
            az containerapp env show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        "functionapp")
            az functionapp show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        "storage")
            az storage account show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        "staticwebapp")
            az staticwebapp show --name "$name" --resource-group "$rg" &>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        TYPOSQUATTING DETECTION PLATFORM - DEPLOYMENT                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Generate random suffix
RANDOM_SUFFIX=$(openssl rand -hex 4)

# Generate names if not provided
[ -z "$DNSTWIST_API_NAME" ] && DNSTWIST_API_NAME="dnstwist-api-${RANDOM_SUFFIX}"
[ -z "$ACR_NAME" ] && ACR_NAME="dnstwistacr${RANDOM_SUFFIX}"
[ -z "$DNSTWIST_API_KEY" ] && DNSTWIST_API_KEY=$(openssl rand -hex 32)
[ -z "$ORCHESTRATOR_NAME" ] && ORCHESTRATOR_NAME="dnstwist-orch-${RANDOM_SUFFIX}"
[ -z "$WHOISDS_FUNC_NAME" ] && WHOISDS_FUNC_NAME="whoisds-func-${RANDOM_SUFFIX}"
[ -z "$NEW_STORAGE_ACCOUNT_NAME" ] && NEW_STORAGE_ACCOUNT_NAME="typosquat${RANDOM_SUFFIX}"
[ -z "$PORTAL_NAME" ] && PORTAL_NAME="typosquat-portal-${RANDOM_SUFFIX}"

# Display configuration
echo "┌─────────────────────────────────────────────────────────────────────┐"
echo "│ Configuration                                                       │"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ Resource Group:      $RESOURCE_GROUP"
echo "│ Location:            $LOCATION"
if [ "$USE_EXISTING_STORAGE" == "true" ]; then
echo "│ Storage Account:     $STORAGE_ACCOUNT_NAME (existing)"
else
echo "│ Storage Account:     $NEW_STORAGE_ACCOUNT_NAME (new)"
fi
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ DNSTwist API:        $DNSTWIST_API_NAME"
echo "│ Orchestrator:        $ORCHESTRATOR_NAME"
echo "│ WhoisDS:             $WHOISDS_FUNC_NAME"
echo "│ Portal:              $PORTAL_NAME"
echo "│ Python Version:      $PYTHON_VERSION"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ Health Check:        $ENABLE_HEALTH_CHECK"
echo "│ App Insights:        $ENABLE_APP_INSIGHTS"
echo "└─────────────────────────────────────────────────────────────────────┘"
echo ""

# Initialize output JSON
DNSTWIST_API_URL=""
ORCHESTRATOR_URL=""
ORCHESTRATOR_KEY=""
WHOISDS_URL=""
WHOISDS_KEY=""
CALLBACK_URL=""
FINAL_STORAGE_NAME=""
PORTAL_URL=""

#===============================================================================
# STEP 1: RESOURCE GROUP
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "STEP 1: Resource Group"
echo "═══════════════════════════════════════════════════════════════════════"

if az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    echo -e "${GREEN}✅ Resource group exists: $RESOURCE_GROUP${NC}"
else
    echo "🔧 Creating resource group..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
    echo -e "${GREEN}✅ Created: $RESOURCE_GROUP${NC}"
fi

#===============================================================================
# STEP 2: STORAGE ACCOUNT
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "STEP 2: Storage Account"
echo "═══════════════════════════════════════════════════════════════════════"

if [ "$USE_EXISTING_STORAGE" == "true" ]; then
    if resource_exists "storage" "$STORAGE_ACCOUNT_NAME" "$RESOURCE_GROUP"; then
        echo -e "${GREEN}✅ Using existing: $STORAGE_ACCOUNT_NAME${NC}"
        FINAL_STORAGE_NAME="$STORAGE_ACCOUNT_NAME"
    else
        echo -e "${RED}❌ Storage account not found: $STORAGE_ACCOUNT_NAME${NC}"
        echo "   Set USE_EXISTING_STORAGE=\"false\" to create new"
        exit 1
    fi
else
    if resource_exists "storage" "$NEW_STORAGE_ACCOUNT_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Storage exists, skipping: $NEW_STORAGE_ACCOUNT_NAME${NC}"
    else
        echo "🔧 Creating storage account..."
        az storage account create \
            --name "$NEW_STORAGE_ACCOUNT_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --sku "$NEW_STORAGE_SKU" \
            --kind StorageV2 \
            --output none
        echo -e "${GREEN}✅ Created: $NEW_STORAGE_ACCOUNT_NAME${NC}"
    fi
    FINAL_STORAGE_NAME="$NEW_STORAGE_ACCOUNT_NAME"
fi

# Get connection string
STORAGE_CONNECTION=$(az storage account show-connection-string \
    --name "$FINAL_STORAGE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query connectionString -o tsv)

# Create containers
echo "🔧 Creating blob containers..."
az storage container create --name "$DNSTWIST_RESULTS_CONTAINER" \
    --connection-string "$STORAGE_CONNECTION" --output none 2>/dev/null || true
az storage container create --name "$WHOISDS_CONTAINER" \
    --connection-string "$STORAGE_CONNECTION" --output none 2>/dev/null || true
echo -e "${GREEN}✅ Containers ready${NC}"

#===============================================================================
# STEP 3: DNSTWIST API (Container App)
#===============================================================================
if [ "$SKIP_DNSTWIST_API" != "true" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "STEP 3: DNSTwist API (Container App)"
    echo "═══════════════════════════════════════════════════════════════════════"

    # ACR
    if resource_exists "acr" "$ACR_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  ACR exists: $ACR_NAME${NC}"
        read -p "   Rebuild and push container image? [y/N]: " rebuild_image
        if [[ "$rebuild_image" =~ ^[Yy]$ ]]; then
            DO_REBUILD_IMAGE="true"
        else
            DO_REBUILD_IMAGE="false"
        fi
    else
        echo "🔧 Creating Container Registry..."
        az acr create \
            --name "$ACR_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --sku Basic \
            --admin-enabled true \
            --output none
        echo -e "${GREEN}✅ Created ACR: $ACR_NAME${NC}"
        DO_REBUILD_IMAGE="true"
    fi

    ACR_SERVER="${ACR_NAME}.azurecr.io"
    ACR_USERNAME=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
    ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

    # Build image
    if [ "$DO_REBUILD_IMAGE" == "true" ]; then
        echo "🔧 Building container image..."
        cd dnstwist-api
        az acr build --registry "$ACR_NAME" --image dnstwist-api:latest . --platform linux/amd64
        cd ..
        echo -e "${GREEN}✅ Image built${NC}"
    else
        echo -e "${YELLOW}⏭️  Skipping image build${NC}"
    fi

    # Container App Environment
    CONTAINER_ENV_NAME="${DNSTWIST_API_NAME}-env"
    if resource_exists "containerapp-env" "$CONTAINER_ENV_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Environment exists, skipping: $CONTAINER_ENV_NAME${NC}"
    else
        echo "🔧 Creating Container App Environment..."
        az containerapp env create \
            --name "$CONTAINER_ENV_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --logs-destination none \
            --output none
        echo -e "${GREEN}✅ Created environment${NC}"
    fi

    # Container App
    if resource_exists "containerapp" "$DNSTWIST_API_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Container App exists: $DNSTWIST_API_NAME${NC}"
        if [ "$DO_REBUILD_IMAGE" == "true" ]; then
            read -p "   Update Container App with new image? [y/N]: " update_containerapp
            if [[ "$update_containerapp" =~ ^[Yy]$ ]]; then
                echo "🔧 Updating Container App..."
                az containerapp update \
                    --name "$DNSTWIST_API_NAME" \
                    --resource-group "$RESOURCE_GROUP" \
                    --image "${ACR_SERVER}/dnstwist-api:latest" \
                    --output none
                echo -e "${GREEN}✅ Container App updated${NC}"
            else
                echo -e "${YELLOW}⏭️  Skipping Container App update${NC}"
            fi
        fi
    else
        echo "🔧 Creating Container App..."
        az containerapp create \
            --name "$DNSTWIST_API_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --environment "$CONTAINER_ENV_NAME" \
            --image "${ACR_SERVER}/dnstwist-api:latest" \
            --registry-server "$ACR_SERVER" \
            --registry-username "$ACR_USERNAME" \
            --registry-password "$ACR_PASSWORD" \
            --target-port 8000 \
            --ingress external \
            --cpu "$CONTAINER_CPU" \
            --memory "$CONTAINER_MEMORY" \
            --min-replicas "$CONTAINER_MIN_REPLICAS" \
            --max-replicas "$CONTAINER_MAX_REPLICAS" \
            --env-vars "API_KEY=$DNSTWIST_API_KEY" \
            --output none
        echo -e "${GREEN}✅ Created Container App${NC}"
    fi

    DNSTWIST_API_URL="https://$(az containerapp show \
        --name "$DNSTWIST_API_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query 'properties.configuration.ingress.fqdn' -o tsv)"
    echo -e "${GREEN}✅ DNSTwist API: $DNSTWIST_API_URL${NC}"
else
    echo ""
    echo -e "${YELLOW}⏭️  Skipping DNSTwist API${NC}"
fi

#===============================================================================
# STEP 4: ORCHESTRATOR (Function App - Flex Consumption)
#===============================================================================
if [ "$SKIP_ORCHESTRATOR" != "true" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "STEP 4: Orchestrator (Function App - Flex Consumption)"
    echo "═══════════════════════════════════════════════════════════════════════"

    if resource_exists "functionapp" "$ORCHESTRATOR_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Function App exists: $ORCHESTRATOR_NAME${NC}"
        read -p "   Redeploy code? [y/N]: " redeploy_orch
        DO_DEPLOY_ORCH="false"
        if [[ "$redeploy_orch" =~ ^[Yy]$ ]]; then
            DO_DEPLOY_ORCH="true"
        fi
    else
        echo "🔧 Creating Function App (Flex Consumption)..."
        az functionapp create \
            --name "$ORCHESTRATOR_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --storage-account "$FINAL_STORAGE_NAME" \
            --flexconsumption-location "$LOCATION" \
            --runtime python \
            --runtime-version "$PYTHON_VERSION" \
            --functions-version 4 \
            --output none
        echo -e "${GREEN}✅ Created Function App${NC}"
        DO_DEPLOY_ORCH="true"
    fi

    # Configure settings
    echo "🔧 Configuring settings..."
    ORCH_SETTINGS="BLOB_CONTAINER_NAME=$DNSTWIST_RESULTS_CONTAINER TABLE_NAME=dnstwisttasks"
    [ -n "$DNSTWIST_API_URL" ] && ORCH_SETTINGS="$ORCH_SETTINGS DNSTWIST_API_URL=$DNSTWIST_API_URL"
    [ -n "$DNSTWIST_API_KEY" ] && ORCH_SETTINGS="$ORCH_SETTINGS DNSTWIST_API_KEY=$DNSTWIST_API_KEY"

    az functionapp config appsettings set \
        --name "$ORCHESTRATOR_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --settings $ORCH_SETTINGS \
        --output none

    ORCHESTRATOR_URL="https://${ORCHESTRATOR_NAME}.azurewebsites.net"
    echo -e "${GREEN}✅ Orchestrator: $ORCHESTRATOR_URL${NC}"

    # Deploy code
    if [ "$DO_DEPLOY_ORCH" == "true" ]; then
        echo "🚀 Deploying Orchestrator code..."
        cd dnstwist-orchestrator
        zip -r ../orch-deploy.zip . -x "*.pyc" -x "__pycache__/*" -x ".venv/*" -x "local.settings.json"
        cd ..
        az functionapp deployment source config-zip \
            --name "$ORCHESTRATOR_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --src orch-deploy.zip \
            --output none
        rm -f orch-deploy.zip
        echo -e "${GREEN}✅ Orchestrator code deployed${NC}"

        # Get function key
        echo "⏳ Waiting for function to be ready (90s)..."
        sleep 90
    else
        echo -e "${YELLOW}⏭️  Skipping code deployment${NC}"
    fi
    ORCHESTRATOR_KEY=$(az functionapp keys list \
        --name "$ORCHESTRATOR_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "functionKeys.default" -o tsv 2>/dev/null || \
        az functionapp keys list \
        --name "$ORCHESTRATOR_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "masterKey" -o tsv 2>/dev/null || echo "DEPLOY_CODE_FIRST")

    CALLBACK_URL="${ORCHESTRATOR_URL}/api/callback?code=${ORCHESTRATOR_KEY}"

    # Update DNSTwist API callback if available
    if [ "$SKIP_DNSTWIST_API" != "true" ] && [ -n "$DNSTWIST_API_URL" ] && [ "$ORCHESTRATOR_KEY" != "DEPLOY_CODE_FIRST" ]; then
        echo "🔧 Configuring callback URL on DNSTwist API..."
        az containerapp update \
            --name "$DNSTWIST_API_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --set-env-vars "CALLBACK_URL=$CALLBACK_URL" \
            --output none
    fi
else
    echo ""
    echo -e "${YELLOW}⏭️  Skipping Orchestrator${NC}"
fi

#===============================================================================
# STEP 5: WHOISDS (Function App - Flex Consumption)
#===============================================================================
if [ "$SKIP_WHOISDS" != "true" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "STEP 5: WhoisDS (Function App - Flex Consumption)"
    echo "═══════════════════════════════════════════════════════════════════════"

    if resource_exists "functionapp" "$WHOISDS_FUNC_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Function App exists: $WHOISDS_FUNC_NAME${NC}"
        read -p "   Redeploy code? [y/N]: " redeploy_whoisds
        DO_DEPLOY_WHOISDS="false"
        if [[ "$redeploy_whoisds" =~ ^[Yy]$ ]]; then
            DO_DEPLOY_WHOISDS="true"
        fi
    else
        echo "🔧 Creating Function App (Flex Consumption)..."
        az functionapp create \
            --name "$WHOISDS_FUNC_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --storage-account "$FINAL_STORAGE_NAME" \
            --flexconsumption-location "$LOCATION" \
            --runtime python \
            --runtime-version "$PYTHON_VERSION" \
            --functions-version 4 \
            --output none
        echo -e "${GREEN}✅ Created Function App${NC}"
        DO_DEPLOY_WHOISDS="true"
    fi

    # Configure settings
    echo "🔧 Configuring settings..."
    WHOISDS_SETTINGS="CONTAINER_NAME=$WHOISDS_CONTAINER"
    [ -n "$WHOISDS_EMAIL" ] && WHOISDS_SETTINGS="$WHOISDS_SETTINGS WHOISDS_EMAIL=$WHOISDS_EMAIL"
    [ -n "$WHOISDS_PASSWORD" ] && WHOISDS_SETTINGS="$WHOISDS_SETTINGS WHOISDS_PASSWORD=$WHOISDS_PASSWORD"

    az functionapp config appsettings set \
        --name "$WHOISDS_FUNC_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --settings $WHOISDS_SETTINGS \
        --output none

    WHOISDS_URL="https://${WHOISDS_FUNC_NAME}.azurewebsites.net"
    echo -e "${GREEN}✅ WhoisDS: $WHOISDS_URL${NC}"

    # Deploy code
    if [ "$DO_DEPLOY_WHOISDS" == "true" ]; then
        echo "🚀 Deploying WhoisDS code..."
        cd whoisds-typosquatting
        zip -r ../whoisds-deploy.zip . -x "*.pyc" -x "__pycache__/*" -x ".venv/*" -x "local.settings.json"
        cd ..
        az functionapp deployment source config-zip \
            --name "$WHOISDS_FUNC_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --src whoisds-deploy.zip \
            --output none
        rm -f whoisds-deploy.zip
        echo -e "${GREEN}✅ WhoisDS code deployed${NC}"

        # Get function key
        echo "⏳ Waiting for function to be ready (90s)..."
        sleep 90
    else
        echo -e "${YELLOW}⏭️  Skipping code deployment${NC}"
    fi
    WHOISDS_KEY=$(az functionapp keys list \
        --name "$WHOISDS_FUNC_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "functionKeys.default" -o tsv 2>/dev/null || \
        az functionapp keys list \
        --name "$WHOISDS_FUNC_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "masterKey" -o tsv 2>/dev/null || echo "DEPLOY_CODE_FIRST")
else
    echo ""
    echo -e "${YELLOW}⏭️  Skipping WhoisDS${NC}"
fi

#===============================================================================
# STEP 6: APPLICATION INSIGHTS (Only if enabled)
#===============================================================================
APPINSIGHTS_KEY=""
if [ "$ENABLE_APP_INSIGHTS" == "true" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "STEP 6: Application Insights"
    echo "═══════════════════════════════════════════════════════════════════════"

    APPINSIGHTS_NAME="${RESOURCE_GROUP}-insights"
    
    if az monitor app-insights component show --app "$APPINSIGHTS_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
        echo -e "${YELLOW}⏭️  App Insights exists, skipping: $APPINSIGHTS_NAME${NC}"
    else
        echo "🔧 Creating Application Insights..."
        az monitor app-insights component create \
            --app "$APPINSIGHTS_NAME" \
            --location "$LOCATION" \
            --resource-group "$RESOURCE_GROUP" \
            --application-type web \
            --output none
        echo -e "${GREEN}✅ Created: $APPINSIGHTS_NAME${NC}"
    fi

    APPINSIGHTS_KEY=$(az monitor app-insights component show \
        --app "$APPINSIGHTS_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query instrumentationKey -o tsv)

    # Connect to functions
    if [ "$SKIP_ORCHESTRATOR" != "true" ]; then
        az functionapp config appsettings set \
            --name "$ORCHESTRATOR_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --settings "APPINSIGHTS_INSTRUMENTATIONKEY=$APPINSIGHTS_KEY" \
            --output none
    fi
    if [ "$SKIP_WHOISDS" != "true" ]; then
        az functionapp config appsettings set \
            --name "$WHOISDS_FUNC_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --settings "APPINSIGHTS_INSTRUMENTATIONKEY=$APPINSIGHTS_KEY" \
            --output none
    fi
fi

#===============================================================================
# STEP 7: STATIC WEB APP (Portal)
#===============================================================================
if [ "$SKIP_PORTAL" != "true" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "STEP 7: Static Web App (Portal)"
    echo "═══════════════════════════════════════════════════════════════════════"

    if resource_exists "staticwebapp" "$PORTAL_NAME" "$RESOURCE_GROUP"; then
        echo -e "${YELLOW}⏭️  Static Web App exists: $PORTAL_NAME${NC}"
        read -p "   Redeploy content? [y/N]: " redeploy_portal
        DO_DEPLOY_PORTAL="false"
        if [[ "$redeploy_portal" =~ ^[Yy]$ ]]; then
            DO_DEPLOY_PORTAL="true"
        fi
    else
        echo "🔧 Creating Static Web App (Free tier)..."
        az staticwebapp create \
            --name "$PORTAL_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$PORTAL_LOCATION" \
            --sku Free \
            --output none
        echo -e "${GREEN}✅ Created Static Web App: $PORTAL_NAME${NC}"
        DO_DEPLOY_PORTAL="true"
    fi

    # Get portal URL
    PORTAL_URL="https://$(az staticwebapp show \
        --name "$PORTAL_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query 'defaultHostname' -o tsv)"
    echo -e "${GREEN}✅ Portal URL: $PORTAL_URL${NC}"

    # Deploy content
    if [ "$DO_DEPLOY_PORTAL" == "true" ]; then
        # Check if portal folder exists
        if [ -d "portal" ] && [ -f "portal/index.html" ]; then
            echo "🚀 Deploying portal content..."
            
            # Get deployment token
            DEPLOYMENT_TOKEN=$(az staticwebapp secrets list \
                --name "$PORTAL_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --query 'properties.apiKey' -o tsv)

            # Deploy using SWA CLI with app-location and output-location
            if command -v swa &> /dev/null; then
                swa deploy \
                    --app-location portal \
                    --output-location portal \
                    --deployment-token "$DEPLOYMENT_TOKEN" \
                    --env production
            else
                npx @azure/static-web-apps-cli deploy \
                    --app-location portal \
                    --output-location portal \
                    --deployment-token "$DEPLOYMENT_TOKEN" \
                    --env production
            fi
            
            echo -e "${GREEN}✅ Portal content deployed${NC}"
        else
            echo -e "${YELLOW}⚠️  portal/index.html not found${NC}"
            echo "   Create portal folder with index.html and redeploy"
        fi
    else
        echo -e "${YELLOW}⏭️  Skipping portal deployment${NC}"
    fi

    # Configure CORS on Functions (allow portal to call APIs)
    echo "🔧 Configuring CORS for portal..."
    if [ "$SKIP_ORCHESTRATOR" != "true" ]; then
        az functionapp cors add \
            --name "$ORCHESTRATOR_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --allowed-origins "$PORTAL_URL" \
            --output none 2>/dev/null || true
    fi
    if [ "$SKIP_WHOISDS" != "true" ]; then
        az functionapp cors add \
            --name "$WHOISDS_FUNC_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --allowed-origins "$PORTAL_URL" \
            --output none 2>/dev/null || true
    fi
    echo -e "${GREEN}✅ CORS configured${NC}"
else
    echo ""
    echo -e "${YELLOW}⏭️  Skipping Portal${NC}"
fi

#===============================================================================
# SAVE OUTPUT JSON
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "Saving Configuration"
echo "═══════════════════════════════════════════════════════════════════════"

cat > "$OUTPUT_FILE" << EOF
{
  "deployment_info": {
    "date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "resource_group": "$RESOURCE_GROUP",
    "location": "$LOCATION",
    "python_version": "$PYTHON_VERSION"
  },
  "storage": {
    "account_name": "$FINAL_STORAGE_NAME",
    "connection_string": "$STORAGE_CONNECTION",
    "containers": {
      "dnstwist_results": "$DNSTWIST_RESULTS_CONTAINER",
      "whoisds": "$WHOISDS_CONTAINER"
    }
  },
  "dnstwist_api": {
    "name": "$DNSTWIST_API_NAME",
    "url": "$DNSTWIST_API_URL",
    "api_key": "$DNSTWIST_API_KEY",
    "acr_name": "$ACR_NAME",
    "acr_server": "${ACR_NAME}.azurecr.io",
    "acr_username": "$ACR_USERNAME",
    "acr_password": "$ACR_PASSWORD",
    "environment": "$CONTAINER_ENV_NAME",
    "skipped": $SKIP_DNSTWIST_API
  },
  "orchestrator": {
    "name": "$ORCHESTRATOR_NAME",
    "url": "$ORCHESTRATOR_URL",
    "function_key": "$ORCHESTRATOR_KEY",
    "callback_url": "$CALLBACK_URL",
    "skipped": $SKIP_ORCHESTRATOR
  },
  "whoisds": {
    "name": "$WHOISDS_FUNC_NAME",
    "url": "$WHOISDS_URL",
    "function_key": "$WHOISDS_KEY",
    "skipped": $SKIP_WHOISDS
  },
  "portal": {
    "name": "$PORTAL_NAME",
    "url": "$PORTAL_URL",
    "skipped": $SKIP_PORTAL
  },
  "app_insights": {
    "enabled": $ENABLE_APP_INSIGHTS,
    "instrumentation_key": "${APPINSIGHTS_KEY:-null}"
  }
}
EOF

echo -e "${GREEN}✅ Saved to: $OUTPUT_FILE${NC}"

#===============================================================================
# DEPLOYMENT COMPLETE
#===============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ✅ DEPLOYMENT COMPLETE!                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "┌─────────────────────────────────────────────────────────────────────┐"
echo "│ RESOURCES CREATED                                                   │"
echo "├─────────────────────────────────────────────────────────────────────┤"
if [ "$SKIP_DNSTWIST_API" != "true" ]; then
echo "│ 🐳 DNSTwist API: $DNSTWIST_API_URL"
echo "│    API Key: $DNSTWIST_API_KEY"
fi
if [ "$SKIP_ORCHESTRATOR" != "true" ]; then
echo "│ ⚡ Orchestrator: $ORCHESTRATOR_URL"
echo "│    Key: $ORCHESTRATOR_KEY"
fi
if [ "$SKIP_WHOISDS" != "true" ]; then
echo "│ ⚡ WhoisDS: $WHOISDS_URL"
echo "│    Key: $WHOISDS_KEY"
fi
if [ "$SKIP_PORTAL" != "true" ]; then
echo "│ 🌐 Portal: $PORTAL_URL"
fi
echo "└─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "💾 All secrets saved to: $OUTPUT_FILE"
echo ""
echo -e "${GREEN}🎉 Done!${NC}"
