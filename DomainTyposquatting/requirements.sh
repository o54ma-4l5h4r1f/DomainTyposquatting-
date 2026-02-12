#!/bin/bash
#===============================================================================
# TYPOSQUATTING PLATFORM - REQUIREMENTS CHECK
#===============================================================================
# Run this before deploy-all.sh to verify all prerequisites
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
ERRORS=0
WARNINGS=0

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          TYPOSQUATTING PLATFORM - REQUIREMENTS CHECK                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

#===============================================================================
# SECTION 1: CORE TOOLS
#===============================================================================
echo "═══════════════════════════════════════════════════════════════════════"
echo "1. CORE TOOLS"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

# Bash
if command -v bash &> /dev/null; then
    echo -e "${GREEN}✅ bash${NC}: $(bash --version | head -1)"
else
    echo -e "${RED}❌ bash: NOT INSTALLED${NC}"
    ((ERRORS++))
fi

# Git
if command -v git &> /dev/null; then
    echo -e "${GREEN}✅ git${NC}: $(git --version)"
else
    echo -e "${RED}❌ git: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install git"
    ((ERRORS++))
fi

# curl
if command -v curl &> /dev/null; then
    echo -e "${GREEN}✅ curl${NC}: $(curl --version | head -1)"
else
    echo -e "${RED}❌ curl: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install curl"
    ((ERRORS++))
fi

# jq
if command -v jq &> /dev/null; then
    echo -e "${GREEN}✅ jq${NC}: $(jq --version)"
else
    echo -e "${RED}❌ jq: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install jq"
    ((ERRORS++))
fi

# zip
if command -v zip &> /dev/null; then
    echo -e "${GREEN}✅ zip${NC}: $(zip --version | head -2 | tail -1)"
else
    echo -e "${RED}❌ zip: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install zip"
    ((ERRORS++))
fi

# unzip
if command -v unzip &> /dev/null; then
    echo -e "${GREEN}✅ unzip${NC}: installed"
else
    echo -e "${RED}❌ unzip: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install unzip"
    ((ERRORS++))
fi

# openssl
if command -v openssl &> /dev/null; then
    echo -e "${GREEN}✅ openssl${NC}: $(openssl version)"
else
    echo -e "${RED}❌ openssl: NOT INSTALLED${NC}"
    echo "   → Install: sudo apt install openssl"
    ((ERRORS++))
fi

#===============================================================================
# SECTION 2: AZURE CLI
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "2. AZURE CLI"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if command -v az &> /dev/null; then
    AZ_VERSION=$(az version --query '"azure-cli"' -o tsv 2>/dev/null)
    echo -e "${GREEN}✅ Azure CLI${NC}: $AZ_VERSION"
    
    # Check login status
    if az account show &>/dev/null; then
        ACCOUNT_NAME=$(az account show --query "name" -o tsv 2>/dev/null)
        SUBSCRIPTION_ID=$(az account show --query "id" -o tsv 2>/dev/null)
        echo -e "${GREEN}✅ Logged in${NC}: $ACCOUNT_NAME"
        echo "   Subscription: ${SUBSCRIPTION_ID:0:8}..."
    else
        echo -e "${RED}❌ Not logged in to Azure${NC}"
        echo "   → Run: az login"
        ((ERRORS++))
    fi
    
    # Check containerapp extension
    echo ""
    if az extension show --name containerapp &>/dev/null; then
        EXT_VERSION=$(az extension show --name containerapp --query "version" -o tsv 2>/dev/null)
        echo -e "${GREEN}✅ containerapp extension${NC}: $EXT_VERSION"
    else
        echo -e "${YELLOW}⚠️  containerapp extension: NOT INSTALLED${NC}"
        echo "   → Install: az extension add --name containerapp"
        ((WARNINGS++))
    fi
else
    echo -e "${RED}❌ Azure CLI: NOT INSTALLED${NC}"
    echo "   → Install: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
    ((ERRORS++))
fi

#===============================================================================
# SECTION 3: AZURE FUNCTIONS CORE TOOLS
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "3. AZURE FUNCTIONS CORE TOOLS"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if command -v func &> /dev/null; then
    FUNC_VERSION=$(func --version 2>/dev/null)
    if [[ "$FUNC_VERSION" == 4.* ]]; then
        echo -e "${GREEN}✅ Azure Functions Core Tools${NC}: v$FUNC_VERSION"
    else
        echo -e "${YELLOW}⚠️  Azure Functions Core Tools${NC}: v$FUNC_VERSION (v4.x recommended)"
        ((WARNINGS++))
    fi
else
    echo -e "${YELLOW}⚠️  Azure Functions Core Tools: NOT INSTALLED (optional for deployment)${NC}"
    echo "   → Install: npm install -g azure-functions-core-tools@4"
    ((WARNINGS++))
fi

#===============================================================================
# SECTION 4: NODE.JS / NPM
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "4. NODE.JS / NPM"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}✅ Node.js${NC}: $NODE_VERSION"
else
    echo -e "${RED}❌ Node.js: NOT INSTALLED${NC}"
    echo "   → Install: https://nodejs.org/ or nvm"
    ((ERRORS++))
fi

if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    echo -e "${GREEN}✅ npm${NC}: v$NPM_VERSION"
else
    echo -e "${RED}❌ npm: NOT INSTALLED${NC}"
    echo "   → Comes with Node.js"
    ((ERRORS++))
fi

if command -v npx &> /dev/null; then
    echo -e "${GREEN}✅ npx${NC}: installed"
else
    echo -e "${RED}❌ npx: NOT INSTALLED${NC}"
    echo "   → Comes with npm 5.2+"
    ((ERRORS++))
fi

# SWA CLI (optional)
echo ""
if npm list -g @azure/static-web-apps-cli &>/dev/null 2>&1; then
    echo -e "${GREEN}✅ SWA CLI${NC}: installed globally"
else
    echo -e "${YELLOW}⚠️  SWA CLI: not installed globally (will use npx)${NC}"
    echo "   → Optional: npm install -g @azure/static-web-apps-cli"
    ((WARNINGS++))
fi

#===============================================================================
# SECTION 5: PYTHON (Optional for local development)
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "5. PYTHON (Optional - for local development)"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version)
    echo -e "${GREEN}✅ Python${NC}: $PY_VERSION"
    
    # Check if 3.11+
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PY_MINOR" -ge 11 ]; then
        echo "   (3.11+ required for Azure Functions)"
    else
        echo -e "${YELLOW}   ⚠️  Azure Functions requires Python 3.11${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Python: NOT INSTALLED (optional)${NC}"
    echo "   → Install: sudo apt install python3"
    ((WARNINGS++))
fi

if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✅ pip3${NC}: installed"
else
    echo -e "${YELLOW}⚠️  pip3: NOT INSTALLED (optional)${NC}"
    ((WARNINGS++))
fi

#===============================================================================
# SECTION 6: DOCKER (Optional)
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "6. DOCKER (Optional - ACR Build used instead)"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}✅ Docker${NC}: $DOCKER_VERSION"
    
    if docker info &>/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker daemon${NC}: running"
    else
        echo -e "${YELLOW}⚠️  Docker daemon: not running${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Docker: NOT INSTALLED (optional - using ACR Build)${NC}"
    ((WARNINGS++))
fi

#===============================================================================
# SECTION 7: NETWORK CONNECTIVITY
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "7. NETWORK CONNECTIVITY"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

# Azure Management
echo -n "   Azure Management API: "
if curl -s --connect-timeout 5 https://management.azure.com > /dev/null 2>&1; then
    echo -e "${GREEN}✅ reachable${NC}"
else
    echo -e "${RED}❌ unreachable${NC}"
    ((ERRORS++))
fi

# Azure Container Registry
echo -n "   Azure Container Registry: "
if curl -s --connect-timeout 5 https://azurecr.io > /dev/null 2>&1; then
    echo -e "${GREEN}✅ reachable${NC}"
else
    echo -e "${YELLOW}⚠️  unreachable${NC}"
    ((WARNINGS++))
fi

# npm Registry
echo -n "   npm Registry: "
if curl -s --connect-timeout 5 https://registry.npmjs.org > /dev/null 2>&1; then
    echo -e "${GREEN}✅ reachable${NC}"
else
    echo -e "${YELLOW}⚠️  unreachable${NC}"
    ((WARNINGS++))
fi

#===============================================================================
# SECTION 8: PROJECT STRUCTURE
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "8. PROJECT STRUCTURE"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

# Check required folders
SCRIPT_DIR="$(pwd)"

if [ -d "dnstwist-api" ]; then
    echo -e "${GREEN}✅ dnstwist-api/${NC}"
else
    echo -e "${RED}❌ dnstwist-api/ NOT FOUND${NC}"
    ((ERRORS++))
fi

if [ -d "dnstwist-orchestrator" ]; then
    echo -e "${GREEN}✅ dnstwist-orchestrator/${NC}"
else
    echo -e "${RED}❌ dnstwist-orchestrator/ NOT FOUND${NC}"
    ((ERRORS++))
fi

if [ -d "whoisds-typosquatting" ]; then
    echo -e "${GREEN}✅ whoisds-typosquatting/${NC}"
else
    echo -e "${RED}❌ whoisds-typosquatting/ NOT FOUND${NC}"
    ((ERRORS++))
fi

if [ -d "portal" ] && [ -f "portal/index.html" ]; then
    echo -e "${GREEN}✅ portal/index.html${NC}"
else
    echo -e "${YELLOW}⚠️  portal/index.html NOT FOUND (portal won't deploy)${NC}"
    ((WARNINGS++))
fi

if [ -f "deploy-all.sh" ]; then
    echo -e "${GREEN}✅ deploy-all.sh${NC}"
else
    echo -e "${RED}❌ deploy-all.sh NOT FOUND${NC}"
    ((ERRORS++))
fi

#===============================================================================
# SUMMARY
#===============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "SUMMARY"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ALL REQUIREMENTS MET - Ready to deploy!                         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Run: ./deploy-all.sh"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ⚠️  $WARNINGS warning(s) - Deployment should still work                    ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Run: ./deploy-all.sh"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ $ERRORS error(s), $WARNINGS warning(s) - Please fix before deploying         ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Quick Fix Commands:${NC}"
    echo ""
    echo "# Install Azure CLI"
    echo "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
    echo ""
    echo "# Login to Azure"
    echo "az login"
    echo ""
    echo "# Add containerapp extension"
    echo "az extension add --name containerapp"
    echo ""
    echo "# Install Node.js (Ubuntu/Debian)"
    echo "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -"
    echo "sudo apt install -y nodejs"
    echo ""
    echo "# Install other tools"
    echo "sudo apt install -y git curl jq zip unzip openssl"
    echo ""
    exit 1
fi
