# Typosquatting Detection Platform

Complete deployment package for domain typosquatting detection.

## Components

| Component | Type | Hosting | Cost |
|-----------|------|---------|------|
| **DNSTwist API** | Container App | Flex | ~$0-30/mo |
| **Orchestrator** | Function App | Flex Consumption | ~$0/mo (free tier) |
| **WhoisDS** | Function App | Flex Consumption | ~$0/mo (free tier) |

## Quick Start

```bash
# 1. Unzip and enter directory
unzip typosquatting-platform.zip
cd typosquatting-platform

# 2. Edit configuration
nano deploy-all.sh

# 3. Deploy everything (infrastructure + code)
chmod +x deploy-all.sh
./deploy-all.sh

# 4. Check deployment-output.json for all URLs and keys
cat deployment-output.json
```

The script automatically:
- Creates all Azure resources
- Deploys function code using remote build (same as VS Code)
- Waits for functions to be ready (90s)
- Retrieves all keys and URLs
- Saves everything to `deployment-output.json`

---

## Configuration

### Azure Settings
```bash
RESOURCE_GROUP="dnstwist-rg"
LOCATION="uksouth"
```

### Storage Account
```bash
# Option 1: Use existing
USE_EXISTING_STORAGE="true"
STORAGE_ACCOUNT_NAME="your-existing-storage"

# Option 2: Create new
USE_EXISTING_STORAGE="false"
NEW_STORAGE_ACCOUNT_NAME=""               # Auto-generated if empty
NEW_STORAGE_SKU="Standard_LRS"
```

### Python Version
```bash
PYTHON_VERSION="3.11"                     # 3.9, 3.10, 3.11
```

### Container App (DNSTwist API)
```bash
DNSTWIST_API_NAME=""                      # Auto-generated
DNSTWIST_API_KEY=""                       # Auto-generated
CONTAINER_CPU="1.0"                       # 0.25, 0.5, 1.0, 2.0
CONTAINER_MEMORY="2.0Gi"                  # 0.5Gi - 4.0Gi
CONTAINER_MIN_REPLICAS="0"                # 0 = scale to zero
CONTAINER_MAX_REPLICAS="3"
```

### Function Apps
```bash
ORCHESTRATOR_NAME=""                      # Auto-generated
WHOISDS_FUNC_NAME=""                      # Auto-generated
```

### Options
```bash
ENABLE_HEALTH_CHECK="true"
ENABLE_APP_INSIGHTS="false"               # Disabled by default

# Skip components
SKIP_DNSTWIST_API="false"
SKIP_ORCHESTRATOR="false"
SKIP_WHOISDS="false"
```

---

## Deployment Output

All secrets and URLs are saved to `deployment-output.json`:

```json
{
  "deployment_info": {
    "date": "2026-01-23T...",
    "resource_group": "dnstwist-rg",
    "location": "uksouth",
    "python_version": "3.11"
  },
  "storage": {
    "account_name": "...",
    "connection_string": "...",
    "containers": {...}
  },
  "dnstwist_api": {
    "name": "dnstwist-api-xxx",
    "url": "https://...",
    "api_key": "...",
    "acr_name": "...",
    "acr_server": "...",
    "acr_username": "...",
    "acr_password": "..."
  },
  "orchestrator": {
    "name": "dnstwist-orch-xxx",
    "url": "https://...",
    "function_key": "..."
  },
  "whoisds": {
    "name": "whoisds-func-xxx",
    "url": "https://...",
    "function_key": "..."
  }
}
```

---

## How Code Deployment Works

The script uses **remote build** via `az functionapp deployment source config-zip`:
1. Zips your function code (excluding `.pyc`, `__pycache__`, `.venv`)
2. Uploads to Azure
3. Azure builds dependencies remotely (installs from requirements.txt)
4. Function becomes available

This is the same deployment method VS Code uses under the hood - no `func` CLI needed!

---

## What Gets Created

| Resource | Type | Notes |
|----------|------|-------|
| Container Registry | ACR | Docker images |
| Container App Environment | - | No Log Analytics |
| Container App | DNSTwist API | Flex scaling |
| Function App | Orchestrator | Flex Consumption |
| Function App | WhoisDS | Flex Consumption |
| Blob Containers (2) | Storage | Results storage |

### What's NOT Created (by default)
- ❌ Log Analytics Workspace
- ❌ Application Insights
- ❌ Smart Detector Alert Rules
- ❌ App Service Plans (using Flex Consumption)

---

## Resource Behavior

The script **only creates** resources:
- If resource exists → **Skips** (no update/delete)
- If resource doesn't exist → **Creates**

Use `clean.sh` to delete resources.

---

## Cleanup

```bash
chmod +x clean.sh
./clean.sh
```

Options in `clean.sh`:
```bash
# Delete entire resource group (everything)
DELETE_RESOURCE_GROUP="false"

# Or delete specific resources
DELETE_DNSTWIST_API="true"
DELETE_ORCHESTRATOR="true"
DELETE_WHOISDS="true"
DELETE_ACR="true"
DELETE_STORAGE_CONTAINERS="true"
DELETE_STORAGE_ACCOUNT="false"    # Careful!
DELETE_APP_INSIGHTS="true"
```

---

## Directory Structure

```
typosquatting-platform/
├── deploy-all.sh              # Creates everything + deploys code
├── clean.sh                   # Deletes resources
├── deployment-output.json     # Generated - all secrets
├── dnstwist-api/              # Container App source
│   ├── api.py
│   ├── Dockerfile
│   └── requirements.txt
├── dnstwist-orchestrator/     # Function App source
│   ├── function_app.py
│   ├── requirements.txt
│   └── host.json
└── whoisds-typosquatting/     # Function App source
    ├── function_app.py
    ├── requirements.txt
    └── host.json
```

---

## Cost Estimate

| Component | Cost |
|-----------|------|
| DNSTwist API (Container) | ~$0-30/mo (pay per use) |
| Orchestrator (Flex) | Free tier |
| WhoisDS (Flex) | Free tier |
| Storage | ~$1-5/mo |
| **Total** | **~$1-35/mo** |

---

## API Endpoints

### DNSTwist API
| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET/POST /scan` | Scan domain |
| `GET /fuzzers` | List algorithms |

### Orchestrator
| Endpoint | Description |
|----------|-------------|
| `POST /api/scan` | Submit domains |
| `POST /api/callback` | Receive results |
| `GET /api/status` | Pending scans |
| `GET /api/results` | Get results |
| `GET /api/health` | Health check |

### WhoisDS
| Endpoint | Description |
|----------|-------------|
| `POST /api/download_nrd` | Download NRD |
| `POST /api/search_keywords` | Search keywords |
| `GET /api/health` | Health check |
