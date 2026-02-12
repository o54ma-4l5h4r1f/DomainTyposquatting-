# Typosquatting Detection Platform

Complete domain typosquatting detection platform using containerized microservices.

## Architecture

All services run as **container apps** (FastAPI + Docker), no Azure Functions required.

| Service | Port | Description |
|---------|------|-------------|
| **dnstwist-api** | 8000 | Domain scanning engine (dnstwist fuzzing) |
| **orchestrator-api** | 8001 | Scan orchestration, result storage, task tracking |
| **whoisds-api** | 8002 | NRD download and keyword search |

## Quick Start (Local)

```bash
# 1. Clone and enter directory
cd DomainTyposquatting

# 2. Copy environment config
cp .env.example .env
# Edit .env with your API key

# 3. Start all services
docker-compose up --build

# 4. Open API docs
# dnstwist-api:    http://localhost:8000/docs
# orchestrator:    http://localhost:8001/docs
# whoisds:         http://localhost:8002/docs
```

## Services

### DNSTwist API (Port 8000)
Core scanning engine with 13 fuzzing algorithms.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/scan` | GET/POST | Scan domain for typosquatting |
| `/scan/csv` | GET | Export results as CSV |
| `/fuzzers` | GET | List fuzzing algorithms |
| `/dictionaries` | GET | List dictionary files |
| `/permutations` | GET | Generate permutations (no DNS) |
| `/permutations/list` | GET | Permutations as plain text |

**Example:**
```bash
# Basic scan
curl "http://localhost:8000/scan?domain=example.com" -H "X-API-Key: changeme"

# Registered domains only with specific fuzzers
curl "http://localhost:8000/scan?domain=example.com&registered=true&fuzzers=homoglyph,bitsquatting" \
  -H "X-API-Key: changeme"
```

### Orchestrator API (Port 8001)
Manages scan jobs, receives callbacks from dnstwist-api, stores results with deduplication.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Submit domains for scanning |
| `/api/callback` | POST | Receive scan results (internal) |
| `/api/status` | GET | Get pending scan tasks |
| `/api/results` | GET | Get stored domains for customer |
| `/api/customers` | GET | List all customers |
| `/api/health` | GET | Health check |

**Example:**
```bash
# Submit domains for scanning
curl -X POST "http://localhost:8001/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": "AcmeCorp",
    "domains": ["example.com", "acme.com"],
    "registered": true
  }'

# Check results
curl "http://localhost:8001/api/results?customer=AcmeCorp"

# Check pending scans
curl "http://localhost:8001/api/status"
```

### WhoisDS NRD API (Port 8002)
Downloads and searches Newly Registered Domains.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/download_nrd` | POST | Download NRD file from WhoisDS |
| `/api/search_keywords` | POST | Search NRD for keywords |
| `/api/files` | GET | List downloaded NRD files |
| `/api/results` | GET | Get search results for customer |
| `/api/health` | GET | Health check |

**Example:**
```bash
# Download NRD for a date
curl -X POST "http://localhost:8002/api/download_nrd" \
  -H "Content-Type: application/json" \
  -d '{"email": "you@email.com", "password": "pass", "date": "2026-01-20"}'

# Search for keywords
curl -X POST "http://localhost:8002/api/search_keywords" \
  -H "Content-Type: application/json" \
  -d '{"Customer": "AcmeCorp", "Keywords": ["acme", "acmecorp"], "date": "2026-01-20"}'
```

## How It Works

```
                  ┌──────────────┐
  Client ──POST──▶│ Orchestrator │──async──▶ DNSTwist API
                  │   (8001)     │            (8000)
                  │              │◀─callback──    │
                  │  ┌─────────┐ │           ┌────────┐
                  │  │ SQLite  │ │           │dnstwist│
                  │  │ (tasks) │ │           │ engine │
                  │  └─────────┘ │           └────────┘
                  │  ┌─────────┐ │
                  │  │  Files  │ │
                  │  │(results)│ │
                  │  └─────────┘ │
                  └──────────────┘

  Client ──POST──▶ WhoisDS API (8002) ──download──▶ whoisds.com
                  │  ┌─────────┐ │
                  │  │  Files  │ │
                  │  │(NRD/res)│ │
                  │  └─────────┘ │
```

1. Client submits domains via orchestrator `/api/scan`
2. Orchestrator sends each domain to dnstwist-api in async mode
3. dnstwist-api scans and calls back orchestrator `/api/callback`
4. Orchestrator stores results (deduped by customer/month)
5. Client queries results via `/api/results`

## Data Storage (Local)

Results are stored in Docker volumes:

```
dnstwist-data volume:
  /{customer}/
    all_domains.txt              # All-time cumulative (deduped)
    {YYYY-MM}/domains.txt        # Monthly results
  tasks.db                       # SQLite task tracking

whoisds-data volume:
  nrd-files/{date}-NRD.txt       # Downloaded NRD files
  matched-results/{customer}/
    {YYYY-MM}/{date}-matches.json  # Keyword search results
```

## Directory Structure

```
DomainTyposquatting/
├── docker-compose.yml           # All services orchestration
├── .env.example                 # Environment template
├── .env                         # Your environment (git-ignored)
├── dnstwist-api/                # Scan engine container
│   ├── Dockerfile
│   ├── api.py
│   ├── requirements.txt
│   └── dictionaries/            # Fuzzing dictionaries
├── orchestrator-api/            # Orchestrator container
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
└── whoisds-api/                 # WhoisDS NRD container
    ├── Dockerfile
    ├── app.py
    └── requirements.txt
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNSTWIST_API_KEY` | `changeme` | API key for dnstwist-api authentication |

All inter-service communication uses Docker networking (no external URLs needed).

## Stopping Services

```bash
# Stop all
docker-compose down

# Stop and remove data volumes
docker-compose down -v
```
