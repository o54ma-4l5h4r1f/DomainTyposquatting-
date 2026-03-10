# DomainTyposquatting — Technical Reference

Full API reference, database schema, and configuration for every microservice.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Services Overview](#services-overview)
- [DNSTwist API (8000)](#dnstwist-api-port-8000)
- [Orchestrator API (8001)](#orchestrator-api-port-8001)
- [WhoisDS NRD API (8002)](#whoisds-nrd-api-port-8002)
- [Who-Dat WHOIS API (8080)](#who-dat-whois-api-port-8080)
- [Frontend API (8003)](#frontend-api-port-8003)
- [Frontend Dashboard (3000)](#frontend-dashboard-port-3000)
- [Database Schema](#database-schema)
- [Environment Variables](#environment-variables)
- [Directory Structure](#directory-structure)

---

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env — set WHOISDS_EMAIL and WHOISDS_PASSWORD if using NRD downloads

# 2. Start all services
docker-compose up --build

# 3. Open
# Dashboard:     http://localhost:3000/?customers=YourCustomer
# Orchestrator:  http://localhost:8001/docs
# WhoisDS:       http://localhost:8002/docs
# DNSTwist:      http://localhost:8000/docs
# pgAdmin:       http://localhost:5050   (admin@admin.com / admin)

# 4. Stop
docker-compose down          # keep data
docker-compose down -v       # remove data volumes
```

---

## Services Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      docker-compose                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  dnstwist-api│  │ orchestrator │  │  whoisds-api │       │
│  │    :8000     │  │    :8001     │  │    :8002     │       │
│  │  scan engine │  │  hub + store │  │ NRD search   │       │
│  └──────────────┘  └──────┬───────┘  └──────┬───────┘       │
│                           │                 │                │
│  ┌──────────────┐         ▼                 ▼                │
│  │   who-dat    │  ┌──────────────┐                          │
│  │    :8080     │  │  PostgreSQL  │                          │
│  │ WHOIS/RDAP   │  │    :5432     │                          │
│  └──────────────┘  └──────┬───────┘                          │
│                           │                                  │
│  ┌──────────────┐  ┌──────┴───────┐  ┌──────────────┐       │
│  │  frontend    │  │ frontend-api │  │   pgadmin    │       │
│  │    :3000     │──│    :8003     │  │    :5050     │       │
│  │  Vue 3 SPA   │  │ dashboard BE │  │  debug UI    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└──────────────────────────────────────────────────────────────┘
```

| Service | Port | Tech | Role |
|---|---|---|---|
| dnstwist-api | 8000 | Python / FastAPI | Domain permutation + DNS resolution (13 fuzzers) |
| orchestrator-api | 8001 | Python / FastAPI | Scan orchestration, WHOIS enrichment, result storage |
| whoisds-api | 8002 | Python / FastAPI | NRD download from whoisds.com, keyword search |
| who-dat | 8080 | Go | WHOIS + RDAP lookup (fallback chain) |
| frontend-api | 8003 | Python / FastAPI | Dashboard backend — domain listing, actions, customer config |
| frontend | 3000 | Vue 3 / PrimeVue | Customer dashboard SPA (nginx) |
| postgres | 5432 | PostgreSQL 16 | Shared database for all services |
| pgadmin | 5050 | pgAdmin 4 | Database browser (dev only) |

---

## DNSTwist API (Port 8000)

Core scanning engine. Generates domain permutations using 13 fuzzing algorithms and resolves them via DNS.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/scan` | POST | Scan a domain — full options via JSON body |
| `/scan` | GET | Scan a domain — options via query params |
| `/scan/csv` | GET | Export scan results as CSV download |
| `/permutations` | GET | Generate permutations only (no DNS resolution) |
| `/permutations/list` | GET | Permutations as plain text (one per line) |
| `/fuzzers` | GET | List all available fuzzing algorithms |
| `/dictionaries` | GET | List loaded dictionary files |
| `/api/health` | GET | Health check |

### Scan Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `domain` | string | required | Target domain to scan |
| `registered` | bool | false | Only return domains that resolve in DNS |
| `fuzzers` | string | all | Comma-separated: `bitsquatting,homoglyph,...` |
| `threads` | int | 10 | Parallel DNS workers (1-100) |
| `nameservers` | string | null | Custom DNS servers (comma-separated) |
| `whois` | bool | false | Run WHOIS lookups on results |
| `geoip` | bool | false | GeoIP country lookup |
| `banners` | bool | false | Grab HTTP/SMTP banners |
| `mxcheck` | bool | false | Test if MX can intercept email |
| `lsh` | string | null | Fuzzy hashing: `ssdeep` or `tlsh` |
| `lsh_url` | string | null | Original page URL for hash comparison |
| `useragent` | string | null | Custom User-Agent for HTTP requests |

### Available Fuzzers

`addition` `bitsquatting` `homoglyph` `hyphenation` `insertion` `omission` `repetition` `replacement` `subdomain` `transposition` `vowel-swap` `dictionary` `tld-swap`

### Examples

```bash
# Basic scan — all fuzzers, all permutations
curl "http://localhost:8000/scan?domain=example.com"

# Registered only, specific fuzzers
curl "http://localhost:8000/scan?domain=example.com&registered=true&fuzzers=homoglyph,bitsquatting"

# Full scan with banners and WHOIS
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","registered":true,"whois":true,"banners":true,"geoip":true}'

# Export to CSV
curl "http://localhost:8000/scan/csv?domain=example.com&registered=true" -o results.csv
```

---

## Orchestrator API (Port 8001)

Central hub that coordinates dnstwist scans, enriches results with WHOIS via who-dat, and stores everything in PostgreSQL.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | POST | Submit domains for background scanning |
| `/api/status` | GET | Check scan task progress |
| `/api/health` | GET | Health check (includes DB status + domain count) |

### POST `/api/scan`

Submit one or more domains for typosquatting scanning.

**Request:**
```json
{
  "customer": "AcmeCorp",
  "domains": ["acme.com", "acmecorp.com"],
  "registered": true,
  "fuzzers": "bitsquatting,homoglyph",
  "enrich_whois": true
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `customer` | string | required | Customer name (groups results) |
| `domains` | string[] | required | Seed domains to scan |
| `registered` | bool | true | Only store domains that resolve |
| `fuzzers` | string | all | Comma-separated fuzzer list |
| `enrich_whois` | bool | true | Enrich results with WHOIS via who-dat |

**Response:**
```json
{
  "status": "scanning",
  "task_id": "uuid",
  "customer": "AcmeCorp",
  "domains": ["acme.com", "acmecorp.com"],
  "enrich_whois": true
}
```

### GET `/api/status`

```bash
# All tasks
curl "http://localhost:8001/api/status"

# Tasks for a specific customer
curl "http://localhost:8001/api/status?customer=AcmeCorp"
```

**Response:**
```json
{
  "total": 2,
  "tasks": [
    {
      "id": "uuid",
      "customer": "AcmeCorp",
      "domain": "acme.com",
      "status": "completed",
      "submitted_at": "2026-03-10T02:00:00Z",
      "completed_at": "2026-03-10T02:03:45Z",
      "domains_found": 142,
      "error": null
    }
  ]
}
```

---

## WhoisDS NRD API (Port 8002)

Downloads Newly Registered Domains (NRD) files from whoisds.com and searches them for customer keywords. Matches are stored in PostgreSQL.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/search_keywords` | POST | Download NRD file + search for keywords |
| `/api/health` | GET | Health check |

### POST `/api/search_keywords`

**Request:**
```json
{
  "Customer": "AcmeCorp",
  "Keywords": ["acme", "acmecorp", "acme-corp"],
  "date": "2026-03-10",
  "enrich_whois": true,
  "pass_to_dnstwist": false,
  "dnstwist_registered": true,
  "dnstwist_enrich_whois": false,
  "dnstwist_fuzzers": "bitsquatting"
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `Customer` | string | required | Customer name |
| `Keywords` | string[] | required | Keywords to search in NRD |
| `date` | string | required | NRD date (`YYYY-MM-DD`) |
| `enrich_whois` | bool | false | Enrich matches with WHOIS via who-dat |
| `pass_to_dnstwist` | bool | false | Send matches to orchestrator for dnstwist scanning |
| `dnstwist_registered` | bool | true | (if pass_to_dnstwist) Only registered results |
| `dnstwist_enrich_whois` | bool | false | (if pass_to_dnstwist) Enrich dnstwist results with WHOIS |
| `dnstwist_fuzzers` | string | bitsquatting | (if pass_to_dnstwist) Comma-separated fuzzers |

**Response:**
```json
{
  "status": "completed",
  "customer": "AcmeCorp",
  "date": "2026-03-10",
  "keywords": ["acme", "acmecorp"],
  "total_nrd_matches": 15,
  "stored_in_db": 12,
  "matches": ["acme-solutions.com", "acmecorps.net", "..."],
  "nrd_whois_enrichment": "completed",
  "dnstwist_scan": "skipped"
}
```

---

## Who-Dat WHOIS API (Port 8080)

Go-based WHOIS/RDAP lookup service. Tries WHOIS protocol first, falls back to RDAP if parsing fails.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/{domain}` | GET | WHOIS lookup for a single domain |
| `/multi?domains=a.com,b.com` | GET | WHOIS lookup for multiple domains |

### Examples

```bash
# Single domain
curl "http://localhost:8080/example.com"

# Multiple domains
curl "http://localhost:8080/multi?domains=example.com,google.com"
```

### Response

```json
{
  "domain": {
    "domain": "example.com",
    "name": "example",
    "extension": "com",
    "status": ["clientTransferProhibited"],
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "created_date": "1995-08-14T04:00:00Z",
    "updated_date": "2024-08-14T07:01:44Z",
    "expiration_date": "2025-08-13T04:00:00Z",
    "dnssec": true
  },
  "registrar": {
    "name": "RESERVED-Internet Assigned Numbers Authority",
    "organization": "IANA"
  },
  "registrant": { "name": "...", "country": "US" },
  "administrative": { "..." },
  "technical": { "..." },
  "billing": null
}
```

---

## Frontend API (Port 8003)

Dashboard backend. Reads domains from PostgreSQL, manages customer configuration, and tracks triage actions.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/domains` | GET | Paginated domain list (with filters) |
| `/api/domains/{domain}/action` | POST | Mark domain as blocked/safe/takedown |
| `/api/domains/{domain}/action` | DELETE | Reset (undo) domain action |
| `/api/customers` | POST | Create or update a customer |
| `/api/customers/{name}` | GET | Get customer details |
| `/api/customers/{name}/config` | GET | Get customer keywords + monitored domains |
| `/api/customers/{name}/keywords` | POST | Add a keyword |
| `/api/customers/{name}/keywords/{kw}` | DELETE | Remove a keyword |
| `/api/customers/{name}/domains` | POST | Add a monitored domain |
| `/api/customers/{name}/domains/{d}` | DELETE | Remove a monitored domain |
| `/api/health` | GET | Health check |

### GET `/api/domains`

```bash
curl "http://localhost:8003/api/domains?customers=AcmeCorp&action_status=pending&page=1&page_size=25&sort_field=first_seen_at&sort_order=desc"
```

| Param | Type | Default | Description |
|---|---|---|---|
| `customers` | string | required | Comma-separated customer names |
| `action_status` | string | null | Filter: `pending`, `blocked`, `safe`, `takedown_requested` |
| `page` | int | 1 | Page number |
| `page_size` | int | 25 | Rows per page |
| `sort_field` | string | first_seen_at | Sort column |
| `sort_order` | string | desc | `asc` or `desc` |

### POST `/api/domains/{domain}/action`

```bash
curl -X POST "http://localhost:8003/api/domains/acme-phish.com/action" \
  -H "Content-Type: application/json" \
  -d '{"action": "blocked", "customer": "AcmeCorp"}'
```

Valid actions: `blocked`, `safe`, `takedown_requested`

---

## Frontend Dashboard (Port 3000)

Vue 3 + PrimeVue single-page application served by nginx.

**URL:** `http://localhost:3000/?customers=AcmeCorp`

### Features

- Paginated domain table with sorting
- Filter by status: pending, blocked, safe, takedown requested, all
- Expand row to see WHOIS details (registrar, registrant, country, created/updated/expires)
- One-click actions: block, mark safe, request takedown, undo
- Customer configuration dialog (manage keywords + monitored domains)
- Source badges: dnstwist (blue) / whoisds (amber)
- Fuzzer type display per domain

### Columns Displayed

| Column | Description |
|---|---|
| Domain | The suspicious domain name |
| Source | `dnstwist` or `whoisds` |
| Fuzzer | Algorithm that generated it (bitsquatting, homoglyph, etc.) |
| First Seen | When the domain was first discovered |
| Registered | WHOIS creation date |
| Registrar | WHOIS registrar name |
| Status | Action taken: pending / blocked / safe / takedown |
| Actions | Buttons to mark or undo |

### Expanded Row (WHOIS Details)

| Field | Description |
|---|---|
| Registrar | Domain registrar name |
| Registrant | Registrant name (often redacted) |
| Country | Registrant country |
| Created | Domain registration date |
| Updated | Last WHOIS update |
| Expires | Domain expiry date |

---

## Database Schema

All services share a single PostgreSQL database (`typosquatting`).

### `domains` — main results table

| Column | Type | Description |
|---|---|---|
| `domain` | TEXT PK | The discovered domain |
| `customer` | TEXT | Customer this belongs to |
| `original_domain` | TEXT | Seed domain (for dnstwist scans) |
| `source` | TEXT | `dnstwist` or `whoisds` |
| `fuzzer` | TEXT | Fuzzing algorithm used |
| `first_seen_at` | TIMESTAMPTZ | First discovery timestamp |
| `last_updated_at` | TIMESTAMPTZ | Last update timestamp |
| `whois_registrar` | TEXT | WHOIS registrar name |
| `whois_created` | TEXT | Domain creation date |
| `whois_updated` | TEXT | WHOIS last updated |
| `whois_expires` | TEXT | Domain expiry date |
| `whois_registrant` | TEXT | Registrant name |
| `whois_country` | TEXT | Registrant country |
| `dns_a` | TEXT | A records (JSON) |
| `dns_aaaa` | TEXT | AAAA records (JSON) |
| `dns_mx` | TEXT | MX records (JSON) |
| `dns_ns` | TEXT | NS records (JSON) |
| `geoip_country` | TEXT | GeoIP country |
| `http_banner` | TEXT | HTTP Server header |
| `smtp_banner` | TEXT | SMTP greeting banner |
| `lsh_ssdeep` | TEXT | SSDeep fuzzy hash |
| `lsh_tlsh` | TEXT | TLSH fuzzy hash |
| `mx_can_intercept` | INTEGER | 1 if MX can intercept email |
| `nrd_date` | TEXT | NRD file date (whoisds source) |
| `nrd_keyword_matched` | TEXT | Keyword that matched (whoisds source) |
| `whodat_raw` | TEXT | Full who-dat JSON response |
| `action_status` | TEXT | `pending` / `blocked` / `safe` / `takedown_requested` |
| `action_taken_at` | TIMESTAMPTZ | When action was taken |
| `action_taken_by` | TEXT | Who took the action |

### `tasks` — scan job tracking (orchestrator-api)

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | Task UUID |
| `customer` | TEXT | Customer name |
| `domain` | TEXT | Seed domain being scanned |
| `status` | TEXT | `pending` / `scanning` / `completed` / `failed` |
| `submitted_at` | TIMESTAMPTZ | When task was created |
| `completed_at` | TIMESTAMPTZ | When task finished |
| `domains_found` | INTEGER | Number of results |
| `error` | TEXT | Error message if failed |

### `customers` — customer registry (frontend-api)

| Column | Type | Description |
|---|---|---|
| `name` | TEXT PK | Customer name |
| `tier` | TEXT | `standard` or `premium` |
| `active` | BOOLEAN | Is customer active |
| `created_at` | TIMESTAMPTZ | Created timestamp |
| `updated_at` | TIMESTAMPTZ | Updated timestamp |

### `customer_keywords` — monitored keywords

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | Auto-increment ID |
| `customer_name` | TEXT FK | References customers(name) |
| `keyword` | TEXT | Keyword to search in NRD |

### `customer_domains` — monitored domains

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | Auto-increment ID |
| `customer_name` | TEXT FK | References customers(name) |
| `domain` | TEXT | Domain to scan with dnstwist |

---

## Environment Variables

| Variable | Default | Used By | Description |
|---|---|---|---|
| `POSTGRES_DB` | `typosquatting` | postgres | Database name |
| `POSTGRES_USER` | `postgres` | postgres | Database user |
| `POSTGRES_PASSWORD` | `postgres` | postgres | Database password |
| `DATABASE_URL` | `postgresql://postgres:postgres@postgres:5432/typosquatting` | orchestrator, whoisds, frontend-api | PostgreSQL connection string |
| `DNSTWIST_API_URL` | `http://dnstwist-api:8000` | orchestrator | DNSTwist engine URL |
| `WHO_DAT_URL` | `http://who-dat:8080` | orchestrator, whoisds | Who-Dat WHOIS service URL |
| `ORCHESTRATOR_URL` | `http://orchestrator-api:8001` | whoisds | Orchestrator URL (for pass_to_dnstwist) |
| `WHOISDS_EMAIL` | *(empty)* | whoisds | WhoisDS login email |
| `WHOISDS_PASSWORD` | *(empty)* | whoisds | WhoisDS login password |
| `PGADMIN_DEFAULT_EMAIL` | `admin@admin.com` | pgadmin | pgAdmin login email |
| `PGADMIN_DEFAULT_PASSWORD` | `admin` | pgadmin | pgAdmin login password |

All inter-service communication uses the Docker network (`typosquatting-net`). No external URLs needed for local development.

---

## Directory Structure

```
DomainTyposquatting/
├── docker-compose.yml            # All 8 services
├── .env.example                  # Environment template
├── .env                          # Your config (git-ignored)
├── InstalledNRD/                 # NRD file storage (bind mount)
│
├── dnstwist-api/                 # Scan engine
│   ├── Dockerfile
│   ├── api.py                    # FastAPI app — /scan, /fuzzers, etc.
│   ├── requirements.txt
│   └── dictionaries/             # TLD + English word lists
│
├── orchestrator-api/             # Orchestration hub
│   ├── Dockerfile
│   ├── app.py                    # FastAPI app — /api/scan, /api/status
│   └── requirements.txt
│
├── whoisds-api/                  # NRD keyword search
│   ├── Dockerfile
│   ├── app.py                    # FastAPI app — /api/search_keywords
│   └── requirements.txt
│
├── who-dat/                      # WHOIS/RDAP service (Go)
│   ├── Dockerfile                # Multi-stage: Node + Go + Alpine
│   ├── main.go                   # HTTP server + embedded frontend
│   ├── go.mod
│   ├── api/                      # HTTP handlers
│   │   ├── index.go              # GET /{domain}
│   │   └── multi.go              # GET /multi?domains=...
│   └── lib/                      # Business logic
│       ├── whois.go              # WHOIS lookup + RDAP fallback
│       ├── rdap.go               # RDAP protocol implementation
│       ├── multi.go              # Concurrent multi-domain lookup
│       └── middleware.go         # Optional API key auth
│
├── frontend-api/                 # Dashboard backend
│   ├── Dockerfile
│   ├── app.py                    # FastAPI app — /api/domains, /api/customers
│   └── requirements.txt
│
└── frontend/                     # Dashboard SPA
    ├── Dockerfile                # Node build + nginx serve
    ├── index.html
    ├── nginx.conf
    ├── package.json
    └── src/
        ├── App.vue
        ├── types.ts              # TypeScript interfaces
        └── components/
            ├── DomainDashboard.vue   # Main dashboard view
            └── ConfigDialog.vue      # Customer config modal
```
