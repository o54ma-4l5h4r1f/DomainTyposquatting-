# Domain Typosquatting Detection Platform

Containerised microservice platform that detects domain typosquatting and newly registered lookalike domains, enriches them with WHOIS data, and surfaces results on a customer dashboard for triage.

## How It Works

```
 Schedule / Logic App
        │
        ▼
 ┌─────────────────────────────────────────────────────────┐
 │                    Processing Layer                      │
 │                                                          │
 │   ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
 │   │ Orchestrator  │───▶│  DNSTwist    │    │ Who-Dat  │  │
 │   │   API (8001)  │    │  API (8000)  │    │  (8080)  │  │
 │   │               │◀───│              │    │ WHOIS /  │  │
 │   │  scan + store │    │ 13 fuzzers   │    │ RDAP     │  │
 │   └──────┬────────┘    └──────────────┘    └────▲─────┘  │
 │          │                                      │        │
 │   ┌──────┴────────┐                             │        │
 │   │ WhoisDS API   │─────────────────────────────┘        │
 │   │   (8002)      │  enrich matches with WHOIS           │
 │   │ NRD keyword   │                                      │
 │   │ search        │                                      │
 │   └──────┬────────┘                                      │
 └──────────┼───────────────────────────────────────────────┘
            │
            ▼
 ┌──────────────────────┐
 │   PostgreSQL (5432)  │  shared database
 │   domains │ tasks    │
 │   customers │ keywords│
 └──────────┬───────────┘
            │
            ▼
 ┌─────────────────────────────────────────────┐
 │                Dashboard Layer               │
 │   ┌────────────────┐    ┌────────────────┐  │
 │   │  Frontend API  │    │   Frontend     │  │
 │   │    (8003)      │◀───│  Vue 3 (3000)  │  │
 │   │  read/write DB │    │  PrimeVue SPA  │  │
 │   └────────────────┘    └────────────────┘  │
 └─────────────────────────────────────────────┘
```

## Trigger and Scheduling

Scans can be triggered on a schedule or on demand. The recommended approach for production is an **Azure Logic App** (or any HTTP-capable scheduler) that calls the processing APIs on a recurring basis.

### Scheduling Flow

```
┌──────────────┐     ┌──────────────────────────────────────┐     ┌───────────┐
│  Logic App   │     │         Processing APIs               │     │ Dashboard │
│  (Scheduler) │     │                                       │     │           │
│              │     │                                       │     │           │
│  Recurrence  │────▶│  1. POST /api/scan (orchestrator)    │     │           │
│  (daily /    │     │     → dnstwist scans each domain      │     │           │
│   weekly)    │     │     → who-dat enriches with WHOIS     │     │           │
│              │     │     → results stored in PostgreSQL    │     │           │
│              │────▶│  2. POST /api/search_keywords         │     │           │
│              │     │     (whoisds-api)                      │     │           │
│              │     │     → downloads NRD file for today     │     │           │
│              │     │     → searches for customer keywords   │     │           │
│              │     │     → stores matches in PostgreSQL     │     │           │
│              │     │                                       │     │           │
│              │     │         ┌──────────────┐              │     │           │
│              │     │         │  PostgreSQL   │──────────────│────▶│  Customer │
│              │     │         │  (shared DB)  │              │     │  sees new │
│              │     │         └──────────────┘              │     │  results  │
└──────────────┘     └──────────────────────────────────────┘     └───────────┘
```

### Step 1 — Typosquatting Scan (Orchestrator API)

The Logic App sends a POST request to the orchestrator with the customer's monitored domains:

```http
POST http://<host>:8001/api/scan
Content-Type: application/json

{
  "customer": "AcmeCorp",
  "domains": ["acme.com", "acmecorp.com"],
  "registered": true,
  "enrich_whois": true
}
```

The orchestrator:
1. Creates a background task for each domain
2. Calls dnstwist-api to generate and resolve domain permutations
3. Filters to only registered (live) domains
4. Enriches each result with WHOIS data via who-dat
5. Stores results in the `domains` table (deduplicated)

### Step 2 — NRD Keyword Search (WhoisDS API)

The Logic App sends a POST request to search newly registered domains:

```http
POST http://<host>:8002/api/search_keywords
Content-Type: application/json

{
  "Customer": "AcmeCorp",
  "Keywords": ["acme", "acmecorp", "acme-corp"],
  "date": "2026-03-10",
  "enrich_whois": true,
  "pass_to_dnstwist": false
}
```

The whoisds-api:
1. Downloads the NRD file for the given date (from whoisds.com)
2. Searches every newly registered domain for keyword matches
3. Stores matches in the `domains` table with source `whoisds`
4. Optionally enriches with WHOIS data via who-dat

### Step 3 — Results Appear on the Dashboard

No extra step needed. The frontend reads from the same PostgreSQL database:

1. Customer opens the dashboard at `http://<host>:3000/?customers=AcmeCorp`
2. The Vue frontend calls `GET /api/domains?customers=AcmeCorp`
3. All newly discovered domains from both scans appear immediately
4. Each domain shows: source, fuzzer type, first seen date, WHOIS registrar, registration date
5. Customer expands a row to see full WHOIS details (registrar, registrant, country, dates)
6. Customer triages each domain: mark as **blocked**, **safe**, or **takedown requested**

### Example Logic App Configuration

| Setting | Value |
|---|---|
| **Trigger** | Recurrence — every day at 02:00 UTC |
| **Action 1** | HTTP POST to orchestrator `/api/scan` for each customer |
| **Action 2** | HTTP POST to whoisds-api `/api/search_keywords` with today's date |
| **Retry policy** | 3 retries, exponential backoff |
| **Timeout** | 10 minutes per action (scans can be slow) |

You can also trigger scans manually by calling the same endpoints from any HTTP client (curl, Postman, etc.).

## Services

| Service | Port | Role |
|---|---|---|
| **dnstwist-api** | 8000 | Domain fuzzing engine (13 algorithms) |
| **orchestrator-api** | 8001 | Scan orchestration, WHOIS enrichment, result storage |
| **whoisds-api** | 8002 | NRD file download and keyword search |
| **who-dat** | 8080 | WHOIS/RDAP lookup service (Go) |
| **frontend-api** | 8003 | Dashboard backend (read/write PostgreSQL) |
| **frontend** | 3000 | Vue 3 + PrimeVue dashboard SPA |
| **postgres** | 5432 | Shared PostgreSQL database |
| **pgadmin** | 5050 | Database admin UI (dev only) |

## Quick Start

```bash
cd DomainTyposquatting
cp .env.example .env        # edit with your settings
docker-compose up --build   # start all 8 services
```

Then open:
- Dashboard: http://localhost:3000/?customers=YourCustomer
- API docs: http://localhost:8001/docs (orchestrator), http://localhost:8002/docs (whoisds)
- pgAdmin: http://localhost:5050 (admin@admin.com / admin)

See [`DomainTyposquatting/README.md`](DomainTyposquatting/README.md) for full API reference, database schema, and environment variables.

## Project Structure

```
DomainTyposquatting/
├── docker-compose.yml        # All 8 services
├── .env.example              # Environment template
├── dnstwist-api/             # Python — domain fuzzing engine
├── orchestrator-api/         # Python — scan orchestration + WHOIS enrichment
├── whoisds-api/              # Python — NRD keyword search
├── who-dat/                  # Go — WHOIS/RDAP lookup service
├── frontend-api/             # Python — dashboard backend
├── frontend/                 # Vue 3 — dashboard SPA
└── InstalledNRD/             # NRD file storage (volume mount)
```
