"""
DNSTwist Orchestrator API - Container App
Central orchestrator for domain typosquatting detection.
Manages a unified domain database that all services enrich.

Database: PostgreSQL (local Docker + Azure Database for PostgreSQL Flexible Server)
Debug UI: pgAdmin at http://localhost:5050

Services:
- dnstwist-api (port 8000)  → scans & sends results via callback
- whoisds-api  (port 8002)  → NRD keyword matches, pushed here
- who-dat      (port 8080)  → WHOIS/RDAP lookups, called by orchestrator

Endpoints:
- POST /api/scan          - Submit domains for scanning
- POST /api/callback      - Receive results from dnstwist API
- POST /api/enrich        - Accept enrichment data from any service
- POST /api/enrich/whois  - Trigger who-dat WHOIS lookup for domain(s)
- GET  /api/status        - Get pending/running scans
- GET  /api/results       - Get enriched domain data for customer
- GET  /api/customers     - List all customers
- GET  /api/domain/{domain} - Get full detail for one domain
- GET  /api/health        - Health check
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import json
import os
import httpx
import psycopg2
import psycopg2.extras
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DNSTwist Orchestrator API",
    description="Central orchestrator with unified domain database. All services enrich one table.",
    version="2.0.0",
)

# === Configuration ===
DNSTWIST_API_URL = os.environ.get("DNSTWIST_API_URL", "http://dnstwist-api:8000")
DNSTWIST_API_KEY = os.environ.get("DNSTWIST_API_KEY", "")
WHO_DAT_URL = os.environ.get("WHO_DAT_URL", "http://who-dat:8080")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/typosquatting"
)

# === PostgreSQL Unified Database ===


def init_db():
    """Initialize the unified domain database (PostgreSQL)."""
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            # --- Tasks table (scan tracking) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    customer TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    submitted_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ
                )
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_customer ON tasks(customer)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)"
            )

            # --- Unified domains table ---
            # One row per unique domain. All services upsert into this table.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    customer TEXT,
                    original_domain TEXT,
                    source TEXT,
                    first_seen_at TIMESTAMPTZ,
                    last_updated_at TIMESTAMPTZ,

                    -- DNSTwist enrichment
                    fuzzer TEXT,
                    dns_a TEXT,
                    dns_aaaa TEXT,
                    dns_mx TEXT,
                    dns_ns TEXT,

                    -- WHOIS enrichment (dnstwist --whois or who-dat)
                    whois_registrar TEXT,
                    whois_created TEXT,
                    whois_updated TEXT,
                    whois_expires TEXT,
                    whois_registrant TEXT,
                    whois_country TEXT,

                    -- GeoIP enrichment
                    geoip_country TEXT,

                    -- Web enrichment
                    http_banner TEXT,
                    smtp_banner TEXT,
                    lsh_ssdeep TEXT,
                    lsh_tlsh TEXT,

                    -- MX check
                    mx_can_intercept INTEGER,

                    -- WhoisDS NRD enrichment
                    nrd_date TEXT,
                    nrd_keyword_matched TEXT,

                    -- Who-dat full RDAP JSON
                    whodat_raw TEXT
                )
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_domains_customer ON domains(customer)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_domains_original ON domains(original_domain)"
            )
        conn.commit()


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# All columns that services can upsert into (excluding PK 'domain')
ALLOWED_COLS = [
    "customer", "original_domain", "source", "first_seen_at", "last_updated_at",
    "fuzzer", "dns_a", "dns_aaaa", "dns_mx", "dns_ns",
    "whois_registrar", "whois_created", "whois_updated", "whois_expires",
    "whois_registrant", "whois_country",
    "geoip_country",
    "http_banner", "smtp_banner", "lsh_ssdeep", "lsh_tlsh",
    "mx_can_intercept",
    "nrd_date", "nrd_keyword_matched",
    "whodat_raw",
]


def upsert_domain(domain_name: str, data: dict):
    """
    Insert or update a domain row using PostgreSQL UPSERT.
    Only non-None values in `data` will overwrite existing columns.
    This allows different services to enrich the same row incrementally.
    """
    now = datetime.now(timezone.utc).isoformat()
    data["last_updated_at"] = now

    # Filter to only columns that have non-None values
    updates = {k: v for k, v in data.items() if k in ALLOWED_COLS and v is not None}
    if not updates:
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            # Build column lists for INSERT
            insert_cols = ["domain"] + list(updates.keys())
            if "first_seen_at" not in updates:
                insert_cols.append("first_seen_at")
                insert_vals = [domain_name] + list(updates.values()) + [now]
            else:
                insert_vals = [domain_name] + list(updates.values())

            placeholders = ", ".join(["%s"] * len(insert_cols))

            # ON CONFLICT: update only the columns being provided (not first_seen_at)
            update_set = ", ".join(
                f"{col} = EXCLUDED.{col}" for col in updates.keys()
            )

            sql = f"""
                INSERT INTO domains ({', '.join(insert_cols)})
                VALUES ({placeholders})
                ON CONFLICT (domain) DO UPDATE SET {update_set}
            """
            cur.execute(sql, insert_vals)


# === Task helpers ===


def add_task(customer: str, domain: str, tracking_id: str):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO tasks (id, customer, domain, status, submitted_at)
                       VALUES (%s, %s, %s, 'pending', %s)
                       ON CONFLICT (id) DO UPDATE SET
                           customer = EXCLUDED.customer,
                           domain = EXCLUDED.domain,
                           status = EXCLUDED.status,
                           submitted_at = EXCLUDED.submitted_at""",
                    (tracking_id, customer, domain, datetime.now(timezone.utc).isoformat()),
                )
    except Exception as e:
        logger.error(f"Failed to add task: {e}")


def complete_task(customer: str, tracking_id: str):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tasks SET status = 'completed', completed_at = %s WHERE id = %s AND customer = %s",
                    (datetime.now(timezone.utc).isoformat(), tracking_id, customer),
                )
    except Exception as e:
        logger.error(f"Failed to complete task: {e}")


def get_pending_tasks(customer: str = None) -> list:
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if customer:
                    cur.execute(
                        "SELECT * FROM tasks WHERE customer = %s AND status = 'pending'",
                        (customer,),
                    )
                else:
                    cur.execute("SELECT * FROM tasks WHERE status = 'pending'")
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"Failed to get pending tasks: {e}")
        return []


# === Who-dat enrichment helper ===


async def enrich_with_whodat(domain_name: str, customer: str = None):
    """
    Call local who-dat service to get WHOIS/RDAP data and upsert into domains table.

    who-dat response format (whoisparser.WhoisInfo):
    {
      "domain": {
        "created_date": "...", "updated_date": "...", "expiration_date": "...",
        "name_servers": [...], "status": [...], "whois_server": "..."
      },
      "registrar": { "name": "...", "organization": "...", ... },
      "registrant": { "name": "...", "country": "...", ... },
      "administrative": { ... },
      "technical": { ... }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{WHO_DAT_URL}/{domain_name}")
            if resp.status_code == 200:
                whodat_data = resp.json()
                enrichment = {"whodat_raw": json.dumps(whodat_data)}
                if customer:
                    enrichment["customer"] = customer

                if isinstance(whodat_data, dict):
                    # Extract domain dates
                    domain_info = whodat_data.get("domain") or {}
                    if isinstance(domain_info, dict):
                        if domain_info.get("created_date"):
                            enrichment["whois_created"] = domain_info["created_date"]
                        if domain_info.get("updated_date"):
                            enrichment["whois_updated"] = domain_info["updated_date"]
                        if domain_info.get("expiration_date"):
                            enrichment["whois_expires"] = domain_info["expiration_date"]

                    # Extract registrar info
                    registrar = whodat_data.get("registrar") or {}
                    if isinstance(registrar, dict):
                        registrar_name = registrar.get("name") or registrar.get("organization")
                        if registrar_name:
                            enrichment["whois_registrar"] = registrar_name

                    # Extract registrant info
                    registrant = whodat_data.get("registrant") or {}
                    if isinstance(registrant, dict):
                        registrant_name = registrant.get("name") or registrant.get("organization")
                        if registrant_name:
                            enrichment["whois_registrant"] = registrant_name
                        if registrant.get("country"):
                            enrichment["whois_country"] = registrant["country"]

                upsert_domain(domain_name, enrichment)
                logger.info(f"Who-dat enrichment completed for {domain_name}")
                return True
            else:
                logger.warning(f"Who-dat returned {resp.status_code} for {domain_name}")
                return False
    except Exception as e:
        logger.error(f"Who-dat enrichment failed for {domain_name}: {e}")
        return False


# === Init DB on startup ===
@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"Orchestrator started. dnstwist API: {DNSTWIST_API_URL}")
    logger.info(f"Who-dat URL: {WHO_DAT_URL}")
    logger.info(f"Database: {DATABASE_URL.split('@')[-1]}")  # log host only, not creds


# === Request Models ===


class ScanRequest(BaseModel):
    customer: str = Field(..., description="Customer name")
    domains: List[str] = Field(..., description="List of domains to scan")
    registered: bool = Field(True, description="Only show registered domains")
    fuzzers: Optional[str] = Field(None, description="Comma-separated fuzzers, or 'all'")
    whois: bool = Field(False, description="Perform WHOIS lookups via dnstwist")
    geoip: bool = Field(False, description="GeoIP lookup")
    mxcheck: bool = Field(False, description="Check MX for email interception")
    banners: bool = Field(False, description="Grab HTTP/SMTP banners")
    enrich_whois: bool = Field(True, description="Auto-enrich results with who-dat WHOIS lookup")
    callback_url: Optional[str] = Field(None, description="Override callback URL")


class EnrichRequest(BaseModel):
    """Generic enrichment payload. Any service can push domain data."""
    customer: Optional[str] = Field(None, description="Customer name")
    domains: List[dict] = Field(
        ...,
        description="List of domain enrichment objects. Each must have 'domain' key.",
        example=[{"domain": "examp1e.com", "nrd_date": "2026-02-10", "nrd_keyword_matched": "example"}],
    )
    source: Optional[str] = Field(None, description="Source service name")


class WhoisEnrichRequest(BaseModel):
    domains: List[str] = Field(..., description="Domain names to enrich with WHOIS data")
    customer: Optional[str] = Field(None, description="Customer name")


# === API Endpoints ===


@app.post("/api/scan", tags=["Scanning"])
async def submit_scan(request: ScanRequest, req: Request):
    """
    Submit domains for scanning.

    The orchestrator sends each domain to the dnstwist-api in async mode.
    Results come back via /api/callback.

    **Example - scan with all fuzzers + WHOIS + GeoIP:**
    ```json
    {
        "customer": "AcmeCorp",
        "domains": ["example.com", "acme.com"],
        "registered": true,
        "fuzzers": "all",
        "whois": true,
        "geoip": true,
        "mxcheck": true,
        "banners": true,
        "enrich_whois": true
    }
    ```

    **Example - specific fuzzers (multi-select):**
    ```json
    {
        "customer": "AcmeCorp",
        "domains": ["example.com"],
        "fuzzers": "homoglyph,bitsquatting,addition,tld-swap"
    }
    ```
    """
    if not DNSTWIST_API_URL:
        raise HTTPException(status_code=500, detail="DNSTWIST_API_URL not configured")

    if not request.domains:
        raise HTTPException(status_code=400, detail="domains must be a non-empty list")

    # Build callback URL
    callback_url = request.callback_url
    if not callback_url:
        base_url = str(req.base_url).rstrip("/")
        callback_url = f"{base_url}/api/callback"

    tracking_ids = []
    submitted = []
    errors = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for domain in request.domains:
            tracking_id = str(uuid.uuid4())
            tracking_ids.append(tracking_id)

            payload = {
                "domain": domain,
                "registered": request.registered,
                "forward": True,
                "async_mode": True,
                "callback_url": callback_url,
                "customer": request.customer,
                "tracking_id": tracking_id,
            }

            if request.fuzzers:
                payload["fuzzers"] = request.fuzzers
            if request.whois:
                payload["whois"] = True
            if request.geoip:
                payload["geoip"] = True
            if request.mxcheck:
                payload["mxcheck"] = True
            if request.banners:
                payload["banners"] = True

            # Store enrich_whois preference in metadata so callback knows
            payload["metadata"] = {"enrich_whois": request.enrich_whois}

            try:
                headers = {"Content-Type": "application/json"}
                if DNSTWIST_API_KEY:
                    headers["X-API-Key"] = DNSTWIST_API_KEY

                response = await client.post(
                    f"{DNSTWIST_API_URL}/scan",
                    json=payload,
                    headers=headers,
                )

                if response.status_code == 200:
                    add_task(request.customer, domain, tracking_id)
                    submitted.append(domain)
                    logger.info(f"Queued scan for {domain}, tracking_id: {tracking_id}")
                else:
                    errors.append({
                        "domain": domain,
                        "error": f"API returned {response.status_code}: {response.text}",
                    })

            except Exception as e:
                logger.error(f"Error submitting {domain}: {str(e)}")
                errors.append({"domain": domain, "error": str(e)})

    result = {
        "status": "submitted",
        "customer": request.customer,
        "domains_submitted": len(submitted),
        "tracking_ids": tracking_ids,
        "callback_url": callback_url,
    }

    if errors:
        result["errors"] = errors

    return result


@app.post("/api/callback", tags=["Callback"])
async def receive_callback(req: Request):
    """
    Receive results from dnstwist API callback.
    Each domain from the scan is upserted into the unified domains table
    with all available enrichment data (DNS, WHOIS, GeoIP, banners, etc.).
    """
    logger.info("Callback received from dnstwist API")

    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    customer = body.get("customer")
    tracking_id = body.get("tracking_id")
    source_domain = body.get("domain")
    results = body.get("results", [])
    metadata = body.get("metadata", {})
    enrich_whois = metadata.get("enrich_whois", False) if isinstance(metadata, dict) else False

    if not customer:
        raise HTTPException(status_code=400, detail="customer field is required")

    domains_stored = 0
    domains_to_enrich = []

    for result in results:
        fuzzer = result.get("fuzzer", "")
        domain_name = result.get("domain", "")

        # Skip the original domain entry
        if fuzzer == "*original" or domain_name == source_domain:
            continue
        if not domain_name:
            continue

        # Build enrichment data from dnstwist result
        enrichment = {
            "customer": customer,
            "original_domain": source_domain,
            "source": "dnstwist",
            "fuzzer": fuzzer,
        }

        # DNS records (store as JSON strings for lists)
        dns_a = result.get("dns_a")
        if dns_a:
            enrichment["dns_a"] = json.dumps(dns_a) if isinstance(dns_a, list) else str(dns_a)
        dns_aaaa = result.get("dns_aaaa")
        if dns_aaaa:
            enrichment["dns_aaaa"] = json.dumps(dns_aaaa) if isinstance(dns_aaaa, list) else str(dns_aaaa)
        dns_mx = result.get("dns_mx")
        if dns_mx:
            enrichment["dns_mx"] = json.dumps(dns_mx) if isinstance(dns_mx, list) else str(dns_mx)
        dns_ns = result.get("dns_ns")
        if dns_ns:
            enrichment["dns_ns"] = json.dumps(dns_ns) if isinstance(dns_ns, list) else str(dns_ns)

        # WHOIS data from dnstwist --whois
        whois_created = result.get("whois_created")
        if whois_created:
            enrichment["whois_created"] = whois_created
        whois_updated = result.get("whois_updated")
        if whois_updated:
            enrichment["whois_updated"] = whois_updated
        whois_registrar = result.get("whois_registrar")
        if whois_registrar:
            enrichment["whois_registrar"] = whois_registrar

        # GeoIP
        geoip = result.get("geoip")
        if geoip:
            enrichment["geoip_country"] = geoip

        # Banners
        http_banner = result.get("banner_http")
        if http_banner:
            enrichment["http_banner"] = http_banner
        smtp_banner = result.get("banner_smtp")
        if smtp_banner:
            enrichment["smtp_banner"] = smtp_banner

        # Fuzzy hashing
        ssdeep = result.get("ssdeep")
        if ssdeep:
            enrichment["lsh_ssdeep"] = ssdeep
        tlsh = result.get("tlsh")
        if tlsh:
            enrichment["lsh_tlsh"] = tlsh

        # MX interception check
        mx_spy = result.get("mx_spy")
        if mx_spy is not None:
            enrichment["mx_can_intercept"] = 1 if mx_spy else 0

        upsert_domain(domain_name, enrichment)
        domains_stored += 1

        if enrich_whois:
            domains_to_enrich.append(domain_name)

    logger.info(f"Stored {domains_stored} domains for {customer} (source: {source_domain})")

    # Complete the task
    if tracking_id:
        complete_task(customer, tracking_id)

    # Auto-enrich with who-dat in background (non-blocking, best effort)
    if domains_to_enrich:
        import asyncio

        async def _enrich_batch():
            for d in domains_to_enrich[:50]:  # cap at 50 to avoid overload
                await enrich_with_whodat(d, customer)

        asyncio.ensure_future(_enrich_batch())

    return {
        "status": "ok",
        "customer": customer,
        "source_domain": source_domain,
        "domains_stored": domains_stored,
        "whois_enrichment_queued": len(domains_to_enrich) if enrich_whois else 0,
    }


@app.post("/api/enrich", tags=["Enrichment"])
async def enrich_domains(request: EnrichRequest):
    """
    Generic enrichment endpoint. Any service can push domain data here.

    Used by whoisds-api to push NRD keyword matches, or any external source.

    **Example from whoisds-api:**
    ```json
    {
        "customer": "AcmeCorp",
        "source": "whoisds",
        "domains": [
            {"domain": "acmecorp-login.com", "nrd_date": "2026-02-10", "nrd_keyword_matched": "acmecorp"},
            {"domain": "acme-secure.com", "nrd_date": "2026-02-10", "nrd_keyword_matched": "acme"}
        ]
    }
    ```
    """
    count = 0
    for item in request.domains:
        domain_name = item.get("domain")
        if not domain_name:
            continue

        enrichment = {k: v for k, v in item.items() if k != "domain"}
        if request.customer:
            enrichment["customer"] = request.customer
        if request.source:
            enrichment["source"] = request.source

        upsert_domain(domain_name, enrichment)
        count += 1

    return {"status": "ok", "domains_enriched": count}


@app.post("/api/enrich/whois", tags=["Enrichment"])
async def enrich_whois(request: WhoisEnrichRequest):
    """
    Trigger who-dat WHOIS/RDAP lookup for specific domains.
    Results are stored in the unified domains table.

    **Example:**
    ```json
    {
        "domains": ["examp1e.com", "exampl3.com"],
        "customer": "AcmeCorp"
    }
    ```
    """
    results = []
    for domain_name in request.domains:
        success = await enrich_with_whodat(domain_name, request.customer)
        results.append({"domain": domain_name, "enriched": success})

    return {"status": "ok", "results": results}


@app.get("/api/status", tags=["Status"])
async def get_status(customer: Optional[str] = None):
    """Get pending/running scan tasks."""
    pending_tasks = get_pending_tasks(customer)

    by_customer = {}
    for task in pending_tasks:
        cust = task.get("customer", "unknown")
        if cust not in by_customer:
            by_customer[cust] = []
        by_customer[cust].append({
            "domain": task.get("domain"),
            "tracking_id": task.get("id"),
            "submitted_at": task.get("submitted_at"),
            "status": task.get("status"),
        })

    result = {"pending_count": len(pending_tasks), "by_customer": by_customer}
    if customer:
        result["filter"] = {"customer": customer}

    return result


@app.get("/api/results", tags=["Results"])
async def get_results(
    customer: str,
    original_domain: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
):
    """
    Get enriched domain data for a customer from the unified database.

    Query params:
    - customer (required): Customer name
    - original_domain (optional): Filter by the domain that was scanned
    - source (optional): Filter by source (dnstwist, whoisds, who-dat)
    - limit / offset: Pagination
    """
    conditions = ["customer = %s"]
    params: list = [customer]

    if original_domain:
        conditions.append("original_domain = %s")
        params.append(original_domain)
    if source:
        conditions.append("source = %s")
        params.append(source)

    where_clause = " AND ".join(conditions)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT COUNT(*) as cnt FROM domains WHERE {where_clause}", params
            )
            count_row = cur.fetchone()
            total = count_row["cnt"] if count_row else 0

            cur.execute(
                f"SELECT * FROM domains WHERE {where_clause} ORDER BY last_updated_at DESC LIMIT %s OFFSET %s",
                params + [limit, offset],
            )
            domains = [dict(r) for r in cur.fetchall()]

    # Serialize any datetime objects to ISO strings for JSON response
    for d in domains:
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()

    return {
        "customer": customer,
        "total": total,
        "limit": limit,
        "offset": offset,
        "domains": domains,
    }


@app.get("/api/customers", tags=["Customers"])
async def list_customers():
    """List all customers with domain counts."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT customer, COUNT(*) as domain_count FROM domains WHERE customer IS NOT NULL GROUP BY customer ORDER BY customer"
            )
            rows = cur.fetchall()

    customers = [{"customer": r["customer"], "domain_count": r["domain_count"]} for r in rows]

    return {
        "customers": customers,
        "count": len(customers),
    }


@app.get("/api/domain/{domain}", tags=["Results"])
async def get_domain_detail(domain: str):
    """Get full enrichment detail for a single domain."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM domains WHERE domain = %s", (domain,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")

    result = dict(row)
    for k, v in result.items():
        if isinstance(v, datetime):
            result[k] = v.isoformat()
    return result


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    domain_count = 0
    db_ok = False
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM domains")
                row = cur.fetchone()
                domain_count = row[0] if row else 0
                db_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if db_ok else "degraded",
        "service": "dnstwist-orchestrator",
        "version": "2.0.0",
        "database": "connected" if db_ok else "disconnected",
        "dnstwist_api_url": DNSTWIST_API_URL,
        "who_dat_url": WHO_DAT_URL,
        "total_domains_in_db": domain_count,
    }


@app.get("/", tags=["Health"])
async def root():
    """Root health check."""
    return {
        "status": "ok",
        "service": "dnstwist-orchestrator",
        "version": "2.0.0",
        "docs": "/docs",
        "debug_db": "http://localhost:5050 (pgAdmin)",
    }
