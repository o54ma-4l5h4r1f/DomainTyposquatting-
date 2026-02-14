"""
DNSTwist Orchestrator API - Container App
Central orchestrator for domain typosquatting detection.
Manages a unified domain database that all services enrich.

Database: PostgreSQL (local Docker + Azure Database for PostgreSQL Flexible Server)
Debug UI: pgAdmin at http://localhost:5050

Architecture:
- POST /api/scan calls dnstwist-api synchronously, stores results in DB,
  then fires background who-dat enrichment if enrich_whois=true.
- WhoisDS-api writes NRD matches directly to PostgreSQL.
- who-dat is a stateless lookup API - callers write results to DB themselves.
- No callbacks. Every service writes to the DB independently.

Endpoints:
- POST /api/scan              - Submit domains for scanning
- POST /api/enrich            - Accept enrichment data from any service
- POST /api/enrich/whois      - Trigger who-dat WHOIS lookup for domain(s)
- GET  /api/status            - Get pending/running scans
- GET  /api/results           - Get enriched domain data for customer
- GET  /api/customers         - List all customers
- GET  /api/domain/{domain}   - Get full detail for one domain
- GET  /api/health            - Health check
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
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
                    completed_at TIMESTAMPTZ,
                    domains_found INTEGER DEFAULT 0,
                    error TEXT
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
            # domain is the primary key — every row is unique per domain.
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

                    -- WHOIS enrichment (from who-dat RDAP/WHOIS)
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

                    -- Fuzzy hash (ssdeep / tlsh)
                    lsh_ssdeep TEXT,
                    lsh_tlsh TEXT,

                    -- MX interception check
                    mx_can_intercept INTEGER,

                    -- WhoisDS NRD enrichment
                    nrd_date TEXT,
                    nrd_keyword_matched TEXT,

                    -- Who-dat full RDAP/WHOIS raw JSON
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
    """
    now = datetime.now(timezone.utc).isoformat()
    data["last_updated_at"] = now

    updates = {k: v for k, v in data.items() if k in ALLOWED_COLS and v is not None}
    if not updates:
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            insert_cols = ["domain"] + list(updates.keys())
            if "first_seen_at" not in updates:
                insert_cols.append("first_seen_at")
                insert_vals = [domain_name] + list(updates.values()) + [now]
            else:
                insert_vals = [domain_name] + list(updates.values())

            placeholders = ", ".join(["%s"] * len(insert_cols))

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
                       VALUES (%s, %s, %s, 'scanning', %s)
                       ON CONFLICT (id) DO UPDATE SET
                           customer = EXCLUDED.customer,
                           domain = EXCLUDED.domain,
                           status = EXCLUDED.status,
                           submitted_at = EXCLUDED.submitted_at""",
                    (tracking_id, customer, domain, datetime.now(timezone.utc).isoformat()),
                )
    except Exception as e:
        logger.error(f"Failed to add task: {e}")


def complete_task(tracking_id: str, domains_found: int = 0, error: str = None):
    try:
        status = "failed" if error else "completed"
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE tasks SET status = %s, completed_at = %s,
                       domains_found = %s, error = %s WHERE id = %s""",
                    (status, datetime.now(timezone.utc).isoformat(),
                     domains_found, error, tracking_id),
                )
    except Exception as e:
        logger.error(f"Failed to complete task: {e}")


def get_tasks(customer: str = None, status_filter: str = None) -> list:
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                conditions = []
                params = []
                if customer:
                    conditions.append("customer = %s")
                    params.append(customer)
                if status_filter:
                    conditions.append("status = %s")
                    params.append(status_filter)

                where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
                cur.execute(
                    f"SELECT * FROM tasks {where} ORDER BY submitted_at DESC", params
                )
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"Failed to get tasks: {e}")
        return []


# === Who-dat enrichment helper ===


def enrich_with_whodat(domain_name: str, customer: str = None):
    """
    Call who-dat to get WHOIS/RDAP data and upsert into domains table.
    Synchronous — designed to run inside background tasks.
    """
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{WHO_DAT_URL}/{domain_name}")
            if resp.status_code != 200:
                logger.warning(f"Who-dat returned {resp.status_code} for {domain_name}")
                return

            whodat_data = resp.json()
            enrichment = {"whodat_raw": json.dumps(whodat_data)}
            if customer:
                enrichment["customer"] = customer

            if isinstance(whodat_data, dict):
                domain_info = whodat_data.get("domain") or {}
                if isinstance(domain_info, dict):
                    if domain_info.get("created_date"):
                        enrichment["whois_created"] = domain_info["created_date"]
                    if domain_info.get("updated_date"):
                        enrichment["whois_updated"] = domain_info["updated_date"]
                    if domain_info.get("expiration_date"):
                        enrichment["whois_expires"] = domain_info["expiration_date"]

                registrar = whodat_data.get("registrar") or {}
                if isinstance(registrar, dict):
                    registrar_name = registrar.get("name") or registrar.get("organization")
                    if registrar_name:
                        enrichment["whois_registrar"] = registrar_name

                registrant = whodat_data.get("registrant") or {}
                if isinstance(registrant, dict):
                    registrant_name = registrant.get("name") or registrant.get("organization")
                    if registrant_name:
                        enrichment["whois_registrant"] = registrant_name
                    if registrant.get("country"):
                        enrichment["whois_country"] = registrant["country"]

            upsert_domain(domain_name, enrichment)
            logger.info(f"Who-dat enrichment done: {domain_name}")

    except Exception as e:
        logger.error(f"Who-dat enrichment failed for {domain_name}: {e}")


# === Background scan runner ===


def run_scan_background(customer: str, domains: list, registered: bool,
                        fuzzers: str, enrich_whois: bool, task_id: str):
    """
    Background task: call dnstwist-api synchronously per domain,
    store results in DB, then run who-dat enrichment if requested.
    """
    all_discovered = []

    for domain in domains:
        logger.info(f"Scanning {domain} for {customer}...")

        payload = {
            "domain": domain,
            "registered": registered,
            "forward": False,
            "async_mode": False,
        }
        if fuzzers:
            payload["fuzzers"] = fuzzers

        try:
            headers = {"Content-Type": "application/json"}
            if DNSTWIST_API_KEY:
                headers["X-API-Key"] = DNSTWIST_API_KEY

            with httpx.Client(timeout=600.0) as client:
                response = client.post(
                    f"{DNSTWIST_API_URL}/scan",
                    json=payload,
                    headers=headers,
                )

            if response.status_code != 200:
                logger.error(f"dnstwist returned {response.status_code} for {domain}")
                complete_task(task_id, error=f"dnstwist {response.status_code}: {response.text[:200]}")
                return

            body = response.json()
            results = body.get("results", [])

            for result in results:
                fuzzer = result.get("fuzzer", "")
                domain_name = result.get("domain", "")

                if fuzzer == "*original" or domain_name == domain or not domain_name:
                    continue

                enrichment = {
                    "customer": customer,
                    "original_domain": domain,
                    "source": "dnstwist",
                    "fuzzer": fuzzer,
                }

                # DNS records
                for field in ("dns_a", "dns_aaaa", "dns_mx", "dns_ns"):
                    val = result.get(field)
                    if val:
                        enrichment[field] = json.dumps(val) if isinstance(val, list) else str(val)

                # GeoIP
                geoip = result.get("geoip")
                if geoip:
                    enrichment["geoip_country"] = geoip

                # Banners
                if result.get("banner_http"):
                    enrichment["http_banner"] = result["banner_http"]
                if result.get("banner_smtp"):
                    enrichment["smtp_banner"] = result["banner_smtp"]

                # Fuzzy hash
                if result.get("ssdeep"):
                    enrichment["lsh_ssdeep"] = result["ssdeep"]
                if result.get("tlsh"):
                    enrichment["lsh_tlsh"] = result["tlsh"]

                # MX interception
                mx_spy = result.get("mx_spy")
                if mx_spy is not None:
                    enrichment["mx_can_intercept"] = 1 if mx_spy else 0

                upsert_domain(domain_name, enrichment)
                all_discovered.append(domain_name)

            logger.info(f"Stored {len(all_discovered)} domains for {customer} (source: {domain})")

        except Exception as e:
            logger.error(f"Scan failed for {domain}: {e}")
            complete_task(task_id, error=str(e))
            return

    # Mark task complete
    complete_task(task_id, domains_found=len(all_discovered))

    # Enrich with who-dat if requested (runs sequentially, no rush)
    if enrich_whois and all_discovered:
        logger.info(f"Starting who-dat enrichment for {len(all_discovered)} domains...")
        for d in all_discovered:
            enrich_with_whodat(d, customer)
        logger.info(f"Who-dat enrichment complete for {customer}")


# === Init DB on startup ===
@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"Orchestrator started. dnstwist API: {DNSTWIST_API_URL}")
    logger.info(f"Who-dat URL: {WHO_DAT_URL}")
    logger.info(f"Database: {DATABASE_URL.split('@')[-1]}")


# === Request Models ===


class ScanRequest(BaseModel):
    customer: str = Field(..., description="Customer name")
    domains: List[str] = Field(..., description="List of domains to scan")
    registered: bool = Field(True, description="Only show registered domains")
    fuzzers: Optional[str] = Field(None, description="Comma-separated fuzzers, or 'all'")
    enrich_whois: bool = Field(True, description="Auto-enrich results with who-dat WHOIS/RDAP lookup")


class EnrichRequest(BaseModel):
    """Generic enrichment payload. Any service can push domain data."""
    customer: Optional[str] = Field(None, description="Customer name")
    domains: List[dict] = Field(
        ...,
        description="List of domain enrichment objects. Each must have 'domain' key.",
    )
    source: Optional[str] = Field(None, description="Source service name")


class WhoisEnrichRequest(BaseModel):
    domains: List[str] = Field(..., description="Domain names to enrich with WHOIS data")
    customer: Optional[str] = Field(None, description="Customer name")


# === API Endpoints ===


@app.post("/api/scan", tags=["Scanning"])
async def submit_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Submit domains for scanning.

    The orchestrator calls dnstwist-api synchronously in the background,
    stores results in PostgreSQL, then enriches with who-dat if requested.
    Returns immediately with a task ID — poll /api/status to track progress.

    **Example:**
    ```json
    {
        "customer": "Osama",
        "domains": ["osama.com"],
        "registered": true,
        "fuzzers": "addition,bitsquatting",
        "enrich_whois": true
    }
    ```
    """
    if not request.domains:
        raise HTTPException(status_code=400, detail="domains must be a non-empty list")

    task_id = str(uuid.uuid4())

    # Create task in DB
    add_task(request.customer, ", ".join(request.domains), task_id)

    # Kick off background scan
    background_tasks.add_task(
        run_scan_background,
        customer=request.customer,
        domains=request.domains,
        registered=request.registered,
        fuzzers=request.fuzzers,
        enrich_whois=request.enrich_whois,
        task_id=task_id,
    )

    return {
        "status": "submitted",
        "task_id": task_id,
        "customer": request.customer,
        "domains": request.domains,
        "enrich_whois": request.enrich_whois,
        "message": "Scan running in background. Poll /api/status to track progress.",
    }


@app.post("/api/enrich", tags=["Enrichment"])
async def enrich_domains(request: EnrichRequest):
    """
    Generic enrichment endpoint. Any service can push domain data here.

    **Example from whoisds-api:**
    ```json
    {
        "customer": "AcmeCorp",
        "source": "whoisds",
        "domains": [
            {"domain": "acmecorp-login.com", "nrd_date": "2026-02-10", "nrd_keyword_matched": "acmecorp"}
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
async def enrich_whois(request: WhoisEnrichRequest, background_tasks: BackgroundTasks):
    """
    Trigger who-dat WHOIS/RDAP lookup for specific domains.
    Runs in background — results are written to DB when ready.

    **Example:**
    ```json
    {
        "domains": ["examp1e.com", "exampl3.com"],
        "customer": "AcmeCorp"
    }
    ```
    """
    def _enrich_batch():
        for domain_name in request.domains:
            enrich_with_whodat(domain_name, request.customer)

    background_tasks.add_task(_enrich_batch)

    return {
        "status": "queued",
        "domains": len(request.domains),
        "message": "WHOIS enrichment running in background.",
    }


@app.get("/api/status", tags=["Status"])
async def get_status(customer: Optional[str] = None):
    """Get scan tasks and their status."""
    tasks = get_tasks(customer)

    # Serialize datetimes
    for t in tasks:
        for k, v in t.items():
            if isinstance(v, datetime):
                t[k] = v.isoformat()

    by_status = {}
    for task in tasks:
        s = task.get("status", "unknown")
        if s not in by_status:
            by_status[s] = []
        by_status[s].append(task)

    return {
        "total": len(tasks),
        "by_status": by_status,
    }


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

    return {
        "customers": [{"customer": r["customer"], "domain_count": r["domain_count"]} for r in rows],
        "count": len(rows),
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
    return {
        "status": "ok",
        "service": "dnstwist-orchestrator",
        "version": "2.0.0",
        "docs": "/docs",
        "debug_db": "http://localhost:5050 (pgAdmin)",
    }
