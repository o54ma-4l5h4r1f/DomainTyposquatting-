"""
DNSTwist Orchestrator API
Scans domains via dnstwist, stores results in PostgreSQL,
enriches with who-dat WHOIS/RDAP if requested.

Endpoints:
- POST /api/scan   - Submit domains for scanning
- GET  /api/status - Track scan progress
- GET  /api/health - Health check
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
    description="Scans domains via dnstwist, stores results in PostgreSQL, enriches with who-dat.",
    version="2.0.0",
)

# === Configuration ===
DNSTWIST_API_URL = os.environ.get("DNSTWIST_API_URL", "http://dnstwist-api:8000")
WHO_DAT_URL = os.environ.get("WHO_DAT_URL", "http://who-dat:8080")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/typosquatting"
)


# === Database ===


_db_initialized = False


def _ddl(cur, sql):
    """Execute a DDL statement using a savepoint so concurrent duplicate-object
    errors (race condition when multiple services create the same table) are
    silently ignored instead of crashing the service."""
    cur.execute("SAVEPOINT _ddl")
    try:
        cur.execute(sql)
        cur.execute("RELEASE SAVEPOINT _ddl")
    except (
        psycopg2.errors.DuplicateTable,
        psycopg2.errors.UniqueViolation,
        psycopg2.errors.DuplicateObject,
    ):
        cur.execute("ROLLBACK TO SAVEPOINT _ddl")


def _create_tables(conn):
    """Create all required tables and indexes."""
    with conn.cursor() as cur:
        _ddl(cur, """
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
        _ddl(cur, "CREATE INDEX IF NOT EXISTS idx_tasks_customer ON tasks(customer)")
        _ddl(cur, "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")

        _ddl(cur, """
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                customer TEXT,
                original_domain TEXT,
                source TEXT,
                first_seen_at TIMESTAMPTZ,
                last_updated_at TIMESTAMPTZ,
                fuzzer TEXT,
                dns_a TEXT,
                dns_aaaa TEXT,
                dns_mx TEXT,
                dns_ns TEXT,
                whois_registrar TEXT,
                whois_created TEXT,
                whois_updated TEXT,
                whois_expires TEXT,
                whois_registrant TEXT,
                whois_country TEXT,
                geoip_country TEXT,
                http_banner TEXT,
                smtp_banner TEXT,
                lsh_ssdeep TEXT,
                lsh_tlsh TEXT,
                mx_can_intercept INTEGER,
                nrd_date TEXT,
                nrd_keyword_matched TEXT,
                whodat_raw TEXT
            )
        """)
        _ddl(cur, "CREATE INDEX IF NOT EXISTS idx_domains_customer ON domains(customer)")
        _ddl(cur, "CREATE INDEX IF NOT EXISTS idx_domains_original ON domains(original_domain)")
    conn.commit()


def init_db():
    """Initialise DB with retries so the app survives postgres being slow to start."""
    global _db_initialized
    import time

    max_retries = 10
    for attempt in range(1, max_retries + 1):
        try:
            with psycopg2.connect(DATABASE_URL) as conn:
                _create_tables(conn)
            _db_initialized = True
            logger.info("Database tables initialised successfully")
            return
        except psycopg2.OperationalError as exc:
            if attempt == max_retries:
                logger.error(f"Could not connect to database after {max_retries} attempts: {exc}")
                raise
            wait = min(2 ** attempt, 30)
            logger.warning(f"DB not ready (attempt {attempt}/{max_retries}), retrying in {wait}s …")
            time.sleep(wait)


def ensure_db():
    """Lazily ensure tables exist (called from get_db on first use)."""
    global _db_initialized
    if _db_initialized:
        return
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            _create_tables(conn)
        _db_initialized = True
        logger.info("Database tables created (lazy init)")
    except Exception as exc:
        logger.error(f"ensure_db failed: {exc}")
        raise


@contextmanager
def get_db():
    ensure_db()
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


ALLOWED_COLS = [
    "customer", "original_domain", "source", "first_seen_at", "last_updated_at",
    "fuzzer", "dns_a", "dns_aaaa", "dns_mx", "dns_ns",
    "whois_registrar", "whois_created", "whois_updated", "whois_expires",
    "whois_registrant", "whois_country",
    "geoip_country", "http_banner", "smtp_banner", "lsh_ssdeep", "lsh_tlsh",
    "mx_can_intercept", "nrd_date", "nrd_keyword_matched", "whodat_raw",
]


def upsert_domain(domain_name: str, data: dict):
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
            update_set = ", ".join(f"{col} = EXCLUDED.{col}" for col in updates.keys())

            cur.execute(
                f"INSERT INTO domains ({', '.join(insert_cols)}) VALUES ({placeholders}) "
                f"ON CONFLICT (domain) DO UPDATE SET {update_set}",
                insert_vals,
            )


# === Task helpers ===


def add_task(customer: str, domain: str, task_id: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO tasks (id, customer, domain, status, submitted_at)
                   VALUES (%s, %s, %s, 'scanning', %s)
                   ON CONFLICT (id) DO UPDATE SET status = 'scanning', submitted_at = EXCLUDED.submitted_at""",
                (task_id, customer, domain, datetime.now(timezone.utc).isoformat()),
            )


def complete_task(task_id: str, domains_found: int = 0, error: str = None):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE tasks SET status = %s, completed_at = %s,
                   domains_found = %s, error = %s WHERE id = %s""",
                ("failed" if error else "completed",
                 datetime.now(timezone.utc).isoformat(),
                 domains_found, error, task_id),
            )


# === Who-dat enrichment ===


def _call_whodat(domain_name: str) -> dict | None:
    """Call who-dat and return the raw JSON response, or None on failure."""
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{WHO_DAT_URL}/{domain_name}")
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as e:
        logger.error(f"Who-dat request failed for {domain_name}: {e}")
        return None


def _is_registered(whodat_data: dict) -> bool:
    """Check whether who-dat response indicates the domain is actually registered.

    A domain is considered registered when the WHOIS/RDAP data contains at
    least one of: a created_date, a registrar name, or a registrant name.
    Bare 200 responses from who-dat that lack these fields are treated as
    *not registered*.
    """
    if not isinstance(whodat_data, dict):
        return False

    # Check for a creation date in the domain section
    d = whodat_data.get("domain") or {}
    if isinstance(d, dict) and d.get("created_date"):
        return True

    # Check for a registrar
    reg = whodat_data.get("registrar") or {}
    if isinstance(reg, dict) and (reg.get("name") or reg.get("organization")):
        return True

    # Check for a registrant
    rnt = whodat_data.get("registrant") or {}
    if isinstance(rnt, dict) and (rnt.get("name") or rnt.get("organization")):
        return True

    return False


def _parse_whodat(whodat_data: dict, customer: str = None) -> dict:
    """Parse raw who-dat JSON into an enrichment dict for the database."""
    enrichment = {"whodat_raw": json.dumps(whodat_data)}
    if customer:
        enrichment["customer"] = customer

    if isinstance(whodat_data, dict):
        d = whodat_data.get("domain") or {}
        if isinstance(d, dict):
            for src, dst in [("created_date", "whois_created"), ("updated_date", "whois_updated"), ("expiration_date", "whois_expires")]:
                if d.get(src):
                    enrichment[dst] = d[src]

        reg = whodat_data.get("registrar") or {}
        if isinstance(reg, dict):
            name = reg.get("name") or reg.get("organization")
            if name:
                enrichment["whois_registrar"] = name

        rnt = whodat_data.get("registrant") or {}
        if isinstance(rnt, dict):
            name = rnt.get("name") or rnt.get("organization")
            if name:
                enrichment["whois_registrant"] = name
            if rnt.get("country"):
                enrichment["whois_country"] = rnt["country"]

    return enrichment


def _fetch_whodat(domain_name: str, customer: str = None) -> dict | None:
    """Call who-dat, validate the domain is registered, and return enrichment dict.

    Returns None when who-dat fails OR the response lacks registration signals.
    """
    whodat_data = _call_whodat(domain_name)
    if whodat_data is None:
        return None
    if not _is_registered(whodat_data):
        logger.info(f"Who-dat returned data for {domain_name} but no registration signals found — treating as not registered")
        return None
    return _parse_whodat(whodat_data, customer)


def enrich_with_whodat(domain_name: str, customer: str = None):
    """Fetch WHOIS data and upsert into DB (used for standalone enrichment)."""
    enrichment = _fetch_whodat(domain_name, customer)
    if enrichment:
        upsert_domain(domain_name, enrichment)
        logger.info(f"Who-dat enrichment done: {domain_name}")


# === Background scan ===


def _parse_scan_results(results: list, customer: str, original_domain: str) -> list:
    """Parse dnstwist JSON results into a list of (domain_name, data) tuples."""
    parsed = []
    for result in results:
        fuzzer = result.get("fuzzer", "")
        domain_name = result.get("domain", "")
        if fuzzer == "*original" or domain_name == original_domain or not domain_name:
            continue

        data = {"customer": customer, "original_domain": original_domain, "source": "dnstwist", "fuzzer": fuzzer}

        for field in ("dns_a", "dns_aaaa", "dns_mx", "dns_ns"):
            val = result.get(field)
            if val:
                data[field] = json.dumps(val) if isinstance(val, list) else str(val)

        if result.get("geoip"):
            data["geoip_country"] = result["geoip"]
        if result.get("banner_http"):
            data["http_banner"] = result["banner_http"]
        if result.get("banner_smtp"):
            data["smtp_banner"] = result["banner_smtp"]
        if result.get("ssdeep"):
            data["lsh_ssdeep"] = result["ssdeep"]
        if result.get("tlsh"):
            data["lsh_tlsh"] = result["tlsh"]
        if result.get("mx_spy") is not None:
            data["mx_can_intercept"] = 1 if result["mx_spy"] else 0

        parsed.append((domain_name, data))
    return parsed


def run_scan_background(customer: str, domains: list, registered: bool,
                        fuzzers: str, enrich_whois: bool, task_id: str):
    """Scan domains via dnstwist. When enrich_whois is enabled, only domains
    with successful WHOIS data are stored in the database."""
    all_discovered = []

    for domain in domains:
        logger.info(f"[scan] {domain} for {customer}...")

        payload = {"domain": domain, "registered": registered}
        if fuzzers:
            payload["fuzzers"] = fuzzers

        try:
            with httpx.Client(timeout=600.0) as client:
                response = client.post(f"{DNSTWIST_API_URL}/scan", json=payload)

            if response.status_code != 200:
                logger.error(f"[scan] dnstwist returned {response.status_code} for {domain}")
                complete_task(task_id, error=f"dnstwist {response.status_code}: {response.text[:200]}")
                return

            results = response.json().get("results", [])
            parsed = _parse_scan_results(results, customer, domain)
            logger.info(f"[scan] {domain}: {len(parsed)} fuzzed domains returned by dnstwist")

            if registered:
                # Only store domains that WHOIS confirms as registered
                for domain_name, scan_data in parsed:
                    whois_data = _fetch_whodat(domain_name, customer)
                    if whois_data:
                        if enrich_whois:
                            merged = {**scan_data, **whois_data}
                            upsert_domain(domain_name, merged)
                            logger.info(f"[scan+whois] {domain_name}: stored (scan + WHOIS merged)")
                        else:
                            upsert_domain(domain_name, scan_data)
                            logger.info(f"[scan] {domain_name}: stored (scan only, registered)")
                        all_discovered.append(domain_name)
                    else:
                        logger.info(f"[scan] {domain_name}: skipped (not registered)")
            else:
                # Store all scan results directly
                for domain_name, scan_data in parsed:
                    upsert_domain(domain_name, scan_data)
                    all_discovered.append(domain_name)

            logger.info(f"[scan] {domain}: {len(all_discovered)} domains stored in DB")

        except Exception as e:
            logger.error(f"[scan] failed for {domain}: {e}")
            complete_task(task_id, error=str(e))
            return

    complete_task(task_id, domains_found=len(all_discovered))
    logger.info(f"[scan] Task {task_id} complete: {len(all_discovered)} total domains for {customer}")


# === Startup ===


@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"Orchestrator started | dnstwist: {DNSTWIST_API_URL} | who-dat: {WHO_DAT_URL}")


# === Request Models ===


class ScanRequest(BaseModel):
    customer: str = Field(..., description="Customer name")
    domains: List[str] = Field(..., description="List of domains to scan")
    registered: bool = Field(True, description="Only show registered domains")
    fuzzers: Optional[str] = Field("bitsquatting", description="Comma-separated fuzzers, or 'all'")
    enrich_whois: bool = Field(True, description="Auto-enrich with who-dat WHOIS/RDAP")


# === Endpoints ===


@app.post("/api/scan")
async def submit_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Submit domains for dnstwist scanning. Returns immediately, scan runs in background."""
    if not request.domains:
        raise HTTPException(status_code=400, detail="domains must be a non-empty list")

    task_id = str(uuid.uuid4())
    add_task(request.customer, ", ".join(request.domains), task_id)

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
    }


@app.get("/api/status")
async def get_status(customer: Optional[str] = None):
    """Get scan tasks and their status."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if customer:
                cur.execute("SELECT * FROM tasks WHERE customer = %s ORDER BY submitted_at DESC", (customer,))
            else:
                cur.execute("SELECT * FROM tasks ORDER BY submitted_at DESC")
            tasks = [dict(r) for r in cur.fetchall()]

    for t in tasks:
        for k, v in t.items():
            if isinstance(v, datetime):
                t[k] = v.isoformat()

    return {"total": len(tasks), "tasks": tasks}


@app.get("/api/health")
async def health_check():
    db_ok = False
    domain_count = 0
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM domains")
                domain_count = cur.fetchone()[0]
                db_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if db_ok else "degraded",
        "service": "orchestrator-api",
        "database": "connected" if db_ok else "disconnected",
        "total_domains": domain_count,
    }
