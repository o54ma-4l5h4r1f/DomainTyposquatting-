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


def init_db():
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
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
            cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_customer ON tasks(customer)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")

            cur.execute("""
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
            cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_customer ON domains(customer)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_original ON domains(original_domain)")
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


def enrich_with_whodat(domain_name: str, customer: str = None):
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{WHO_DAT_URL}/{domain_name}")
            if resp.status_code != 200:
                return

            whodat_data = resp.json()
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

            upsert_domain(domain_name, enrichment)
            logger.info(f"Who-dat enrichment done: {domain_name}")
    except Exception as e:
        logger.error(f"Who-dat enrichment failed for {domain_name}: {e}")


# === Background scan ===


def store_scan_results(results: list, customer: str, original_domain: str) -> list:
    """Parse dnstwist results and upsert each domain into PostgreSQL. Returns list of discovered domain names."""
    discovered = []
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

        upsert_domain(domain_name, data)
        discovered.append(domain_name)

    return discovered


def run_scan_background(customer: str, domains: list, registered: bool,
                        fuzzers: str, enrich_whois: bool, task_id: str):
    """Phase 1: dnstwist scan + store in DB. Phase 2: who-dat enrichment (independent)."""
    all_discovered = []

    # --- Phase 1: Scan each domain via dnstwist, store results immediately ---
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
            discovered = store_scan_results(results, customer, domain)
            all_discovered.extend(discovered)
            logger.info(f"[scan] {domain}: {len(discovered)} domains found and stored in DB")

        except Exception as e:
            logger.error(f"[scan] failed for {domain}: {e}")
            complete_task(task_id, error=str(e))
            return

    # Task complete — all scan results are in the database
    complete_task(task_id, domains_found=len(all_discovered))
    logger.info(f"[scan] Task {task_id} complete: {len(all_discovered)} total domains for {customer}")

    # --- Phase 2: Who-dat enrichment (runs after scan is done, independent) ---
    if enrich_whois and all_discovered:
        logger.info(f"[whois] Starting who-dat enrichment for {len(all_discovered)} domains...")
        for d in all_discovered:
            enrich_with_whodat(d, customer)
        logger.info(f"[whois] Enrichment complete for {customer}: {len(all_discovered)} domains")


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
    fuzzers: Optional[str] = Field(None, description="Comma-separated fuzzers, or 'all'")
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
