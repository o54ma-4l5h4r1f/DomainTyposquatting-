"""Dashboard API — read/write gateway between the Vue frontend and PostgreSQL.

This service shares the same database as orchestrator-api and whoisds-api but
is dedicated to the dashboard.  It never calls the processing backend.
"""

import os
import time
import logging
from datetime import datetime, timezone
from typing import Optional, List
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@postgres:5432/typosquatting",
)

app = FastAPI(title="Typosquatting Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Database helpers ─────────────────────────────────────────────────────────


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _retry_init(fn, retries=10, delay=2):
    for attempt in range(retries):
        try:
            fn()
            return
        except Exception as e:
            if attempt == retries - 1:
                raise
            logger.warning(f"DB init attempt {attempt+1} failed: {e} — retrying in {delay}s")
            time.sleep(delay)


def init_db():
    """Create dashboard-specific tables and extend the shared domains table."""

    def _create():
        with get_db() as conn:
            with conn.cursor() as cur:
                # Customers
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS customers (
                        name  TEXT PRIMARY KEY,
                        tier  TEXT NOT NULL DEFAULT 'standard',
                        active BOOLEAN NOT NULL DEFAULT true,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)

                # Customer keywords
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS customer_keywords (
                        id   SERIAL PRIMARY KEY,
                        customer_name TEXT NOT NULL REFERENCES customers(name) ON DELETE CASCADE,
                        keyword TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE(customer_name, keyword)
                    )
                """)
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ck_customer ON customer_keywords(customer_name)"
                )

                # Customer monitored domains (seeds for dnstwist)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS customer_domains (
                        id   SERIAL PRIMARY KEY,
                        customer_name TEXT NOT NULL REFERENCES customers(name) ON DELETE CASCADE,
                        domain TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE(customer_name, domain)
                    )
                """)
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cd_customer ON customer_domains(customer_name)"
                )

                # Ensure the shared domains table exists (orchestrator-api
                # normally creates it, but frontend-api may start first).
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS domains (
                        domain            TEXT PRIMARY KEY,
                        customer          TEXT,
                        original_domain   TEXT,
                        source            TEXT,
                        first_seen_at     TIMESTAMPTZ,
                        last_updated_at   TIMESTAMPTZ,
                        fuzzer            TEXT,
                        dns_a             TEXT,
                        dns_aaaa          TEXT,
                        dns_mx            TEXT,
                        dns_ns            TEXT,
                        whois_registrar   TEXT,
                        whois_created     TEXT,
                        whois_updated     TEXT,
                        whois_expires     TEXT,
                        whois_registrant  TEXT,
                        whois_country     TEXT,
                        geoip_country     TEXT,
                        http_banner       TEXT,
                        smtp_banner       TEXT,
                        lsh_ssdeep        TEXT,
                        lsh_tlsh          TEXT,
                        mx_can_intercept  INTEGER,
                        nrd_date          TEXT,
                        nrd_keyword_matched TEXT,
                        whodat_raw        TEXT
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_customer ON domains(customer)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_original ON domains(original_domain)")

                # Add dashboard action columns to the domains table
                for col, dtype in [
                    ("action_status", "TEXT"),
                    ("action_taken_at", "TIMESTAMPTZ"),
                    ("action_taken_by", "TEXT"),
                ]:
                    cur.execute(
                        f"ALTER TABLE domains ADD COLUMN IF NOT EXISTS {col} {dtype}"
                    )

                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_domains_action ON domains(action_status)"
                )

    _retry_init(_create)
    logger.info("Dashboard DB tables ready")


# ── Request / response models ────────────────────────────────────────────────


class ActionRequest(BaseModel):
    action: str = Field(..., pattern="^(blocked|safe|takedown_requested)$")
    customer: str


class CustomerRequest(BaseModel):
    name: str
    tier: str = Field("standard", pattern="^(standard|premium)$")


class KeywordRequest(BaseModel):
    keyword: str = Field(..., min_length=1)


class DomainConfigRequest(BaseModel):
    domain: str = Field(..., min_length=1)


# ── Domain endpoints ─────────────────────────────────────────────────────────


@app.get("/api/domains")
def list_domains(
    customers: str = Query(..., description="Comma-separated customer names"),
    action_status: Optional[str] = Query(
        None,
        description="Filter: pending | blocked | safe | takedown_requested",
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    sort_field: str = Query("first_seen_at"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    """Paginated domain list for the dashboard."""

    customer_list = [c.strip() for c in customers.split(",") if c.strip()]
    if not customer_list:
        raise HTTPException(400, "customers parameter required")

    # Whitelist sortable columns to prevent SQL injection
    allowed_sort = {
        "domain", "source", "fuzzer", "first_seen_at", "last_updated_at",
        "whois_created", "whois_registrar", "action_status",
    }
    if sort_field not in allowed_sort:
        sort_field = "first_seen_at"

    # Build WHERE clause
    conditions = ["customer = ANY(%(customers)s)"]
    params: dict = {"customers": customer_list}

    if action_status == "pending":
        conditions.append("action_status IS NULL")
    elif action_status in ("blocked", "safe", "takedown_requested"):
        conditions.append("action_status = %(action_status)s")
        params["action_status"] = action_status

    where = " AND ".join(conditions)
    order = f"{sort_field} {sort_order} NULLS LAST"
    offset = (page - 1) * page_size

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM domains WHERE {where}", params)
            total = cur.fetchone()["cnt"]

            cur.execute(
                f"""SELECT * FROM domains
                    WHERE {where}
                    ORDER BY {order}
                    LIMIT %(limit)s OFFSET %(offset)s""",
                {**params, "limit": page_size, "offset": offset},
            )
            rows = cur.fetchall()

    return {
        "domains": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.post("/api/domains/{domain}/action")
def set_domain_action(domain: str, body: ActionRequest):
    """Mark a domain as blocked / safe / takedown_requested."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE domains
                   SET action_status = %s, action_taken_at = %s, action_taken_by = %s
                   WHERE domain = %s AND customer = %s""",
                (body.action, now, body.customer, domain, body.customer),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Domain not found for this customer")
    return {"status": "ok"}


@app.delete("/api/domains/{domain}/action")
def undo_domain_action(domain: str, customer: str = Query(...)):
    """Reset a domain's action (undo block / safe / takedown)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE domains
                   SET action_status = NULL, action_taken_at = NULL, action_taken_by = NULL
                   WHERE domain = %s AND customer = %s""",
                (domain, customer),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Domain not found for this customer")
    return {"status": "ok"}


# ── Customer management ──────────────────────────────────────────────────────


@app.post("/api/customers")
def upsert_customer(body: CustomerRequest):
    """Create or update a customer (admin endpoint)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO customers (name, tier, created_at, updated_at)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (name) DO UPDATE
                   SET tier = EXCLUDED.tier, updated_at = EXCLUDED.updated_at""",
                (body.name, body.tier, now, now),
            )
    return {"status": "ok", "customer": body.name, "tier": body.tier}


@app.get("/api/customers/{name}")
def get_customer(name: str):
    """Get a single customer's details."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM customers WHERE name = %s", (name,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(404, f"Customer '{name}' not found")
    return row


@app.get("/api/customers/{name}/config")
def get_customer_config(name: str):
    """Get a customer's keywords and monitored domains."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM customers WHERE name = %s", (name,))
            customer = cur.fetchone()
            if not customer:
                raise HTTPException(404, f"Customer '{name}' not found")

            cur.execute(
                "SELECT keyword FROM customer_keywords WHERE customer_name = %s ORDER BY keyword",
                (name,),
            )
            keywords = [r["keyword"] for r in cur.fetchall()]

            cur.execute(
                "SELECT domain FROM customer_domains WHERE customer_name = %s ORDER BY domain",
                (name,),
            )
            domains = [r["domain"] for r in cur.fetchall()]

    return {"customer": customer, "keywords": keywords, "domains": domains}


# ── Keyword config ───────────────────────────────────────────────────────────


@app.post("/api/customers/{name}/keywords")
def add_keyword(name: str, body: KeywordRequest):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM customers WHERE name = %s", (name,))
            if not cur.fetchone():
                raise HTTPException(404, f"Customer '{name}' not found")
            try:
                cur.execute(
                    "INSERT INTO customer_keywords (customer_name, keyword) VALUES (%s, %s)",
                    (name, body.keyword.lower()),
                )
            except psycopg2.errors.UniqueViolation:
                raise HTTPException(409, "Keyword already exists")
    return {"status": "ok"}


@app.delete("/api/customers/{name}/keywords/{keyword}")
def remove_keyword(name: str, keyword: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM customer_keywords WHERE customer_name = %s AND keyword = %s",
                (name, keyword),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Keyword not found")
    return {"status": "ok"}


# ── Monitored domain config ─────────────────────────────────────────────────


@app.post("/api/customers/{name}/domains")
def add_monitored_domain(name: str, body: DomainConfigRequest):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM customers WHERE name = %s", (name,))
            if not cur.fetchone():
                raise HTTPException(404, f"Customer '{name}' not found")
            try:
                cur.execute(
                    "INSERT INTO customer_domains (customer_name, domain) VALUES (%s, %s)",
                    (name, body.domain.lower()),
                )
            except psycopg2.errors.UniqueViolation:
                raise HTTPException(409, "Domain already monitored")
    return {"status": "ok"}


@app.delete("/api/customers/{name}/domains/{domain}")
def remove_monitored_domain(name: str, domain: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM customer_domains WHERE customer_name = %s AND domain = %s",
                (name, domain),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Domain not found")
    return {"status": "ok"}


# ── Health ───────────────────────────────────────────────────────────────────


@app.get("/api/health")
def health():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ── Startup ──────────────────────────────────────────────────────────────────


@app.on_event("startup")
def startup():
    init_db()
    logger.info("Dashboard API ready")
