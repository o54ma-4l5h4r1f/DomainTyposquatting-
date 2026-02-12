"""
DNSTwist Orchestrator API - Container App
Orchestrates domain scanning via dnstwist API and stores results locally.

Endpoints:
- POST /api/scan          - Submit domains for scanning
- POST /api/callback      - Receive results from dnstwist API
- GET  /api/status        - Get pending/running scans
- GET  /api/results       - Get domains found for customer/month
- GET  /api/customers     - List all customers
- GET  /api/health        - Health check
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import json
import os
import httpx
import sqlite3
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DNSTwist Orchestrator API",
    description="Orchestrates domain scanning and stores results.",
    version="1.0.0",
)

# === Configuration ===
DNSTWIST_API_URL = os.environ.get("DNSTWIST_API_URL", "http://dnstwist-api:8000")
DNSTWIST_API_KEY = os.environ.get("DNSTWIST_API_KEY", "")
DATA_DIR = os.environ.get("DATA_DIR", "/data/dnstwist-results")
DB_PATH = os.environ.get("DB_PATH", "/data/dnstwist-results/tasks.db")

# === Storage Helpers (Local Filesystem) ===


def ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def read_file_text(file_path: str) -> str:
    """Read text from file, return empty string if not exists."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def write_file_text(file_path: str, content: str):
    """Write text to file (overwrite)."""
    ensure_dir(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


def append_domains_to_file(
    file_path: str, new_domains: list, exclude_set: set = None
) -> int:
    """Append new domains to file, skip duplicates, return count of new domains."""
    existing_content = read_file_text(file_path)
    existing_domains = set(d.strip() for d in existing_content.splitlines() if d.strip())

    all_excluded = existing_domains.copy()
    if exclude_set:
        all_excluded.update(exclude_set)

    new_unique = [d for d in new_domains if d not in all_excluded]

    if new_unique:
        all_domains = sorted(existing_domains | set(new_unique))
        write_file_text(file_path, "\n".join(all_domains))

    return len(new_unique)


# === SQLite Task Tracking ===


def init_db():
    """Initialize the SQLite database for task tracking."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                customer TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                submitted_at TEXT NOT NULL,
                completed_at TEXT
            )
        """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_customer ON tasks(customer)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def add_task(customer: str, domain: str, tracking_id: str):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tasks (id, customer, domain, status, submitted_at) VALUES (?, ?, ?, 'pending', ?)",
                (tracking_id, customer, domain, datetime.now(timezone.utc).isoformat()),
            )
    except Exception as e:
        logger.error(f"Failed to add task: {e}")


def complete_task(customer: str, tracking_id: str):
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE tasks SET status = 'completed', completed_at = ? WHERE id = ? AND customer = ?",
                (datetime.now(timezone.utc).isoformat(), tracking_id, customer),
            )
    except Exception as e:
        logger.error(f"Failed to complete task: {e}")


def get_pending_tasks(customer: str = None) -> list:
    try:
        with get_db() as conn:
            if customer:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE customer = ? AND status = 'pending'",
                    (customer,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE status = 'pending'"
                ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get pending tasks: {e}")
        return []


# === Init DB on startup ===
@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"Orchestrator started. dnstwist API: {DNSTWIST_API_URL}")
    logger.info(f"Data directory: {DATA_DIR}")


# === Request Models ===


class ScanRequest(BaseModel):
    customer: str = Field(..., description="Customer name")
    domains: List[str] = Field(..., description="List of domains to scan")
    registered: bool = Field(True, description="Only show registered domains")
    fuzzers: Optional[str] = Field(None, description="Comma-separated fuzzers")
    whois: bool = Field(False, description="Perform WHOIS lookups")
    geoip: bool = Field(False, description="GeoIP lookup")
    callback_url: Optional[str] = Field(
        None, description="Override callback URL"
    )


# === API Endpoints ===


@app.post("/api/scan", tags=["Scanning"])
async def submit_scan(request: ScanRequest, req: Request):
    """
    Submit domains for scanning.

    The orchestrator sends each domain to the dnstwist-api in async mode.
    Results are received via the /api/callback endpoint.
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
                    logger.info(
                        f"Queued scan for {domain}, tracking_id: {tracking_id}"
                    )
                else:
                    errors.append(
                        {
                            "domain": domain,
                            "error": f"API returned {response.status_code}: {response.text}",
                        }
                    )

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

    Stores results in local filesystem:
    - /{customer}/{YYYY-MM}/domains.txt   - Domains found this month
    - /{customer}/all_domains.txt         - All domains ever found (cumulative)
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
    timestamp = body.get("timestamp", datetime.now(timezone.utc).isoformat())

    if not customer:
        raise HTTPException(status_code=400, detail="customer field is required")

    # Extract domain names from results (skip original)
    domains_found = []
    for result in results:
        fuzzer = result.get("fuzzer", "")
        domain = result.get("domain", "")
        if fuzzer == "*original" or domain == source_domain:
            continue
        if domain:
            domains_found.append(domain)

    if not domains_found:
        logger.info(f"No lookalike domains found for {source_domain}")
        if tracking_id:
            complete_task(customer, tracking_id)
        return {
            "status": "ok",
            "message": "No lookalike domains found",
            "customer": customer,
            "source_domain": source_domain,
        }

    # Get current month
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)

    month_folder = dt.strftime("%Y-%m")

    # File paths
    month_file = os.path.join(DATA_DIR, customer, month_folder, "domains.txt")
    all_time_file = os.path.join(DATA_DIR, customer, "all_domains.txt")

    # Read existing all-time domains for deduplication
    all_time_content = read_file_text(all_time_file)
    existing_all_time = set(
        d.strip() for d in all_time_content.splitlines() if d.strip()
    )

    # Append to monthly file
    new_monthly = append_domains_to_file(
        month_file, domains_found, exclude_set=existing_all_time
    )

    # Append to all-time file
    new_alltime = append_domains_to_file(all_time_file, domains_found)

    logger.info(f"Stored {new_monthly} new domains for {customer}/{month_folder}")
    logger.info(f"Added {new_alltime} new unique domains to all-time list")

    if tracking_id:
        complete_task(customer, tracking_id)

    return {
        "status": "ok",
        "customer": customer,
        "source_domain": source_domain,
        "domains_received": len(domains_found),
        "new_domains_this_month": new_monthly,
        "new_domains_all_time": new_alltime,
        "month": month_folder,
    }


@app.get("/api/status", tags=["Status"])
async def get_status(customer: Optional[str] = None):
    """
    Get pending/running scan tasks.

    Query params:
    - customer (optional): Filter by customer name
    """
    pending_tasks = get_pending_tasks(customer)

    by_customer = {}
    for task in pending_tasks:
        cust = task.get("customer", "unknown")
        if cust not in by_customer:
            by_customer[cust] = []
        by_customer[cust].append(
            {
                "domain": task.get("domain"),
                "tracking_id": task.get("id"),
                "submitted_at": task.get("submitted_at"),
                "status": task.get("status"),
            }
        )

    result = {"pending_count": len(pending_tasks), "by_customer": by_customer}

    if customer:
        result["filter"] = {"customer": customer}

    return result


@app.get("/api/results", tags=["Results"])
async def get_results(
    customer: str,
    month: Optional[str] = None,
    all_time: bool = False,
):
    """
    Get domains found for a customer.

    Query params:
    - customer (required): Customer name
    - month (optional): Month in YYYY-MM format (default: current month)
    - all_time (optional): If true, return all-time domains
    """
    if all_time:
        file_path = os.path.join(DATA_DIR, customer, "all_domains.txt")
        period = "all_time"
    else:
        if not month:
            month = datetime.now(timezone.utc).strftime("%Y-%m")
        file_path = os.path.join(DATA_DIR, customer, month, "domains.txt")
        period = month

    content = read_file_text(file_path)
    domains = [d.strip() for d in content.splitlines() if d.strip()]

    return {
        "customer": customer,
        "period": period,
        "domains_count": len(domains),
        "domains": domains,
    }


@app.get("/api/customers", tags=["Customers"])
async def list_customers():
    """List all customers with stored results."""
    customers = set()
    if os.path.exists(DATA_DIR):
        for entry in os.listdir(DATA_DIR):
            full_path = os.path.join(DATA_DIR, entry)
            if os.path.isdir(full_path):
                customers.add(entry)

    return {"customers": sorted(list(customers)), "count": len(customers)}


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "dnstwist-orchestrator",
        "dnstwist_api_url": DNSTWIST_API_URL,
        "data_dir": DATA_DIR,
        "db_path": DB_PATH,
    }


@app.get("/", tags=["Health"])
async def root():
    """Root health check."""
    return {
        "status": "ok",
        "service": "dnstwist-orchestrator",
        "version": "1.0.0",
        "docs": "/docs",
    }
