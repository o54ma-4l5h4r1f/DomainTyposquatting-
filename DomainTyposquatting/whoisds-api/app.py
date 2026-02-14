"""
WhoisDS NRD API
Searches Newly Registered Domains for brand keywords.
Auto-downloads NRD files from WhoisDS if not cached locally.
Writes matched domains directly to PostgreSQL.

Endpoints:
- POST /api/search_keywords - Search NRD for keywords (auto-downloads if needed)
- GET  /api/health          - Health check
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List
import logging
import json
import os
import requests
import httpx
import psycopg2
import zipfile
import tempfile
from datetime import datetime, timezone
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WhoisDS NRD API",
    description="Search Newly Registered Domains for brand keywords. Writes directly to PostgreSQL.",
    version="2.0.0",
)

# === Configuration ===
DATA_DIR = os.environ.get("DATA_DIR", "/data/whoisds")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/typosquatting"
)
WHO_DAT_URL = os.environ.get("WHO_DAT_URL", "http://who-dat:8080")
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator-api:8001")
WHOISDS_EMAIL = os.environ.get("WHOISDS_EMAIL", "")
WHOISDS_PASSWORD = os.environ.get("WHOISDS_PASSWORD", "")
NRD_DIR = os.path.join(DATA_DIR, "nrd-files")


# === Database ===


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


# === NRD download ===


def download_nrd(date: str) -> str:
    """Download NRD file for the given date. Returns file path or raises."""
    os.makedirs(NRD_DIR, exist_ok=True)
    file_path = os.path.join(NRD_DIR, f"{date}-NRD.txt")

    if os.path.exists(file_path):
        return file_path

    if not WHOISDS_EMAIL or not WHOISDS_PASSWORD:
        raise HTTPException(
            status_code=404,
            detail=f"NRD file for {date} not found. Set WHOISDS_EMAIL and WHOISDS_PASSWORD to enable auto-download.",
        )

    url = f"https://www.whoisds.com/your-download/direct-download-file/{WHOISDS_EMAIL}/{WHOISDS_PASSWORD}/{date}.zip/ddu/home"
    logger.info(f"Downloading NRD for {date}...")

    response = requests.get(url, timeout=120)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"WhoisDS returned {response.status_code}")

    if not response.content.startswith(b"PK"):
        raise HTTPException(status_code=502, detail="WhoisDS did not return a ZIP file")

    temp_zip = tempfile.mktemp(suffix=".zip")
    try:
        with open(temp_zip, "wb") as f:
            f.write(response.content)

        with zipfile.ZipFile(temp_zip, "r") as zf:
            txt_files = [n for n in zf.namelist() if n.endswith(".txt")]
            if not txt_files:
                raise HTTPException(status_code=502, detail="No .txt file in ZIP")

            content = zf.read(txt_files[0]).decode("utf-8")
    finally:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info(f"Downloaded NRD for {date}: {len(content)} bytes")
    return file_path


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


# === Background tasks ===


def enrich_batch_background(domains: list, customer: str):
    logger.info(f"Starting who-dat enrichment for {len(domains)} NRD domains ({customer})...")
    for domain_name in domains:
        enrich_with_whodat(domain_name, customer)
    logger.info(f"Who-dat enrichment complete for {len(domains)} NRD domains ({customer})")


def pass_to_dnstwist_background(domains: list, customer: str, enrich_whois: bool):
    logger.info(f"Sending {len(domains)} NRD domains to dnstwist scan ({customer})...")
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{ORCHESTRATOR_URL}/api/scan",
                json={"customer": customer, "domains": domains, "registered": True, "enrich_whois": enrich_whois},
            )
            if resp.status_code == 200:
                logger.info(f"dnstwist scan submitted: task_id={resp.json().get('task_id')}")
            else:
                logger.warning(f"Orchestrator returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Failed to send domains to dnstwist: {e}")


# === Startup ===


@app.on_event("startup")
def startup():
    os.makedirs(NRD_DIR, exist_ok=True)
    logger.info(f"WhoisDS API started | who-dat: {WHO_DAT_URL}")


# === Request Model ===


class SearchKeywordsRequest(BaseModel):
    Customer: str = Field(..., description="Customer name")
    Keywords: List[str] = Field(..., description="Keywords to search for")
    date: str = Field(..., description="Date of NRD file (YYYY-MM-DD)")
    enrich_whois: bool = Field(False, description="Enrich matched domains with who-dat WHOIS/RDAP")
    pass_to_dnstwist: bool = Field(False, description="Send matched domains to dnstwist for scanning")


# === Endpoints ===


@app.post("/api/search_keywords")
async def search_keywords(request: SearchKeywordsRequest, background_tasks: BackgroundTasks):
    """
    Search NRD file for keywords. Auto-downloads if not cached.
    Matched domains are written to PostgreSQL.

    ```json
    {"Customer": "Yanal", "Keywords": ["yanal"], "date": "2026-02-13",
     "enrich_whois": true, "pass_to_dnstwist": true}
    ```
    """
    try:
        datetime.strptime(request.date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    cleaned_keywords = [kw.strip().lower() for kw in request.Keywords if kw.strip()]
    if not cleaned_keywords:
        raise HTTPException(status_code=400, detail="No valid keywords")

    # Auto-download NRD if not cached
    nrd_path = download_nrd(request.date)

    with open(nrd_path, "r", encoding="utf-8") as f:
        nrd_content = f.read()

    # Search
    matches = []
    for line in nrd_content.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        line_lower = line_stripped.lower()
        for keyword in cleaned_keywords:
            if keyword in line_lower:
                matches.append({"domain": line_stripped, "keyword": keyword})
                break

    # Write to DB
    matched_domains = []
    for match in matches:
        upsert_domain(match["domain"], {
            "customer": request.Customer,
            "source": "whoisds",
            "nrd_date": request.date,
            "nrd_keyword_matched": match["keyword"],
        })
        matched_domains.append(match["domain"])

    logger.info(f"NRD search: {len(matched_domains)} matches for {request.Customer} ({request.date})")

    # Background enrichment
    if request.enrich_whois and matched_domains:
        background_tasks.add_task(enrich_batch_background, matched_domains, request.Customer)

    if request.pass_to_dnstwist and matched_domains:
        background_tasks.add_task(pass_to_dnstwist_background, matched_domains, request.Customer, request.enrich_whois)

    return {
        "status": "success",
        "customer": request.Customer,
        "date": request.date,
        "keywords": cleaned_keywords,
        "total_matches": len(matched_domains),
        "matches": matches,
        "written_to_db": len(matched_domains),
        "whois_enrichment": "queued" if request.enrich_whois and matched_domains else "skipped",
        "dnstwist_scan": "queued" if request.pass_to_dnstwist and matched_domains else "skipped",
    }


@app.get("/api/health")
async def health_check():
    db_ok = False
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                db_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if db_ok else "degraded",
        "service": "whoisds-nrd-api",
        "database": "connected" if db_ok else "disconnected",
    }
