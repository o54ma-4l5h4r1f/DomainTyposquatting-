"""
WhoisDS NRD API - Container App
Downloads Newly Registered Domains (NRD) from WhoisDS and searches for brand keywords.
Matched domains are written directly to the shared PostgreSQL database.
If enrich_whois=true, who-dat is called and WHOIS data is stored in the same DB rows.

Endpoints:
- POST /api/download_nrd    - Download NRD file from WhoisDS
- POST /api/search_keywords - Search NRD file for keywords, store in DB
- GET  /api/files           - List downloaded NRD files
- GET  /api/results         - Get search results for a customer
- GET  /api/health          - Health check
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import json
import os
import requests
import httpx
import psycopg2
import psycopg2.extras
import zipfile
import tempfile
from datetime import datetime, timezone
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WhoisDS NRD API",
    description="Download and search Newly Registered Domains from WhoisDS. Writes directly to PostgreSQL.",
    version="2.0.0",
)

# === Configuration ===
DATA_DIR = os.environ.get("DATA_DIR", "/data/whoisds")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/typosquatting"
)
WHO_DAT_URL = os.environ.get("WHO_DAT_URL", "http://who-dat:8080")
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator-api:8001")
NRD_FOLDER = "nrd-files"
RESULTS_FOLDER = "matched-results"


# === PostgreSQL (same shared DB as orchestrator) ===


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


# Columns that can be upserted (must match orchestrator's schema)
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
    """Insert or update a domain row using PostgreSQL UPSERT."""
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


# === Who-dat enrichment (writes directly to DB) ===


def enrich_with_whodat(domain_name: str, customer: str = None):
    """Call who-dat for WHOIS/RDAP data and write to DB. Synchronous."""
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


def enrich_batch_background(domains: list, customer: str):
    """Background task: enrich a list of domains with who-dat."""
    logger.info(f"Starting who-dat enrichment for {len(domains)} NRD domains ({customer})...")
    for domain_name in domains:
        enrich_with_whodat(domain_name, customer)
    logger.info(f"Who-dat enrichment complete for {len(domains)} NRD domains ({customer})")


def pass_to_dnstwist_background(domains: list, customer: str, enrich_whois: bool):
    """Background task: send matched NRD domains to orchestrator for dnstwist scanning."""
    logger.info(f"Sending {len(domains)} NRD domains to dnstwist scan ({customer})...")
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{ORCHESTRATOR_URL}/api/scan",
                json={
                    "customer": customer,
                    "domains": domains,
                    "registered": True,
                    "enrich_whois": enrich_whois,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.info(f"dnstwist scan submitted: task_id={data.get('task_id')}")
            else:
                logger.warning(f"Orchestrator returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Failed to send domains to dnstwist: {e}")


# === Storage Helpers (Local Filesystem for NRD files) ===


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def get_nrd_dir() -> str:
    path = os.path.join(DATA_DIR, NRD_FOLDER)
    ensure_dir(path)
    return path


def get_results_dir() -> str:
    path = os.path.join(DATA_DIR, RESULTS_FOLDER)
    ensure_dir(path)
    return path


def file_exists(file_path: str) -> bool:
    return os.path.exists(file_path)


def read_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(file_path: str, content: str):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


# === Request Models ===


class DownloadNRDRequest(BaseModel):
    email: str = Field(..., description="WhoisDS account email")
    password: str = Field(..., description="WhoisDS account password")
    date: str = Field(
        ..., description="Date to download NRD for (YYYY-MM-DD)"
    )


class SearchKeywordsRequest(BaseModel):
    Customer: str = Field(..., description="Customer name")
    Keywords: List[str] = Field(..., description="Keywords to search for")
    date: str = Field(..., description="Date of NRD file (YYYY-MM-DD)")
    enrich_whois: bool = Field(False, description="Enrich matched domains with who-dat WHOIS/RDAP data")
    pass_to_dnstwist: bool = Field(False, description="Send matched domains to dnstwist for typosquatting scan")


# === Init on startup ===
@app.on_event("startup")
def startup():
    ensure_dir(get_nrd_dir())
    ensure_dir(get_results_dir())
    logger.info(f"WhoisDS API started. Data directory: {DATA_DIR}")
    logger.info(f"Database: {DATABASE_URL.split('@')[-1]}")
    logger.info(f"Who-dat URL: {WHO_DAT_URL}")


# === API Endpoints ===


@app.post("/api/download_nrd", tags=["NRD"])
async def download_nrd(request: DownloadNRDRequest):
    """
    Download NRD file from whoisds.com, unzip, and store locally.
    """
    logger.info("Download NRD request received")

    # Validate date format
    try:
        datetime.strptime(request.date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid date format. Use YYYY-MM-DD"
        )

    blob_file_name = f"{request.date}-NRD.txt"
    file_path = os.path.join(get_nrd_dir(), blob_file_name)

    # Check if file already exists
    if file_exists(file_path):
        logger.info(f"File {blob_file_name} already exists")
        return {
            "status": "already_exists",
            "message": f"File {blob_file_name} already exists",
            "file_name": blob_file_name,
            "full_path": file_path,
        }

    # Construct download URL
    download_url = f"https://www.whoisds.com/your-download/direct-download-file/{request.email}/{request.password}/{request.date}.zip/ddu/home"

    logger.info(f"Downloading NRD for date: {request.date}")

    try:
        response = requests.get(download_url, timeout=120, stream=True)

        if response.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to download file. Status code: {response.status_code}",
            )

        content = response.content
        logger.info(f"Downloaded {len(content)} bytes")

        # Check for ZIP signature
        if not content.startswith(b"PK"):
            raise HTTPException(
                status_code=500,
                detail="Downloaded file is not a ZIP file",
            )

        # Extract ZIP
        temp_zip_path = tempfile.mktemp(suffix=".zip")

        try:
            with open(temp_zip_path, "wb") as f:
                f.write(content)

            with zipfile.ZipFile(temp_zip_path, "r") as zip_ref:
                file_list = zip_ref.namelist()
                logger.info(f"Files in ZIP: {file_list}")

                txt_files = [f for f in file_list if f.endswith(".txt")]
                if not txt_files:
                    raise HTTPException(
                        status_code=500,
                        detail=f"No .txt file found in ZIP. Files: {file_list}",
                    )

                txt_file_name = txt_files[0]
                with zip_ref.open(txt_file_name) as txt_file:
                    file_content = txt_file.read().decode("utf-8")

        finally:
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)

        # Save to local storage
        write_file(file_path, file_content)

        return {
            "status": "success",
            "message": "File downloaded, extracted, and stored",
            "file_name": blob_file_name,
            "full_path": file_path,
            "original_file": txt_file_name,
            "file_size": len(file_content),
        }

    except HTTPException:
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")
    except Exception as e:
        logger.error(f"Error in download_nrd: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@app.post("/api/search_keywords", tags=["Search"])
async def search_keywords(request: SearchKeywordsRequest, background_tasks: BackgroundTasks):
    """
    Search for keywords in NRD file.
    Matched domains are written directly to the shared PostgreSQL database.
    If enrich_whois=true, who-dat WHOIS/RDAP enrichment runs in background.

    **Example:**
    ```json
    {
        "Customer": "Yanal",
        "Keywords": ["yanal"],
        "date": "2026-02-13",
        "enrich_whois": true,
        "pass_to_dnstwist": true
    }
    ```
    """
    logger.info("Search keywords request received")

    # Validate date
    try:
        date_obj = datetime.strptime(request.date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid date format. Use YYYY-MM-DD"
        )

    # Clean keywords
    cleaned_keywords = [kw.strip().lower() for kw in request.Keywords if kw.strip()]
    if not cleaned_keywords:
        raise HTTPException(
            status_code=400, detail="No valid keywords after cleaning"
        )

    logger.info(f"Searching for keywords: {cleaned_keywords}")

    # Check NRD file exists
    nrd_file_name = f"{request.date}-NRD.txt"
    nrd_file_path = os.path.join(get_nrd_dir(), nrd_file_name)

    if not file_exists(nrd_file_path):
        raise HTTPException(
            status_code=404,
            detail=f"NRD file not found for date {request.date}. Run download_nrd first.",
        )

    # Read NRD content
    nrd_content = read_file(nrd_file_path)

    # Search for matches
    matches = []
    lines = nrd_content.split("\n")

    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower().strip()
        if not line_lower:
            continue

        for keyword in cleaned_keywords:
            if keyword in line_lower:
                matches.append(
                    {
                        "line_number": line_num,
                        "content": line.strip(),
                        "matched_keyword": keyword,
                    }
                )
                break  # Only count each line once

    # Prepare results
    results = {
        "customer": request.Customer,
        "date": request.date,
        "keywords_searched": cleaned_keywords,
        "total_matches": len(matches),
        "matches": matches,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Store results locally as JSON
    month_folder = date_obj.strftime("%Y-%m")
    customer_safe = request.Customer.replace(" ", "_").replace("/", "-")

    results_dir = os.path.join(
        get_results_dir(), customer_safe, month_folder
    )
    results_file = os.path.join(results_dir, f"{request.date}-matches.json")

    write_file(results_file, json.dumps(results, indent=2))
    logger.info(f"Results stored at: {results_file}")

    # Write each matched domain directly to PostgreSQL
    matched_domains = []
    for match in matches:
        domain_name = match["content"]
        upsert_domain(domain_name, {
            "customer": request.Customer,
            "source": "whoisds",
            "nrd_date": request.date,
            "nrd_keyword_matched": match.get("matched_keyword", ""),
        })
        matched_domains.append(domain_name)

    logger.info(f"Wrote {len(matched_domains)} domains to DB for {request.Customer}")

    # If enrich_whois, kick off background who-dat enrichment
    if request.enrich_whois and matched_domains:
        background_tasks.add_task(
            enrich_batch_background, matched_domains, request.Customer
        )

    # If pass_to_dnstwist, send matched domains to orchestrator for scanning
    if request.pass_to_dnstwist and matched_domains:
        background_tasks.add_task(
            pass_to_dnstwist_background, matched_domains, request.Customer, request.enrich_whois
        )

    return {
        "status": "success",
        "customer": request.Customer,
        "date": request.date,
        "keywords_searched": cleaned_keywords,
        "total_matches": len(matches),
        "matches": matches,
        "results_stored_at": results_file,
        "written_to_db": len(matched_domains),
        "whois_enrichment": "queued" if request.enrich_whois and matched_domains else "skipped",
        "dnstwist_scan": "queued" if request.pass_to_dnstwist and matched_domains else "skipped",
    }


@app.get("/api/files", tags=["NRD"])
async def list_nrd_files():
    """List all downloaded NRD files."""
    nrd_dir = get_nrd_dir()
    files = []
    if os.path.exists(nrd_dir):
        for f in sorted(os.listdir(nrd_dir)):
            if f.endswith("-NRD.txt"):
                full_path = os.path.join(nrd_dir, f)
                files.append(
                    {
                        "file_name": f,
                        "size": os.path.getsize(full_path),
                        "date": f.replace("-NRD.txt", ""),
                    }
                )

    return {"files": files, "count": len(files)}


@app.get("/api/results", tags=["Search"])
async def get_results(customer: str, month: Optional[str] = None):
    """
    Get search results for a customer (from local JSON files).

    Query params:
    - customer (required): Customer name
    - month (optional): Month in YYYY-MM format
    """
    customer_safe = customer.replace(" ", "_").replace("/", "-")
    results_base = os.path.join(get_results_dir(), customer_safe)

    if not os.path.exists(results_base):
        return {"customer": customer, "results": [], "count": 0}

    results = []

    if month:
        month_dir = os.path.join(results_base, month)
        if os.path.exists(month_dir):
            for f in sorted(os.listdir(month_dir)):
                if f.endswith("-matches.json"):
                    file_path = os.path.join(month_dir, f)
                    data = json.loads(read_file(file_path))
                    results.append(data)
    else:
        for month_dir_name in sorted(os.listdir(results_base)):
            month_dir = os.path.join(results_base, month_dir_name)
            if os.path.isdir(month_dir):
                for f in sorted(os.listdir(month_dir)):
                    if f.endswith("-matches.json"):
                        file_path = os.path.join(month_dir, f)
                        data = json.loads(read_file(file_path))
                        results.append(data)

    return {"customer": customer, "results": results, "count": len(results)}


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
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
        "version": "2.0.0",
        "data_dir": DATA_DIR,
        "database": "connected" if db_ok else "disconnected",
        "who_dat_url": WHO_DAT_URL,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "ok",
        "service": "whoisds-nrd-api",
        "version": "2.0.0",
        "docs": "/docs",
    }
