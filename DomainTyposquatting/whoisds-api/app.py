"""
WhoisDS NRD API - Container App
Downloads Newly Registered Domains (NRD) from WhoisDS and searches for brand keywords.

Endpoints:
- POST /api/download_nrd    - Download NRD file from WhoisDS
- POST /api/search_keywords - Search NRD file for keywords
- GET  /api/files           - List downloaded NRD files
- GET  /api/results         - Get search results for a customer
- GET  /api/health          - Health check
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import json
import os
import requests
import zipfile
import tempfile
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WhoisDS NRD API",
    description="Download and search Newly Registered Domains from WhoisDS.",
    version="1.0.0",
)

# === Configuration ===
DATA_DIR = os.environ.get("DATA_DIR", "/data/whoisds")
NRD_FOLDER = "nrd-files"
RESULTS_FOLDER = "matched-results"


# === Storage Helpers (Local Filesystem) ===


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


# === Init on startup ===
@app.on_event("startup")
def startup():
    ensure_dir(get_nrd_dir())
    ensure_dir(get_results_dir())
    logger.info(f"WhoisDS API started. Data directory: {DATA_DIR}")


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
async def search_keywords(request: SearchKeywordsRequest):
    """
    Search for keywords in NRD file and store results.
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
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Store results
    month_folder = date_obj.strftime("%Y-%m")
    customer_safe = request.Customer.replace(" ", "_").replace("/", "-")

    results_dir = os.path.join(
        get_results_dir(), customer_safe, month_folder
    )
    results_file = os.path.join(results_dir, f"{request.date}-matches.json")

    write_file(results_file, json.dumps(results, indent=2))
    logger.info(f"Results stored at: {results_file}")

    return {
        "status": "success",
        "customer": request.Customer,
        "date": request.date,
        "keywords_searched": cleaned_keywords,
        "total_matches": len(matches),
        "matches": matches,
        "results_stored_at": results_file,
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
    Get search results for a customer.

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
        # Return all months
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
    return {
        "status": "ok",
        "service": "whoisds-nrd-api",
        "data_dir": DATA_DIR,
        "folders": {"nrd_files": NRD_FOLDER, "results": RESULTS_FOLDER},
    }


@app.get("/", tags=["Health"])
async def root():
    """Root health check."""
    return {
        "status": "ok",
        "service": "whoisds-nrd-api",
        "version": "1.0.0",
        "docs": "/docs",
    }
