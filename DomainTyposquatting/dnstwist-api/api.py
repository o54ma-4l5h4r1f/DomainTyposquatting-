"""
DNSTwist API - Full Featured
All features from the original dnstwist tool exposed via REST API
Uses dictionaries from the official dnstwist repository
"""
from fastapi import FastAPI, Query, HTTPException, Response, Header, Depends, BackgroundTasks
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum
import dnstwist
import os
import secrets
import httpx
from datetime import datetime, timezone
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DNSTwist API",
    description="""
Domain name permutation engine for detecting typosquatting, phishing attacks, and brand impersonation.

## Authentication
All endpoints (except `/` and `/docs`) require an API key.
Pass it via header: `X-API-Key: your-api-key`

## Webhook/Callback
Add `&forward=true` to send results to the configured CALLBACK_URL.
The callback URL is configured via environment variable in Azure.

## Features
- Multiple fuzzing algorithms (homoglyph, bitsquatting, typo, etc.)
- DNS lookups (A, AAAA, MX, NS records)
- WHOIS lookups
- GeoIP location
- Web page fuzzy hashing (ssdeep/tlsh)
- MX mail server checks
- Banner grabbing
- Multiple output formats (JSON, CSV, List)
- Built-in dictionaries from official dnstwist repo
- Webhook callback support
    """,
    version="1.0.0"
)

# === Configuration from Environment ===
API_KEY = os.environ.get("API_KEY", None)

# === Webhook Configuration ===
# All configurable from Azure without rebuilding!
CALLBACK_URL = os.environ.get("CALLBACK_URL", None)

# Webhook Authentication Options (choose one):
# Option 1: API Key in header
CALLBACK_API_KEY = os.environ.get("CALLBACK_API_KEY", None)
CALLBACK_API_KEY_HEADER = os.environ.get("CALLBACK_API_KEY_HEADER", "X-API-Key")  # Custom header name

# Option 2: Bearer token
CALLBACK_BEARER_TOKEN = os.environ.get("CALLBACK_BEARER_TOKEN", None)

# Option 3: Basic auth
CALLBACK_BASIC_USER = os.environ.get("CALLBACK_BASIC_USER", None)
CALLBACK_BASIC_PASS = os.environ.get("CALLBACK_BASIC_PASS", None)

# Option 4: Custom header (any name/value)
CALLBACK_CUSTOM_HEADER = os.environ.get("CALLBACK_CUSTOM_HEADER", None)  # e.g., "X-Custom-Auth"
CALLBACK_CUSTOM_VALUE = os.environ.get("CALLBACK_CUSTOM_VALUE", None)

# Optional: Custom HTTP method (default POST)
CALLBACK_METHOD = os.environ.get("CALLBACK_METHOD", "POST").upper()

# === API Key Authentication for this API ===
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key if one is configured"""
    if API_KEY is None:
        return True
    if api_key is None or not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Pass via X-API-Key header."
        )
    return True

# === Webhook Helper Function ===
def _build_callback_headers() -> dict:
    """Build headers for callback request based on configured auth method"""
    headers = {"Content-Type": "application/json"}
    
    # Option 1: API Key
    if CALLBACK_API_KEY:
        headers[CALLBACK_API_KEY_HEADER] = CALLBACK_API_KEY
    
    # Option 2: Bearer token
    elif CALLBACK_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {CALLBACK_BEARER_TOKEN}"
    
    # Option 3: Basic auth is handled separately in httpx
    
    # Option 4: Custom header
    elif CALLBACK_CUSTOM_HEADER and CALLBACK_CUSTOM_VALUE:
        headers[CALLBACK_CUSTOM_HEADER] = CALLBACK_CUSTOM_VALUE
    
    return headers

def _get_callback_auth():
    """Get basic auth tuple if configured"""
    if CALLBACK_BASIC_USER and CALLBACK_BASIC_PASS:
        return (CALLBACK_BASIC_USER, CALLBACK_BASIC_PASS)
    return None

async def send_to_callback(data: dict, callback_url_override: str = None):
    """Send results to callback URL (override or configured)"""
    url = callback_url_override or CALLBACK_URL
    
    if not url:
        logger.warning("Callback requested but no URL provided or configured")
        return False
    
    try:
        # Add timestamp to callback payload
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        headers = _build_callback_headers()
        auth = _get_callback_auth()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            if CALLBACK_METHOD == "POST":
                response = await client.post(url, json=data, headers=headers, auth=auth)
            elif CALLBACK_METHOD == "PUT":
                response = await client.put(url, json=data, headers=headers, auth=auth)
            else:
                response = await client.post(url, json=data, headers=headers, auth=auth)
            
            logger.info(f"Callback sent to {url}, method: {CALLBACK_METHOD}, status: {response.status_code}")
            return response.status_code < 400
    except Exception as e:
        logger.error(f"Callback failed: {str(e)}")
        return False


def run_scan_and_callback(
    domain: str,
    registered: bool,
    fuzzers: Optional[str],
    nameservers: Optional[str],
    threads: int,
    whois: bool,
    geoip: bool,
    lsh: Optional[str],
    lsh_url: Optional[str],
    mxcheck: bool,
    banners: bool,
    useragent: Optional[str],
    customer: Optional[str],
    tracking_id: Optional[str],
    metadata: Optional[dict],
    callback_url: str
):
    """Background task: Run scan and send results to callback"""
    import asyncio
    
    logger.info(f"Background scan starting for {domain}")
    
    try:
        # Run the scan
        result = _execute_scan(
            domain=domain,
            registered=registered,
            fuzzers=fuzzers,
            nameservers=nameservers,
            threads=threads,
            whois=whois,
            geoip=geoip,
            lsh=lsh,
            lsh_url=lsh_url,
            mxcheck=mxcheck,
            banners=banners,
            useragent=useragent,
        )
        
        # Add tracking info
        if customer:
            result["customer"] = customer
        if tracking_id:
            result["tracking_id"] = tracking_id
        if metadata:
            result["metadata"] = metadata
        
        # Send to callback
        asyncio.run(send_to_callback(result, callback_url))
        logger.info(f"Background scan completed for {domain}")
        
    except Exception as e:
        logger.error(f"Background scan failed for {domain}: {str(e)}")
        # Try to send error to callback
        error_result = {
            "domain": domain,
            "error": str(e),
            "customer": customer,
            "tracking_id": tracking_id
        }
        try:
            asyncio.run(send_to_callback(error_result, callback_url))
        except:
            pass

# Dictionary paths from environment or default location
DICT_PATH = os.environ.get("DNSTWIST_DICTIONARIES", "/app/dictionaries")
TLD_DICT = os.path.join(DICT_PATH, "common_tlds.dict")
ENGLISH_DICT = os.path.join(DICT_PATH, "english.dict")


# === Enums ===
class LshAlgorithm(str, Enum):
    ssdeep = "ssdeep"
    tlsh = "tlsh"


# === Request/Response Models ===
ALL_FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission,repetition,replacement,subdomain,transposition,vowel-swap,dictionary,tld-swap"


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Domain name to scan", example="example.com")
    registered: bool = Field(False, description="Show only registered (resolvable) domains")
    fuzzers: Optional[str] = Field(None, description="Comma-separated list of fuzzers, or 'all' for every fuzzer", example="homoglyph,bitsquatting")
    nameservers: Optional[str] = Field(None, description="Custom DNS servers (comma-separated)", example="8.8.8.8,1.1.1.1")
    threads: int = Field(10, ge=1, le=100, description="Number of threads")
    whois: bool = Field(False, description="Perform WHOIS lookups")
    geoip: bool = Field(False, description="GeoIP country lookup")
    lsh: Optional[LshAlgorithm] = Field(None, description="Fuzzy hash algorithm for phishing detection")
    lsh_url: Optional[str] = Field(None, description="Override URL for fetching original webpage")
    mxcheck: bool = Field(False, description="Check if MX can intercept emails")
    banners: bool = Field(False, description="Grab HTTP/SMTP banners")
    useragent: Optional[str] = Field(None, description="Custom User-Agent string")
    forward: bool = Field(False, description="Forward results to callback URL")
    # Tracking fields
    customer: Optional[str] = Field(None, description="Customer name for tracking")
    tracking_id: Optional[str] = Field(None, description="Custom tracking/reference ID")
    metadata: Optional[dict] = Field(None, description="Additional metadata to include in callback")
    # Callback override
    callback_url: Optional[str] = Field(None, description="Override callback URL for this request")
    # Async mode - return immediately, run scan in background
    async_mode: Optional[bool] = Field(False, description="Run scan in background and return immediately (requires forward=true)")


class ScanResponse(BaseModel):
    domain: str
    total: int
    registered: int
    results: List[dict]


# === Endpoints ===

@app.get("/", tags=["Health"])
def health():
    """Health check endpoint (no auth required)"""
    
    # Determine which auth method is configured for callback
    callback_auth_method = None
    if CALLBACK_API_KEY:
        callback_auth_method = f"api_key (header: {CALLBACK_API_KEY_HEADER})"
    elif CALLBACK_BEARER_TOKEN:
        callback_auth_method = "bearer_token"
    elif CALLBACK_BASIC_USER:
        callback_auth_method = "basic_auth"
    elif CALLBACK_CUSTOM_HEADER:
        callback_auth_method = f"custom_header ({CALLBACK_CUSTOM_HEADER})"
    
    return {
        "status": "ok",
        "service": "dnstwist-api",
        "version": "1.0.0",
        "auth_enabled": API_KEY is not None,
        "callback": {
            "configured": CALLBACK_URL is not None,
            "url": CALLBACK_URL[:50] + "..." if CALLBACK_URL and len(CALLBACK_URL) > 50 else CALLBACK_URL,
            "method": CALLBACK_METHOD,
            "auth_method": callback_auth_method
        },
        "dictionaries": {
            "tld": os.path.exists(TLD_DICT),
            "english": os.path.exists(ENGLISH_DICT),
            "path": DICT_PATH
        }
    }


@app.get("/dictionaries", tags=["Info"], dependencies=[Depends(verify_api_key)])
def list_dictionaries():
    """List available dictionary files"""
    dicts = []
    if os.path.exists(DICT_PATH):
        for f in os.listdir(DICT_PATH):
            if f.endswith('.dict'):
                filepath = os.path.join(DICT_PATH, f)
                with open(filepath) as file:
                    lines = [l.strip() for l in file if l.strip() and not l.startswith('#')]
                dicts.append({
                    "name": f,
                    "path": filepath,
                    "entries": len(lines)
                })
    return {"dictionaries": dicts}


@app.get("/fuzzers", tags=["Info"], dependencies=[Depends(verify_api_key)])
def list_fuzzers():
    """List all available fuzzing algorithms"""
    return {
        "fuzzers": [
            {"name": "addition", "description": "Appends single character at the end"},
            {"name": "bitsquatting", "description": "Single bit flip in character"},
            {"name": "homoglyph", "description": "Similar looking characters (IDN/Unicode)"},
            {"name": "hyphenation", "description": "Inserts hyphens between characters"},
            {"name": "insertion", "description": "Inserts characters at various positions"},
            {"name": "omission", "description": "Removes one character at a time"},
            {"name": "repetition", "description": "Repeats characters"},
            {"name": "replacement", "description": "Replaces with adjacent keyboard keys"},
            {"name": "subdomain", "description": "Prepends common words as subdomain"},
            {"name": "transposition", "description": "Swaps adjacent characters"},
            {"name": "vowel-swap", "description": "Swaps vowels with other vowels"},
            {"name": "dictionary", "description": "Replaces words with dictionary words (uses english.dict)"},
            {"name": "tld-swap", "description": "Swaps TLD with other TLDs (uses common_tlds.dict)"},
        ]
    }


@app.get("/scan", response_model=ScanResponse, tags=["Scanning"], dependencies=[Depends(verify_api_key)])
async def scan_get(
    background_tasks: BackgroundTasks,
    domain: str = Query(..., description="Domain to scan", example="example.com"),
    registered: bool = Query(False, description="Show only registered domains"),
    fuzzers: Optional[str] = Query(None, description="Comma-separated fuzzers", example="homoglyph,bitsquatting"),
    nameservers: Optional[str] = Query(None, description="Custom DNS servers", example="8.8.8.8,1.1.1.1"),
    threads: int = Query(10, ge=1, le=100, description="Number of threads"),
    whois: bool = Query(False, description="Perform WHOIS lookups"),
    geoip: bool = Query(False, description="GeoIP country lookup"),
    lsh: Optional[LshAlgorithm] = Query(None, description="Fuzzy hashing algorithm"),
    lsh_url: Optional[str] = Query(None, description="Custom URL for LSH comparison"),
    mxcheck: bool = Query(False, description="Check MX for email interception"),
    banners: bool = Query(False, description="Grab HTTP/SMTP banners"),
    forward: bool = Query(False, description="Forward results to callback URL"),
    # Tracking parameters
    customer: Optional[str] = Query(None, description="Customer name for tracking"),
    tracking_id: Optional[str] = Query(None, description="Custom tracking/reference ID"),
    # Callback override
    callback_url: Optional[str] = Query(None, description="Override callback URL for this request"),
):
    """
    Scan a domain for typosquatting and lookalike domains.
    
    **Basic scan:**
    ```
    /scan?domain=example.com
    ```
    
    **Registered only with specific fuzzers:**
    ```
    /scan?domain=example.com&registered=true&fuzzers=homoglyph,bitsquatting
    ```
    
    **TLD swap (uses common_tlds.dict):**
    ```
    /scan?domain=example.com&fuzzers=tld-swap&registered=true
    ```
    
    **Dictionary attack (uses english.dict):**
    ```
    /scan?domain=example.com&fuzzers=dictionary&registered=true
    ```
    
    **Full scan with all features:**
    ```
    /scan?domain=example.com&registered=true&whois=true&geoip=true&mxcheck=true&banners=true
    ```
    
    **Forward results to callback URL with customer tracking:**
    ```
    /scan?domain=example.com&registered=true&forward=true&customer=AcmeCorp&tracking_id=REQ-123
    ```
    
    **Override callback URL per request:**
    ```
    /scan?domain=example.com&forward=true&callback_url=https://my-callback.com/endpoint
    ```
    """
    result = _execute_scan(
        domain=domain,
        registered=registered,
        fuzzers=fuzzers,
        nameservers=nameservers,
        threads=threads,
        whois=whois,
        geoip=geoip,
        lsh=lsh,
        lsh_url=lsh_url,
        mxcheck=mxcheck,
        banners=banners,
    )
    
    # Add tracking info to result
    if customer:
        result["customer"] = customer
    if tracking_id:
        result["tracking_id"] = tracking_id
    
    # Forward to callback if requested
    if forward:
        effective_callback_url = callback_url or CALLBACK_URL
        if effective_callback_url:
            background_tasks.add_task(send_to_callback, result, effective_callback_url)
            result["callback_status"] = "queued"
            result["callback_url"] = effective_callback_url
        else:
            result["callback_status"] = "not_configured"
    
    return result


@app.post("/scan", tags=["Scanning"], dependencies=[Depends(verify_api_key)])
async def scan_post(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan a domain (POST version for complex requests).
    
    **Example with tracking:**
    ```json
    {
        "domain": "example.com",
        "registered": true,
        "forward": true,
        "customer": "AcmeCorp",
        "tracking_id": "REQ-12345",
        "metadata": {
            "department": "Security",
            "requested_by": "john@acme.com"
        }
    }
    ```
    
    **Example with async mode (returns immediately):**
    ```json
    {
        "domain": "example.com",
        "registered": true,
        "forward": true,
        "async_mode": true,
        "customer": "AcmeCorp",
        "callback_url": "https://my-function.azurewebsites.net/api/callback?code=xxx"
    }
    ```
    """
    effective_callback_url = request.callback_url or CALLBACK_URL
    
    # Async mode - return immediately, run scan in background
    if request.async_mode:
        if not request.forward or not effective_callback_url:
            raise HTTPException(
                status_code=400,
                detail="async_mode requires forward=true and a valid callback_url"
            )
        
        # Queue the scan to run in background
        background_tasks.add_task(
            run_scan_and_callback,
            domain=request.domain,
            registered=request.registered,
            fuzzers=request.fuzzers,
            nameservers=request.nameservers,
            threads=request.threads,
            whois=request.whois,
            geoip=request.geoip,
            lsh=request.lsh,
            lsh_url=request.lsh_url,
            mxcheck=request.mxcheck,
            banners=request.banners,
            useragent=request.useragent,
            customer=request.customer,
            tracking_id=request.tracking_id,
            metadata=request.metadata,
            callback_url=effective_callback_url
        )
        
        # Return immediately with queued status
        return {
            "status": "queued",
            "domain": request.domain,
            "customer": request.customer,
            "tracking_id": request.tracking_id,
            "callback_url": effective_callback_url,
            "message": "Scan queued. Results will be sent to callback URL when complete."
        }
    
    # Synchronous mode - run scan and return results
    result = _execute_scan(
        domain=request.domain,
        registered=request.registered,
        fuzzers=request.fuzzers,
        nameservers=request.nameservers,
        threads=request.threads,
        whois=request.whois,
        geoip=request.geoip,
        lsh=request.lsh,
        lsh_url=request.lsh_url,
        mxcheck=request.mxcheck,
        banners=request.banners,
        useragent=request.useragent,
    )
    
    # Add tracking info to result
    if request.customer:
        result["customer"] = request.customer
    if request.tracking_id:
        result["tracking_id"] = request.tracking_id
    if request.metadata:
        result["metadata"] = request.metadata
    
    # Forward to callback if requested
    if request.forward:
        if effective_callback_url:
            background_tasks.add_task(send_to_callback, result, effective_callback_url)
            result["callback_status"] = "queued"
            result["callback_url"] = effective_callback_url
        else:
            result["callback_status"] = "not_configured"
    
    return result


@app.get("/scan/csv", tags=["Scanning"], dependencies=[Depends(verify_api_key)])
def scan_csv(
    domain: str = Query(..., description="Domain to scan"),
    registered: bool = Query(False),
    fuzzers: Optional[str] = Query(None),
    nameservers: Optional[str] = Query(None),
    threads: int = Query(10, ge=1, le=100),
):
    """Export scan results as CSV"""
    try:
        kwargs = _build_kwargs(
            domain=domain,
            registered=registered,
            fuzzers=fuzzers,
            nameservers=nameservers,
            threads=threads,
            format_type="csv",
        )
        result = dnstwist.run(**kwargs)
        return Response(
            content=result,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=dnstwist_{domain}.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/permutations", tags=["Scanning"], dependencies=[Depends(verify_api_key)])
def permutations(
    domain: str = Query(..., description="Domain to generate permutations for"),
    fuzzers: Optional[str] = Query(None, description="Comma-separated fuzzers"),
):
    """
    Generate domain permutations WITHOUT DNS lookups (passive mode).
    Very fast - useful for getting the list of domains to check.
    """
    try:
        effective_fuzzers = ALL_FUZZERS if (fuzzers and fuzzers.strip().lower() == "all") else fuzzers
        kwargs = {
            "domain": domain,
            "format": "list",
            "output": dnstwist.devnull,
        }
        if effective_fuzzers:
            kwargs["fuzzers"] = effective_fuzzers

        # Add dictionaries if needed
        fuzzers_list = effective_fuzzers.split(",") if effective_fuzzers else []
        if "tld-swap" in fuzzers_list and os.path.exists(TLD_DICT):
            kwargs["tld"] = TLD_DICT
        if "dictionary" in fuzzers_list and os.path.exists(ENGLISH_DICT):
            kwargs["dictionary"] = ENGLISH_DICT

        results = dnstwist.run(**kwargs)
        domains = [r.get("domain") for r in results if r.get("domain")]

        return {
            "domain": domain,
            "total": len(domains),
            "permutations": domains
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/permutations/list", response_class=PlainTextResponse, tags=["Scanning"], dependencies=[Depends(verify_api_key)])
def permutations_list(
    domain: str = Query(..., description="Domain"),
    fuzzers: Optional[str] = Query(None),
):
    """Get permutations as plain text (one per line)"""
    try:
        effective_fuzzers = ALL_FUZZERS if (fuzzers and fuzzers.strip().lower() == "all") else fuzzers
        kwargs = {
            "domain": domain,
            "format": "list",
            "output": dnstwist.devnull,
        }
        if effective_fuzzers:
            kwargs["fuzzers"] = effective_fuzzers

        # Add dictionaries if needed
        fuzzers_list = effective_fuzzers.split(",") if effective_fuzzers else []
        if "tld-swap" in fuzzers_list and os.path.exists(TLD_DICT):
            kwargs["tld"] = TLD_DICT
        if "dictionary" in fuzzers_list and os.path.exists(ENGLISH_DICT):
            kwargs["dictionary"] = ENGLISH_DICT

        results = dnstwist.run(**kwargs)
        domains = [r.get("domain") for r in results if r.get("domain")]

        return "\n".join(domains)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Helper Functions ===

def _build_kwargs(
    domain: str,
    registered: bool = False,
    fuzzers: Optional[str] = None,
    nameservers: Optional[str] = None,
    threads: int = 10,
    whois: bool = False,
    geoip: bool = False,
    lsh: Optional[LshAlgorithm] = None,
    lsh_url: Optional[str] = None,
    mxcheck: bool = False,
    banners: bool = False,
    useragent: Optional[str] = None,
    format_type: str = "null",
) -> dict:
    """Build kwargs dict for dnstwist.run()"""
    kwargs = {
        "domain": domain,
        "format": format_type,
        "threads": threads,
    }
    
    if registered:
        kwargs["registered"] = True
    if fuzzers:
        # "all" expands to every available fuzzer
        kwargs["fuzzers"] = ALL_FUZZERS if fuzzers.strip().lower() == "all" else fuzzers
    if nameservers:
        kwargs["nameservers"] = nameservers
    if whois:
        kwargs["whois"] = True
    if geoip:
        kwargs["geoip"] = True
    if lsh:
        kwargs["lsh"] = lsh.value
    if lsh_url:
        kwargs["lsh_url"] = lsh_url
    if mxcheck:
        kwargs["mxcheck"] = True
    if banners:
        kwargs["banners"] = True
    if useragent:
        kwargs["useragent"] = useragent
    
    # Add dictionaries based on fuzzers
    fuzzers_list = fuzzers.split(",") if fuzzers else []
    if "tld-swap" in fuzzers_list and os.path.exists(TLD_DICT):
        kwargs["tld"] = TLD_DICT
    if "dictionary" in fuzzers_list and os.path.exists(ENGLISH_DICT):
        kwargs["dictionary"] = ENGLISH_DICT
    
    return kwargs


def _execute_scan(
    domain: str,
    registered: bool = False,
    fuzzers: Optional[str] = None,
    nameservers: Optional[str] = None,
    threads: int = 10,
    whois: bool = False,
    geoip: bool = False,
    lsh: Optional[LshAlgorithm] = None,
    lsh_url: Optional[str] = None,
    mxcheck: bool = False,
    banners: bool = False,
    useragent: Optional[str] = None,
) -> dict:
    """Execute dnstwist scan and return results"""
    try:
        kwargs = _build_kwargs(
            domain=domain,
            registered=registered,
            fuzzers=fuzzers,
            nameservers=nameservers,
            threads=threads,
            whois=whois,
            geoip=geoip,
            lsh=lsh,
            lsh_url=lsh_url,
            mxcheck=mxcheck,
            banners=banners,
            useragent=useragent,
        )
        
        results = dnstwist.run(**kwargs)
        
        # Count registered domains
        registered_count = sum(
            1 for r in results
            if r.get("dns_a") or r.get("dns_aaaa") or r.get("dns_mx") or r.get("dns_ns")
        )
        
        return {
            "domain": domain,
            "total": len(results),
            "registered": registered_count,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
