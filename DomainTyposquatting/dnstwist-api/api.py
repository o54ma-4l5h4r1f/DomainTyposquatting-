"""
DNSTwist API
Domain name permutation engine for detecting typosquatting,
phishing attacks, and brand impersonation.

Endpoints:
- POST /scan             - Scan domain (primary)
- GET  /scan             - Scan domain (query params)
- GET  /scan/csv         - Export scan as CSV
- GET  /permutations     - Generate permutations (no DNS)
- GET  /permutations/list- Permutations as plain text
- GET  /fuzzers          - List available fuzzers
- GET  /dictionaries     - List dictionary files
- GET  /api/health       - Health check
"""
from fastapi import FastAPI, Query, HTTPException, Response
from fastapi.responses import PlainTextResponse
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum
import dnstwist
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DNSTwist API",
    description="Domain name permutation engine for detecting typosquatting, phishing attacks, and brand impersonation.",
    version="2.0.0",
)

# === Configuration ===
DICT_PATH = os.environ.get("DNSTWIST_DICTIONARIES", "/app/dictionaries")
TLD_DICT = os.path.join(DICT_PATH, "common_tlds.dict")
ENGLISH_DICT = os.path.join(DICT_PATH, "english.dict")

ALL_FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission,repetition,replacement,subdomain,transposition,vowel-swap,dictionary,tld-swap"


# === Enums & Models ===


class LshAlgorithm(str, Enum):
    ssdeep = "ssdeep"
    tlsh = "tlsh"


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Domain name to scan")
    registered: bool = Field(False, description="Show only registered (resolvable) domains")
    fuzzers: Optional[str] = Field(None, description="Comma-separated list of fuzzers, or 'all'")
    nameservers: Optional[str] = Field(None, description="Custom DNS servers (comma-separated)")
    threads: int = Field(10, ge=1, le=100, description="Number of threads")
    whois: bool = Field(False, description="Perform WHOIS lookups")
    geoip: bool = Field(False, description="GeoIP country lookup")
    lsh: Optional[LshAlgorithm] = Field(None, description="Fuzzy hash algorithm for phishing detection")
    lsh_url: Optional[str] = Field(None, description="Override URL for fetching original webpage")
    mxcheck: bool = Field(False, description="Check if MX can intercept emails")
    banners: bool = Field(False, description="Grab HTTP/SMTP banners")
    useragent: Optional[str] = Field(None, description="Custom User-Agent string")


class ScanResponse(BaseModel):
    domain: str
    total: int
    registered: int
    results: List[dict]


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
    format_type: str = "list",
) -> dict:
    """Build kwargs dict for dnstwist.run()"""
    kwargs = {"domain": domain, "format": format_type, "threads": threads}

    if registered:
        kwargs["registered"] = True
    if fuzzers:
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
            domain=domain, registered=registered, fuzzers=fuzzers,
            nameservers=nameservers, threads=threads, whois=whois,
            geoip=geoip, lsh=lsh, lsh_url=lsh_url, mxcheck=mxcheck,
            banners=banners, useragent=useragent,
        )
        results = dnstwist.run(**kwargs)
        registered_count = sum(
            1 for r in results
            if r.get("dns_a") or r.get("dns_aaaa") or r.get("dns_mx") or r.get("dns_ns")
        )
        return {"domain": domain, "total": len(results), "registered": registered_count, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Endpoints ===


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
def scan_post(request: ScanRequest):
    """Scan a domain for typosquatting and lookalike domains (POST)."""
    return _execute_scan(
        domain=request.domain, registered=request.registered,
        fuzzers=request.fuzzers, nameservers=request.nameservers,
        threads=request.threads, whois=request.whois, geoip=request.geoip,
        lsh=request.lsh, lsh_url=request.lsh_url, mxcheck=request.mxcheck,
        banners=request.banners, useragent=request.useragent,
    )


@app.get("/scan", response_model=ScanResponse, tags=["Scanning"])
def scan_get(
    domain: str = Query(..., description="Domain to scan"),
    registered: bool = Query(False, description="Show only registered domains"),
    fuzzers: Optional[str] = Query(None, description="Comma-separated fuzzers"),
    nameservers: Optional[str] = Query(None, description="Custom DNS servers"),
    threads: int = Query(10, ge=1, le=100, description="Number of threads"),
    whois: bool = Query(False, description="Perform WHOIS lookups"),
    geoip: bool = Query(False, description="GeoIP country lookup"),
    lsh: Optional[LshAlgorithm] = Query(None, description="Fuzzy hashing algorithm"),
    lsh_url: Optional[str] = Query(None, description="Custom URL for LSH comparison"),
    mxcheck: bool = Query(False, description="Check MX for email interception"),
    banners: bool = Query(False, description="Grab HTTP/SMTP banners"),
):
    """Scan a domain for typosquatting and lookalike domains (GET)."""
    return _execute_scan(
        domain=domain, registered=registered, fuzzers=fuzzers,
        nameservers=nameservers, threads=threads, whois=whois,
        geoip=geoip, lsh=lsh, lsh_url=lsh_url, mxcheck=mxcheck,
        banners=banners,
    )


@app.get("/scan/csv", tags=["Scanning"])
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
            domain=domain, registered=registered, fuzzers=fuzzers,
            nameservers=nameservers, threads=threads, format_type="csv",
        )
        result = dnstwist.run(**kwargs)
        return Response(
            content=result, media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=dnstwist_{domain}.csv"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/permutations", tags=["Scanning"])
def permutations(
    domain: str = Query(..., description="Domain to generate permutations for"),
    fuzzers: Optional[str] = Query(None, description="Comma-separated fuzzers"),
):
    """Generate domain permutations WITHOUT DNS lookups (passive mode)."""
    try:
        effective_fuzzers = ALL_FUZZERS if (fuzzers and fuzzers.strip().lower() == "all") else fuzzers
        kwargs = {"domain": domain, "format": "list", "output": dnstwist.devnull}
        if effective_fuzzers:
            kwargs["fuzzers"] = effective_fuzzers

        fuzzers_list = effective_fuzzers.split(",") if effective_fuzzers else []
        if "tld-swap" in fuzzers_list and os.path.exists(TLD_DICT):
            kwargs["tld"] = TLD_DICT
        if "dictionary" in fuzzers_list and os.path.exists(ENGLISH_DICT):
            kwargs["dictionary"] = ENGLISH_DICT

        results = dnstwist.run(**kwargs)
        domains = [r.get("domain") for r in results if r.get("domain")]
        return {"domain": domain, "total": len(domains), "permutations": domains}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/permutations/list", response_class=PlainTextResponse, tags=["Scanning"])
def permutations_list(
    domain: str = Query(..., description="Domain"),
    fuzzers: Optional[str] = Query(None),
):
    """Get permutations as plain text (one per line)"""
    try:
        effective_fuzzers = ALL_FUZZERS if (fuzzers and fuzzers.strip().lower() == "all") else fuzzers
        kwargs = {"domain": domain, "format": "list", "output": dnstwist.devnull}
        if effective_fuzzers:
            kwargs["fuzzers"] = effective_fuzzers

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


@app.get("/fuzzers", tags=["Info"])
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
            {"name": "dictionary", "description": "Replaces words with dictionary words"},
            {"name": "tld-swap", "description": "Swaps TLD with other TLDs"},
        ]
    }


@app.get("/dictionaries", tags=["Info"])
def list_dictionaries():
    """List available dictionary files"""
    dicts = []
    if os.path.exists(DICT_PATH):
        for f in os.listdir(DICT_PATH):
            if f.endswith(".dict"):
                filepath = os.path.join(DICT_PATH, f)
                with open(filepath) as file:
                    lines = [l.strip() for l in file if l.strip() and not l.startswith("#")]
                dicts.append({"name": f, "path": filepath, "entries": len(lines)})
    return {"dictionaries": dicts}


@app.get("/api/health", tags=["Health"])
def health():
    """Health check"""
    return {
        "status": "ok",
        "service": "dnstwist-api",
        "dictionaries": {
            "tld": os.path.exists(TLD_DICT),
            "english": os.path.exists(ENGLISH_DICT),
        },
    }
