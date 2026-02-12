"""
DNSTwist Orchestrator - Azure Function App
Orchestrates domain scanning via dnstwist API and stores results in Azure Blob Storage

Endpoints:
- POST /api/scan          - Submit domains for scanning
- POST /api/callback      - Receive results from dnstwist API
- GET  /api/status        - Get pending/running scans
- GET  /api/results       - Get domains found for customer/month
"""

import azure.functions as func
import logging
import json
import os
import httpx
from datetime import datetime, timezone
from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient, TableClient
import uuid

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# === Configuration from Environment ===
DNSTWIST_API_URL = os.environ.get("DNSTWIST_API_URL", "")
DNSTWIST_API_KEY = os.environ.get("DNSTWIST_API_KEY", "")
STORAGE_CONNECTION_STRING = os.environ.get("AzureWebJobsStorage", "")
BLOB_CONTAINER_NAME = os.environ.get("BLOB_CONTAINER_NAME", "dnstwist-typosquatting")
TABLE_NAME = os.environ.get("TABLE_NAME", "dnstwisttasks")

# === Helper Functions ===

def get_blob_service_client():
    """Get Azure Blob Storage client"""
    return BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)

def get_table_client():
    """Get Azure Table Storage client for task tracking"""
    service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    # Create table if not exists
    try:
        service.create_table(TABLE_NAME)
    except:
        pass  # Table already exists
    return service.get_table_client(TABLE_NAME)

def ensure_container_exists():
    """Ensure blob container exists"""
    blob_service = get_blob_service_client()
    try:
        blob_service.create_container(BLOB_CONTAINER_NAME)
    except:
        pass  # Container already exists

def read_blob_text(blob_path: str) -> str:
    """Read text from blob, return empty string if not exists"""
    try:
        blob_service = get_blob_service_client()
        blob_client = blob_service.get_blob_client(BLOB_CONTAINER_NAME, blob_path)
        return blob_client.download_blob().readall().decode('utf-8')
    except:
        return ""

def write_blob_text(blob_path: str, content: str):
    """Write text to blob (overwrite)"""
    ensure_container_exists()
    blob_service = get_blob_service_client()
    blob_client = blob_service.get_blob_client(BLOB_CONTAINER_NAME, blob_path)
    blob_client.upload_blob(content.encode('utf-8'), overwrite=True)

def append_domains_to_blob(blob_path: str, new_domains: list, exclude_set: set = None) -> int:
    """
    Append new domains to blob, skip duplicates, return count of new domains.
    
    Args:
        blob_path: Path to the blob file
        new_domains: List of domains to add
        exclude_set: Optional set of domains to also exclude (e.g., all_domains.txt contents)
    """
    existing_content = read_blob_text(blob_path)
    existing_domains = set(d.strip() for d in existing_content.splitlines() if d.strip())
    
    # Combine existing domains with exclude set
    all_excluded = existing_domains.copy()
    if exclude_set:
        all_excluded.update(exclude_set)
    
    new_unique = [d for d in new_domains if d not in all_excluded]
    
    if new_unique:
        all_domains = sorted(existing_domains | set(new_unique))
        write_blob_text(blob_path, "\n".join(all_domains))
    
    return len(new_unique)

def add_task(customer: str, domain: str, tracking_id: str):
    """Add a task to tracking table"""
    try:
        table_client = get_table_client()
        entity = {
            "PartitionKey": customer,
            "RowKey": tracking_id,
            "domain": domain,
            "status": "pending",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None
        }
        table_client.upsert_entity(entity)
    except Exception as e:
        logging.error(f"Failed to add task: {e}")

def complete_task(customer: str, tracking_id: str):
    """Mark a task as completed"""
    try:
        table_client = get_table_client()
        entity = table_client.get_entity(customer, tracking_id)
        entity["status"] = "completed"
        entity["completed_at"] = datetime.now(timezone.utc).isoformat()
        table_client.upsert_entity(entity)
    except Exception as e:
        logging.error(f"Failed to complete task: {e}")

def get_pending_tasks(customer: str = None) -> list:
    """Get all pending tasks, optionally filtered by customer"""
    try:
        table_client = get_table_client()
        if customer:
            query = f"PartitionKey eq '{customer}' and status eq 'pending'"
        else:
            query = "status eq 'pending'"
        
        entities = table_client.query_entities(query)
        return [dict(e) for e in entities]
    except Exception as e:
        logging.error(f"Failed to get pending tasks: {e}")
        return []


# === HTTP Trigger: Submit Scan ===
@app.route(route="scan", methods=["POST"])
async def submit_scan(req: func.HttpRequest) -> func.HttpResponse:
    """
    Submit domains for scanning.
    
    Request body:
    {
        "customer": "AcmeCorp",
        "domains": ["example.com", "another.com"],
        "registered": true,
        "fuzzers": "homoglyph,bitsquatting",  // optional
        "whois": false,                        // optional
        "geoip": false                         // optional
    }
    
    Response:
    {
        "status": "submitted",
        "customer": "AcmeCorp",
        "domains_submitted": 2,
        "tracking_ids": ["uuid1", "uuid2"]
    }
    """
    logging.info("Submit scan request received")
    
    # Validate configuration
    if not DNSTWIST_API_URL:
        return func.HttpResponse(
            json.dumps({"error": "DNSTWIST_API_URL not configured"}),
            status_code=500,
            mimetype="application/json"
        )
    
    try:
        body = req.get_json()
    except:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )
    
    # Validate required fields
    customer = body.get("customer")
    domains = body.get("domains", [])
    
    if not customer:
        return func.HttpResponse(
            json.dumps({"error": "customer is required"}),
            status_code=400,
            mimetype="application/json"
        )
    
    if not domains or not isinstance(domains, list):
        return func.HttpResponse(
            json.dumps({"error": "domains must be a non-empty list"}),
            status_code=400,
            mimetype="application/json"
        )
    
    # Optional parameters
    registered = body.get("registered", True)
    fuzzers = body.get("fuzzers", None)
    whois = body.get("whois", False)
    geoip = body.get("geoip", False)
    
    # Get callback URL (this function's callback endpoint)
    callback_url = body.get("callback_url")
    if not callback_url:
        # Try to build from request URL
        host = req.headers.get("Host", "")
        scheme = "https" if "https" in req.url else "http"
        callback_url = f"{scheme}://{host}/api/callback"
    
    # Submit each domain to dnstwist API
    tracking_ids = []
    submitted = []
    errors = []
    
    # API returns immediately with async_mode, so normal timeout is fine
    async with httpx.AsyncClient(timeout=30.0) as client:
        for domain in domains:
            tracking_id = str(uuid.uuid4())
            tracking_ids.append(tracking_id)
            
            # Build request payload - use async_mode for immediate return
            payload = {
                "domain": domain,
                "registered": registered,
                "forward": True,
                "async_mode": True,  # Return immediately, scan in background
                "callback_url": callback_url,
                "customer": customer,
                "tracking_id": tracking_id
            }
            
            if fuzzers:
                payload["fuzzers"] = fuzzers
            if whois:
                payload["whois"] = True
            if geoip:
                payload["geoip"] = True
            
            try:
                headers = {
                    "Content-Type": "application/json",
                    "X-API-Key": DNSTWIST_API_KEY
                }
                
                response = await client.post(
                    f"{DNSTWIST_API_URL}/scan",
                    json=payload,
                    headers=headers
                )
                
                if response.status_code == 200:
                    # Track the task
                    add_task(customer, domain, tracking_id)
                    submitted.append(domain)
                    logging.info(f"Queued scan for {domain}, tracking_id: {tracking_id}")
                else:
                    errors.append({
                        "domain": domain,
                        "error": f"API returned {response.status_code}: {response.text}"
                    })
                    
            except Exception as e:
                logging.error(f"Error submitting {domain}: {str(e)}")
                errors.append({
                    "domain": domain,
                    "error": str(e)
                })
    
    result = {
        "status": "submitted",
        "customer": customer,
        "domains_submitted": len(submitted),
        "tracking_ids": tracking_ids,
        "callback_url": callback_url
    }
    
    if errors:
        result["errors"] = errors
    
    return func.HttpResponse(
        json.dumps(result, indent=2),
        status_code=200,
        mimetype="application/json"
    )


# === HTTP Trigger: Callback Receiver ===
@app.route(route="callback", methods=["POST"])
def receive_callback(req: func.HttpRequest) -> func.HttpResponse:
    """
    Receive results from dnstwist API callback.
    
    Stores results in Azure Blob Storage:
    - /{customer}/{YYYY-MM}/domains.txt     - Domains found this month
    - /{customer}/all_domains.txt           - All domains ever found (cumulative)
    """
    logging.info("Callback received from dnstwist API")
    
    try:
        body = req.get_json()
    except:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )
    
    # Extract data from callback
    customer = body.get("customer")
    tracking_id = body.get("tracking_id")
    source_domain = body.get("domain")
    results = body.get("results", [])
    timestamp = body.get("timestamp", datetime.now(timezone.utc).isoformat())
    
    if not customer:
        return func.HttpResponse(
            json.dumps({"error": "customer field is required"}),
            status_code=400,
            mimetype="application/json"
        )
    
    # Extract just the domain names from results (skip original)
    domains_found = []
    for result in results:
        fuzzer = result.get("fuzzer", "")
        domain = result.get("domain", "")
        
        # Skip the original domain
        if fuzzer == "*original" or domain == source_domain:
            continue
        
        if domain:
            domains_found.append(domain)
    
    if not domains_found:
        logging.info(f"No lookalike domains found for {source_domain}")
        if tracking_id:
            complete_task(customer, tracking_id)
        return func.HttpResponse(
            json.dumps({
                "status": "ok",
                "message": "No lookalike domains found",
                "customer": customer,
                "source_domain": source_domain
            }),
            status_code=200,
            mimetype="application/json"
        )
    
    # Get current month for folder
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except:
        dt = datetime.now(timezone.utc)
    
    month_folder = dt.strftime("%Y-%m")
    
    # File paths
    month_file = f"{customer}/{month_folder}/domains.txt"
    all_time_file = f"{customer}/all_domains.txt"
    
    # Read existing all-time domains first (for deduplication)
    all_time_content = read_blob_text(all_time_file)
    existing_all_time = set(d.strip() for d in all_time_content.splitlines() if d.strip())
    
    # Append to monthly file - exclude domains already in all_time
    # This ensures monthly file only has truly NEW domains
    new_monthly = append_domains_to_blob(month_file, domains_found, exclude_set=existing_all_time)
    
    # Append to all-time file (cumulative, deduplicated)
    new_alltime = append_domains_to_blob(all_time_file, domains_found)
    
    logging.info(f"Stored {new_monthly} new domains for {customer}/{month_folder}")
    logging.info(f"Added {new_alltime} new unique domains to all-time list")
    
    # Mark task as completed
    if tracking_id:
        complete_task(customer, tracking_id)
    
    return func.HttpResponse(
        json.dumps({
            "status": "ok",
            "customer": customer,
            "source_domain": source_domain,
            "domains_received": len(domains_found),
            "new_domains_this_month": new_monthly,
            "new_domains_all_time": new_alltime,
            "month": month_folder
        }),
        status_code=200,
        mimetype="application/json"
    )


# === HTTP Trigger: Get Status ===
@app.route(route="status", methods=["GET"])
def get_status(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get pending/running scan tasks.
    
    Query params:
    - customer (optional): Filter by customer name
    
    Example: /api/status?customer=AcmeCorp
    """
    logging.info("Status request received")
    
    customer = req.params.get("customer")
    
    pending_tasks = get_pending_tasks(customer)
    
    # Group by customer
    by_customer = {}
    for task in pending_tasks:
        cust = task.get("PartitionKey", "unknown")
        if cust not in by_customer:
            by_customer[cust] = []
        by_customer[cust].append({
            "domain": task.get("domain"),
            "tracking_id": task.get("RowKey"),
            "submitted_at": task.get("submitted_at"),
            "status": task.get("status")
        })
    
    result = {
        "pending_count": len(pending_tasks),
        "by_customer": by_customer
    }
    
    if customer:
        result["filter"] = {"customer": customer}
    
    return func.HttpResponse(
        json.dumps(result, indent=2),
        status_code=200,
        mimetype="application/json"
    )


# === HTTP Trigger: Get Results ===
@app.route(route="results", methods=["GET"])
def get_results(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get domains found for a customer.
    
    Query params:
    - customer (required): Customer name
    - month (optional): Month in YYYY-MM format (default: current month)
    - all_time (optional): If "true", return all-time domains instead
    
    Examples:
    - /api/results?customer=AcmeCorp
    - /api/results?customer=AcmeCorp&month=2026-01
    - /api/results?customer=AcmeCorp&all_time=true
    """
    logging.info("Results request received")
    
    customer = req.params.get("customer")
    month = req.params.get("month")
    all_time = req.params.get("all_time", "").lower() == "true"
    
    if not customer:
        return func.HttpResponse(
            json.dumps({"error": "customer parameter is required"}),
            status_code=400,
            mimetype="application/json"
        )
    
    # Determine which file to read
    if all_time:
        blob_path = f"{customer}/all_domains.txt"
        period = "all_time"
    else:
        if not month:
            month = datetime.now(timezone.utc).strftime("%Y-%m")
        blob_path = f"{customer}/{month}/domains.txt"
        period = month
    
    # Read domains from blob
    content = read_blob_text(blob_path)
    domains = [d.strip() for d in content.splitlines() if d.strip()]
    
    result = {
        "customer": customer,
        "period": period,
        "domains_count": len(domains),
        "domains": domains
    }
    
    return func.HttpResponse(
        json.dumps(result, indent=2),
        status_code=200,
        mimetype="application/json"
    )


# === HTTP Trigger: List Customers ===
@app.route(route="customers", methods=["GET"])
def list_customers(req: func.HttpRequest) -> func.HttpResponse:
    """
    List all customers with stored results.
    """
    logging.info("List customers request received")
    
    try:
        blob_service = get_blob_service_client()
        container_client = blob_service.get_container_client(BLOB_CONTAINER_NAME)
        
        customers = set()
        blobs = container_client.list_blobs()
        
        for blob in blobs:
            # Extract customer name from path (first segment)
            parts = blob.name.split("/")
            if parts:
                customers.add(parts[0])
        
        return func.HttpResponse(
            json.dumps({
                "customers": sorted(list(customers)),
                "count": len(customers)
            }, indent=2),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


# === HTTP Trigger: Health Check ===
@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint"""
    return func.HttpResponse(
        json.dumps({
            "status": "ok",
            "service": "dnstwist-orchestrator",
            "dnstwist_api_configured": bool(DNSTWIST_API_URL),
            "storage_configured": bool(STORAGE_CONNECTION_STRING)
        }),
        status_code=200,
        mimetype="application/json"
    )
