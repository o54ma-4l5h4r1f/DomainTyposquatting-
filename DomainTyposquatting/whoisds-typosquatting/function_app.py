import azure.functions as func
import logging
import requests
import zipfile
import io
import os
from datetime import datetime
from azure.storage.blob import BlobServiceClient, ContainerClient
import json
from typing import List, Dict, Tuple

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Configuration - Set these in your Azure Function App Settings
STORAGE_CONNECTION_STRING = os.environ.get("AzureWebJobsStorage")
CONTAINER_NAME = os.environ.get("CONTAINER_NAME", "whoisds-typosquatting")
NRD_FOLDER = "nrd-files"                   # Folder (prefix) inside container
RESULTS_FOLDER = "matched-results"         # Folder (prefix) inside container


def get_blob_service_client() -> BlobServiceClient:
    """Initialize and return blob service client"""
    return BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)


def ensure_containers_exist():
    """Ensure the main blob container exists"""
    blob_service_client = get_blob_service_client()
    
    try:
        blob_service_client.create_container(CONTAINER_NAME)
        logging.info(f"Container '{CONTAINER_NAME}' created")
    except Exception as e:
        logging.info(f"Container '{CONTAINER_NAME}' already exists or error: {str(e)}")


def check_file_exists_in_blob(blob_name: str, folder: str = "") -> bool:
    """Check if a file already exists in blob storage
    
    Args:
        blob_name: Name of the blob file
        folder: Folder prefix (e.g., 'nrd-files' or 'matched-results')
    """
    try:
        blob_service_client = get_blob_service_client()
        
        # Construct full blob path with folder prefix
        full_blob_path = f"{folder}/{blob_name}" if folder else blob_name
        
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME, 
            blob=full_blob_path
        )
        return blob_client.exists()
    except Exception as e:
        logging.error(f"Error checking file existence: {str(e)}")
        return False


def upload_to_blob(file_content: str, blob_name: str, folder: str = "") -> bool:
    """Upload content to blob storage
    
    Args:
        file_content: Content to upload
        blob_name: Name of the blob file
        folder: Folder prefix (e.g., 'nrd-files' or 'matched-results')
    """
    try:
        blob_service_client = get_blob_service_client()
        
        # Construct full blob path with folder prefix
        full_blob_path = f"{folder}/{blob_name}" if folder else blob_name
        
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME, 
            blob=full_blob_path
        )
        blob_client.upload_blob(file_content, overwrite=True)
        logging.info(f"File uploaded to blob: {full_blob_path}")
        return True
    except Exception as e:
        logging.error(f"Error uploading to blob: {str(e)}")
        return False


def download_from_blob(blob_name: str, folder: str = "") -> str:
    """Download content from blob storage
    
    Args:
        blob_name: Name of the blob file
        folder: Folder prefix (e.g., 'nrd-files' or 'matched-results')
    """
    try:
        blob_service_client = get_blob_service_client()
        
        # Construct full blob path with folder prefix
        full_blob_path = f"{folder}/{blob_name}" if folder else blob_name
        
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME, 
            blob=full_blob_path
        )
        download_stream = blob_client.download_blob()
        return download_stream.readall().decode('utf-8')
    except Exception as e:
        logging.error(f"Error downloading from blob: {str(e)}")
        raise


@app.route(route="download_nrd", methods=["GET", "POST"])
def download_nrd(req: func.HttpRequest) -> func.HttpResponse:
    """
    Download NRD file from whoisds.com, unzip, and store in blob storage
    Parameters: email, password, date (format: YYYY-MM-DD)
    """
    logging.info('Download NRD function triggered')
    
    try:
        # Ensure containers exist
        ensure_containers_exist()
        
        # Get parameters from query string or body
        email = req.params.get('email')
        password = req.params.get('password')
        date = req.params.get('date')
        
        if not email or not password or not date:
            try:
                req_body = req.get_json()
                email = email or req_body.get('email')
                password = password or req_body.get('password')
                date = date or req_body.get('date')
            except ValueError:
                pass
        
        # Validate required parameters
        if not all([email, password, date]):
            return func.HttpResponse(
                json.dumps({
                    "error": "Missing required parameters",
                    "required": ["email", "password", "date"]
                }),
                status_code=400,
                mimetype="application/json"
            )
        
        # Validate date format
        try:
            datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid date format. Use YYYY-MM-DD"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Expected file name in blob storage
        blob_file_name = f"{date}-NRD.txt"
        
        # Check if file already exists
        if check_file_exists_in_blob(blob_file_name, NRD_FOLDER):
            logging.info(f"File {NRD_FOLDER}/{blob_file_name} already exists in blob storage")
            return func.HttpResponse(
                json.dumps({
                    "status": "already_exists",
                    "message": f"File {blob_file_name} already exists in blob storage",
                    "file_name": blob_file_name,
                    "full_path": f"{NRD_FOLDER}/{blob_file_name}"
                }),
                status_code=200,
                mimetype="application/json"
            )
        
        # Construct download URL
        download_url = f"https://www.whoisds.com/your-download/direct-download-file/{email}/password/{date}.zip/ddu/home"
        
        # Replace "password" placeholder with actual password in URL
        download_url = download_url.replace("/password/", f"/{password}/")
        
        logging.info(f"Downloading from: {download_url}")
        
        # Download the ZIP file
        response = requests.get(download_url, timeout=120, stream=True)
        
        if response.status_code != 200:
            return func.HttpResponse(
                json.dumps({
                    "error": f"Failed to download file. Status code: {response.status_code}",
                    "url": download_url.replace(password, "***"),  # Hide password in logs
                    "response_text": response.text[:200] if response.text else "No response text"
                }),
                status_code=500,
                mimetype="application/json"
            )
        
        # Check if we got a ZIP file
        content = response.content
        logging.info(f"Downloaded {len(content)} bytes. First 4 bytes: {content[:4]}")
        
        # Check for ZIP file signature (PK - 0x504B)
        if not content.startswith(b'PK'):
            # Not a ZIP file - might be an error page
            logging.error(f"Response is not a ZIP file. Content preview: {content[:500]}")
            return func.HttpResponse(
                json.dumps({
                    "error": "Downloaded file is not a ZIP file",
                    "content_preview": content[:500].decode('utf-8', errors='ignore'),
                    "content_type": response.headers.get('Content-Type', 'unknown')
                }),
                status_code=500,
                mimetype="application/json"
            )
        
        # Save to temporary file first (more reliable than BytesIO)
        import tempfile
        temp_zip_path = tempfile.mktemp(suffix='.zip')
        temp_txt_path = tempfile.mktemp(suffix='.txt')
        
        try:
            # Write ZIP to temp file
            with open(temp_zip_path, 'wb') as f:
                f.write(content)
            
            # Unzip the file
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                # Get list of files in the zip
                file_list = zip_ref.namelist()
                logging.info(f"Files in ZIP: {file_list}")
                
                # Find the .txt file
                txt_files = [f for f in file_list if f.endswith('.txt')]
                
                if not txt_files:
                    return func.HttpResponse(
                        json.dumps({
                            "error": "No .txt file found in the ZIP archive",
                            "files_found": file_list
                        }),
                        status_code=500,
                        mimetype="application/json"
                    )
                
                # Extract and read the first .txt file
                txt_file_name = txt_files[0]
                zip_ref.extract(txt_file_name, path=os.path.dirname(temp_txt_path))
                extracted_path = os.path.join(os.path.dirname(temp_txt_path), txt_file_name)
                
                with open(extracted_path, 'r', encoding='utf-8') as txt_file:
                    file_content = txt_file.read()
                
                # Clean up extracted file
                if os.path.exists(extracted_path):
                    os.remove(extracted_path)
        
        finally:
            # Clean up temp ZIP file
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
        
        # Upload to blob storage with standardized name
        if upload_to_blob(file_content, blob_file_name, NRD_FOLDER):
            return func.HttpResponse(
                json.dumps({
                    "status": "success",
                    "message": "File downloaded, extracted, and uploaded successfully",
                    "file_name": blob_file_name,
                    "full_path": f"{NRD_FOLDER}/{blob_file_name}",
                    "original_file": txt_file_name,
                    "file_size": len(file_content)
                }),
                status_code=200,
                mimetype="application/json"
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": "Failed to upload file to blob storage"}),
                status_code=500,
                mimetype="application/json"
            )
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Download failed: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error in download_nrd: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Internal error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )


@app.route(route="search_keywords", methods=["POST"])
def search_keywords(req: func.HttpRequest) -> func.HttpResponse:
    """
    Search for keywords in NRD file and store results
    Request body: {"Customer": "CustomerName", "Keywords": ["keyword1", "keyword2"], "date": "YYYY-MM-DD"}
    """
    logging.info('Search keywords function triggered')
    
    try:
        # Ensure containers exist
        ensure_containers_exist()
        
        # Parse request body
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid JSON in request body"}),
                status_code=400,
                mimetype="application/json"
            )
        
        customer = req_body.get('Customer')
        keywords = req_body.get('Keywords')
        date = req_body.get('date')
        
        # Validate parameters
        if not customer or not keywords or not date:
            return func.HttpResponse(
                json.dumps({
                    "error": "Missing required fields",
                    "required": ["Customer", "Keywords", "date"]
                }),
                status_code=400,
                mimetype="application/json"
            )
        
        if not isinstance(keywords, list) or len(keywords) == 0:
            return func.HttpResponse(
                json.dumps({"error": "Keywords must be a non-empty list"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Validate date format
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid date format. Use YYYY-MM-DD"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Clean and normalize keywords (trim spaces and convert to lowercase)
        cleaned_keywords = [kw.strip().lower() for kw in keywords if kw.strip()]
        
        if not cleaned_keywords:
            return func.HttpResponse(
                json.dumps({"error": "No valid keywords after cleaning"}),
                status_code=400,
                mimetype="application/json"
            )
        
        logging.info(f"Searching for keywords: {cleaned_keywords}")
        
        # Get the NRD file name
        nrd_file_name = f"{date}-NRD.txt"
        
        # Check if NRD file exists
        if not check_file_exists_in_blob(nrd_file_name, NRD_FOLDER):
            return func.HttpResponse(
                json.dumps({
                    "error": f"NRD file not found for date {date}",
                    "expected_path": f"{NRD_FOLDER}/{nrd_file_name}",
                    "suggestion": "Please run download_nrd first for this date"
                }),
                status_code=404,
                mimetype="application/json"
            )
        
        # Download NRD file content
        nrd_content = download_from_blob(nrd_file_name, NRD_FOLDER)
        
        # Search for matches
        matches = []
        lines = nrd_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            if not line_lower:
                continue
            
            for keyword in cleaned_keywords:
                if keyword in line_lower:
                    matches.append({
                        "line_number": line_num,
                        "content": line.strip(),
                        "matched_keyword": keyword
                    })
                    break  # Only count each line once even if multiple keywords match
        
        # Prepare results
        results = {
            "customer": customer,
            "date": date,
            "keywords_searched": cleaned_keywords,
            "total_matches": len(matches),
            "matches": matches,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Create folder structure: matched-results / Customer Name / Month / Daily Results
        month_folder = date_obj.strftime('%Y-%m')  # e.g., "2026-01"
        customer_safe = customer.replace(' ', '_').replace('/', '-')
        
        # Full blob path: matched-results/Customer_Name/2026-01/2026-01-20-matches.json
        results_blob_path = f"{customer_safe}/{month_folder}/{date}-matches.json"
        
        # Upload results to blob storage
        results_json = json.dumps(results, indent=2)
        if upload_to_blob(results_json, results_blob_path, RESULTS_FOLDER):
            logging.info(f"Results stored at: {RESULTS_FOLDER}/{results_blob_path}")
        
        # Return results
        return func.HttpResponse(
            json.dumps({
                "status": "success",
                "customer": customer,
                "date": date,
                "keywords_searched": cleaned_keywords,
                "total_matches": len(matches),
                "matches": matches,
                "results_stored_at": f"{RESULTS_FOLDER}/{results_blob_path}"
            }, indent=2),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Error in search_keywords: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Internal error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )


@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Simple health check endpoint"""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "storage": {
                "container": CONTAINER_NAME,
                "folders": {
                    "nrd_files": NRD_FOLDER,
                    "results": RESULTS_FOLDER
                }
            }
        }),
        status_code=200,
        mimetype="application/json"
    )