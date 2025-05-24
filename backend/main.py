import os
import uuid
import tempfile
import shutil
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pathlib import Path

import whois
import dns.resolver
import requests
import ssl
import socket
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import vt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

# Import the ChatGPT impact analysis helper
from chatgpt_impact import analyze_domain_impact

# --- Logging for OpenAI and VirusTotal API requests and responses ---
import logging
logger = logging.getLogger(__name__)


from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
import json
import logging
from PIL import Image as PILImage
import aiofiles
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Log to console
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="TakedownIQ API", 
              description="API for analyzing suspicious domains",
              version="1.0.0")

# Configure CORS - allow all origins for troubleshooting
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for troubleshooting
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Create temp directory for file storage during processing
# Always use a directory in the current working directory for reliability
TEMP_DIR = Path(os.getcwd()) / "temp"
os.makedirs(TEMP_DIR, mode=0o755, exist_ok=True)
logger.info(f"Created temporary directory at: {TEMP_DIR}")

# Ensure the directory is writable
if not os.access(TEMP_DIR, os.W_OK):
    logger.warning(f"Temporary directory {TEMP_DIR} is not writable, attempting to fix permissions")
    try:
        os.chmod(TEMP_DIR, 0o755)
    except Exception as perm_error:
        logger.error(f"Could not fix permissions on {TEMP_DIR}: {perm_error}")

# In-memory storage for active analysis sessions
# This will be lost when the server restarts
try:
    active_sessions: Dict[str, Dict[str, Any]] = {}
    logger.info("Initialized active sessions storage")
except Exception as session_error:
    logger.error(f"Error initializing active sessions: {session_error}")
    active_sessions = {}

# VirusTotal API key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if VIRUSTOTAL_API_KEY:
    logger.info(f"VirusTotal API Key loaded, starts with: {VIRUSTOTAL_API_KEY[:4]}...")
else:
    logger.error("VirusTotal API Key not found in environment!")

# Models
class DomainAnalysisRequest(BaseModel):
    domain: str
    notes: Optional[str] = None
    tags: Optional[str] = None

class RiskFactor(BaseModel):
    description: str
    severity: str  # "low", "medium", "high"

class TimelineEvent(BaseModel):
    timestamp: datetime
    event: str
    description: str

class AnalysisResponse(BaseModel):
    upload_id: str
    domain: str
    timestamp: datetime
    risk_score: int
    risk_summary: str
    risk_factors: List[RiskFactor] = []
    timeline: List[TimelineEvent] = []
    whois_data: Optional[Dict[str, Any]] = None
    dns_data: Optional[Dict[str, Any]] = None
    ssl_data: Optional[Dict[str, Any]] = None
    virustotal_data: Optional[Dict[str, Any]] = None

class ReportResponse(BaseModel):
    report_id: str
    analysis_id: str
    domain: str
    timestamp: datetime
    risk_level: str
    risk_score: int
    risk_summary: str
    analysis_date: datetime
    report_sections: List[str] = []

# Helper functions
def get_whois_data(domain: str) -> Dict[str, Any]:
    """
    Get domain registration information using RDAP first, then falling back to WHOIS.
    Returns registrar, creation date, expiration date, domain age, and status.
    """
    import rdap
    from datetime import datetime, timezone
    import re
    
    # Initialize result with default values
    result = {
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "domain_age": "Unknown",
        "status": "Unknown",
        "whois_privacy": "Unknown",
        "name_servers": [],
        "method_used": None  # Track which method was used for debugging
    }
    
    # Helper function to safely convert any date to string format
    def format_date_safely(date_value):
        if date_value is None or date_value == "Unknown":
            return "Unknown"
        
        if isinstance(date_value, datetime):
            try:
                return date_value.strftime("%Y-%m-%d")
            except Exception as e:
                logger.warning(f"Error formatting datetime: {e}")
                return "Unknown"
        elif isinstance(date_value, str):
            return date_value
        else:
            try:
                return str(date_value)
            except Exception:
                return "Unknown"
                
    # Helper function to clean up domain status values
    def clean_domain_status(status_values):
        if not status_values:
            return []
            
        # Convert to list if it's not already
        if not isinstance(status_values, list):
            status_values = [status_values]
            
        # Clean up each status value
        cleaned_statuses = []
        for status in status_values:
            if not status:
                continue
                
            # Extract just the status code without URLs
            if isinstance(status, str):
                # Remove URLs and parentheses
                status = status.split(' http')[0].split(' (http')[0].strip()
                if status and status not in cleaned_statuses:
                    cleaned_statuses.append(status)
                    
        return cleaned_statuses
    
    # Helper function to safely calculate domain age
    def calculate_domain_age(date_value):
        if date_value is None or date_value == "Unknown":
            return "Unknown"
        
        try:
            # Convert to datetime if it's a string
            if isinstance(date_value, str):
                # Skip if it's already "Unknown"
                if date_value == "Unknown":
                    return "Unknown"
                    
                # Try to parse the date string with multiple formats
                formats = [
                    "%Y-%m-%d",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                ]
                
                parsed_date = None
                for fmt in formats:
                    try:
                        parsed_date = datetime.strptime(date_value, fmt)
                        break
                    except ValueError:
                        continue
                
                if parsed_date is None:
                    logger.warning(f"Could not parse date string: {date_value}")
                    return "Unknown"
                    
                date_value = parsed_date
            
            # Ensure we have a datetime object
            if not isinstance(date_value, datetime):
                logger.warning(f"Date value is not a datetime object: {type(date_value)}")
                return "Unknown"
            
            # Ensure the datetime is timezone-aware
            if date_value.tzinfo is None:
                date_value = date_value.replace(tzinfo=timezone.utc)
            
            # Calculate age
            now = datetime.now(timezone.utc)
            delta = now - date_value
            years = delta.days // 365
            months = (delta.days % 365) // 30
            
            if years > 0:
                age_str = f"{years} year{'s' if years != 1 else ''}"
                if months > 0:
                    age_str += f", {months} month{'s' if months != 1 else ''}"
                return age_str
            else:
                if months > 0:
                    return f"{months} month{'s' if months != 1 else ''}"
                else:
                    days = delta.days
                    return f"{days} day{'s' if days != 1 else ''}"
        except Exception as e:
            logger.warning(f"Error calculating domain age: {e}")
            return "Unknown"
    
    # Clean the domain (remove protocol and path)
    try:
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
    except Exception as e:
        logger.error(f"Error cleaning domain: {e}")
    
    # Try RDAP first
    rdap_success = False
    try:
        logger.info(f"Attempting RDAP lookup for {domain}")
        client = rdap.client.RdapClient()
        rdap_data = client.get_domain(domain)
        
        # Extract registrar
        try:
            if hasattr(rdap_data, 'entities') and rdap_data.entities:
                for entity in rdap_data.entities:
                    if entity.role and 'registrar' in entity.role:
                        result["registrar"] = entity.name
                        break
        except Exception as e:
            logger.warning(f"Error extracting registrar from RDAP: {e}")
        
        # Extract dates
        try:
            if hasattr(rdap_data, 'events') and rdap_data.events:
                for event in rdap_data.events:
                    if event.action == 'registration':
                        result["creation_date"] = event.date
                    elif event.action == 'expiration':
                        result["expiration_date"] = event.date
        except Exception as e:
            logger.warning(f"Error extracting dates from RDAP: {e}")
        
        # Extract status
        try:
            if hasattr(rdap_data, 'status') and rdap_data.status:
                result["status"] = clean_domain_status(rdap_data.status)
        except Exception as e:
            logger.warning(f"Error extracting status from RDAP: {e}")
        
        # Extract nameservers
        try:
            if hasattr(rdap_data, 'nameservers') and rdap_data.nameservers:
                result["name_servers"] = [ns.name for ns in rdap_data.nameservers]
        except Exception as e:
            logger.warning(f"Error extracting nameservers from RDAP: {e}")
        
        # Check WHOIS privacy
        try:
            result["whois_privacy"] = "Enabled" if not result["registrar"] or "privacy" in result["registrar"].lower() else "Disabled"
        except Exception as e:
            logger.warning(f"Error determining WHOIS privacy from RDAP: {e}")
        
        result["method_used"] = "RDAP"
        rdap_success = True
        logger.info(f"Successfully retrieved RDAP data for {domain}")
        
    except Exception as rdap_error:
        logger.warning(f"RDAP lookup failed for {domain}: {rdap_error}. Falling back to WHOIS.")
    
    # Fall back to WHOIS if RDAP failed
    if not rdap_success:
        try:
            w = whois.whois(domain)
            
            # Extract registrar
            try:
                if hasattr(w, 'registrar') and w.registrar:
                    result["registrar"] = w.registrar
            except Exception as e:
                logger.warning(f"Error extracting registrar from WHOIS: {e}")
            
            # Extract creation date
            try:
                if hasattr(w, 'creation_date') and w.creation_date:
                    if isinstance(w.creation_date, list):
                        result["creation_date"] = w.creation_date[0]
                    else:
                        result["creation_date"] = w.creation_date
            except Exception as e:
                logger.warning(f"Error extracting creation date from WHOIS: {e}")
            
            # Extract expiration date
            try:
                if hasattr(w, 'expiration_date') and w.expiration_date:
                    if isinstance(w.expiration_date, list):
                        result["expiration_date"] = w.expiration_date[0]
                    else:
                        result["expiration_date"] = w.expiration_date
            except Exception as e:
                logger.warning(f"Error extracting expiration date from WHOIS: {e}")
            
            # Extract status
            try:
                if hasattr(w, 'status') and w.status:
                    result["status"] = clean_domain_status(w.status)
            except Exception as e:
                logger.warning(f"Error extracting status from WHOIS: {e}")
            
            # Extract nameservers
            try:
                if hasattr(w, 'name_servers') and w.name_servers:
                    result["name_servers"] = w.name_servers
            except Exception as e:
                logger.warning(f"Error extracting nameservers from WHOIS: {e}")
            
            # Check WHOIS privacy
            try:
                has_emails = hasattr(w, 'emails') and w.emails
                has_privacy_registrar = hasattr(w, 'registrar') and w.registrar and "privacy" in str(w.registrar).lower()
                result["whois_privacy"] = "Enabled" if not has_emails or has_privacy_registrar else "Disabled"
            except Exception as e:
                logger.warning(f"Error determining WHOIS privacy from WHOIS: {e}")
            
            result["method_used"] = "WHOIS"
            logger.info(f"Successfully retrieved WHOIS data for {domain}")
            
        except Exception as whois_error:
            logger.error(f"Both RDAP and WHOIS lookups failed for {domain}. RDAP error: {rdap_error if 'rdap_error' in locals() else 'Unknown'}. WHOIS error: {whois_error}")
            result["error"] = f"Domain information lookup failed: {str(whois_error)}"
    
    # Format dates and calculate domain age
    try:
        # Format creation date
        result["creation_date"] = format_date_safely(result["creation_date"])
        
        # Format expiration date
        result["expiration_date"] = format_date_safely(result["expiration_date"])
        
        # Calculate domain age based on creation date
        if result["creation_date"] and result["creation_date"] != "Unknown":
            result["domain_age"] = calculate_domain_age(result["creation_date"])
    except Exception as e:
        logger.error(f"Error formatting dates or calculating domain age: {e}")
    
    return result

def get_dns_records(domain: str) -> Dict[str, Any]:
    """Get DNS records for a domain."""
    try:
        dns_data = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }
        
        # A records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_data["a_records"] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.info(f"No A records found: {e}")
        
        # MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            dns_data["mx_records"] = [str(rdata.exchange) for rdata in answers]
        except Exception as e:
            logger.info(f"No MX records found: {e}")
        
        # NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            dns_data["ns_records"] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.info(f"No NS records found: {e}")
        
        # TXT records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            dns_data["txt_records"] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.info(f"No TXT records found: {e}")
        
        return dns_data
    except Exception as e:
        logger.error(f"Error getting DNS records: {e}")
        return {"error": str(e)}

def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate data
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                return {
                    "is_valid": True,
                    "subject": subject.get('commonName', 'Unknown'),
                    "issuer": issuer.get('commonName', 'Unknown'),
                    "valid_from": cert['notBefore'],
                    "valid_until": cert['notAfter'],
                    "version": cert['version'],
                    "serial_number": cert['serialNumber'],
                }
    except Exception as e:
        logger.error(f"Error getting SSL info: {e}")
        return {
            "is_valid": False,
            "error": str(e)
        }

async def get_virustotal_data(domain: str) -> Dict[str, Any]:
    """Get VirusTotal information for a domain."""
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key is not available at get_virustotal_data call time.")
        return {"error": "VirusTotal API key not configured"}
    
    logger.info(f"Attempting to initialize VirusTotal client with key starting: {VIRUSTOTAL_API_KEY[:4]}...")
    client = None
    try:
        # Initialize the VirusTotal client
        client = vt.Client(VIRUSTOTAL_API_KEY)
        logger.info("VirusTotal client initialized successfully.")
    except Exception as e_vt_client:
        logger.error(f"Error initializing VirusTotal client: {e_vt_client}", exc_info=True)
        if client: # Try to close if partially initialized
            try:
                await client.close()
            except Exception as e_close:
                logger.error(f"Error closing VT client after initialization failure: {e_close}")
        return {"error": f"Failed to initialize VirusTotal client: {e_vt_client}"}

    # If client initialization was successful, proceed to make the API call
    try:
        logger.info(f"Making VirusTotal API request for domain: {domain}")
        domain_obj = await client.get_object_async(f"/domains/{domain}")
        
        # Extract relevant data
        last_analysis_stats = domain_obj.get("last_analysis_stats", {})
        last_analysis_results = domain_obj.get("last_analysis_results", {})
        
        # Process detection results
        detections = []
        for engine, result in last_analysis_results.items():
            if result.get("category") == "malicious" or result.get("category") == "suspicious":
                detections.append({
                    "engine": engine,
                    "category": result.get("category"),
                    "result": result.get("result")
                })
        
        # Get categories if available
        categories = domain_obj.get("categories", {})
        
        # Get last analysis date and format it
        raw_vt_date = domain_obj.get("last_analysis_date")
        formatted_date = None

        try:
            # First, handle the case where raw_vt_date is already an integer
            if isinstance(raw_vt_date, int) and raw_vt_date > 0:
                formatted_date = datetime.fromtimestamp(raw_vt_date, tz=timezone.utc).isoformat()
                logger.info(f"Successfully parsed VirusTotal date from integer timestamp: {raw_vt_date}")
            # Next, handle the case where raw_vt_date is a string that can be converted to an integer
            elif isinstance(raw_vt_date, str) and raw_vt_date.strip():
                # Try to parse as ISO format string first
                try:
                    # If it's already in ISO format, parse it directly
                    parsed_date = datetime.fromisoformat(raw_vt_date.replace('Z', '+00:00'))
                    formatted_date = parsed_date.isoformat()
                    logger.info(f"Successfully parsed VirusTotal date from ISO format string: {raw_vt_date}")
                except ValueError:
                    # If not ISO format, try to convert to integer timestamp
                    try:
                        timestamp_int = int(raw_vt_date)
                        if timestamp_int > 0:
                            formatted_date = datetime.fromtimestamp(timestamp_int, tz=timezone.utc).isoformat()
                            logger.info(f"Successfully parsed VirusTotal date from string numeric timestamp: {raw_vt_date}")
                        else:
                            logger.info(f"VirusTotal timestamp '{raw_vt_date}' converted to non-positive integer: {timestamp_int}, using current time")
                            formatted_date = datetime.now(tz=timezone.utc).isoformat()
                    except ValueError:
                        logger.info(f"VirusTotal last_analysis_date is not a valid ISO format or integer: '{raw_vt_date}', using current time")
                        formatted_date = datetime.now(tz=timezone.utc).isoformat()
            elif raw_vt_date is None or raw_vt_date == "":
                logger.info("VirusTotal last_analysis_date is None or empty, using current time")
                formatted_date = datetime.now(tz=timezone.utc).isoformat()
            else:
                logger.info(f"VirusTotal last_analysis_date is of unexpected type: {type(raw_vt_date).__name__}, using current time")
                formatted_date = datetime.now(tz=timezone.utc).isoformat()
        except Exception as e:
            logger.info(f"Error parsing VirusTotal date: {e}, using current time")
            formatted_date = datetime.now(tz=timezone.utc).isoformat()
        
        # Build the result
        result = {
            "malicious_count": last_analysis_stats.get("malicious", 0),
            "suspicious_count": last_analysis_stats.get("suspicious", 0),
            "harmless_count": last_analysis_stats.get("harmless", 0),
            "undetected_count": last_analysis_stats.get("undetected", 0),
            "total_engines": sum(last_analysis_stats.values()),
            "detections": detections,
            "categories": categories,
            "last_analysis_date": formatted_date # Use the parsed date (or None if parsing failed)
        }
        
        logger.info(f"Successfully retrieved VirusTotal data for {domain} with {result['malicious_count']} malicious detections")
        return result
        
    except vt.error.APIError as e_vt_api:
        logger.error(f"VirusTotal API error for domain {domain}: {e_vt_api}", exc_info=True)
        # Check for specific error codes, e.g., NotFoundError
        if isinstance(e_vt_api, vt.error.NotFoundError):
            return {"error": f"Domain {domain} not found in VirusTotal.", "details": str(e_vt_api)}
        return {"error": f"VirusTotal API error: {e_vt_api}", "details": str(e_vt_api)}
    except Exception as e_general_api:
        logger.error(f"Unexpected error during VirusTotal API call for domain {domain}: {e_general_api}", exc_info=True)
        return {"error": f"Unexpected error processing VirusTotal data: {e_general_api}"}
    finally:
        if client:
            try:
                await client.close_async()
                logger.info(f"VirusTotal client closed for domain {domain}.")
                # vt-py client typically manages its own HTTPX session, 
                # but explicit close_async is good practice if available and needed.
                # For vt.Client, closing is usually handled by context manager or when it goes out of scope.
                # If using httpx directly, then async with client: ... else await client.aclose()
                # For now, let's assume vt.Client handles this or doesn't require explicit close_async here
                # await client.close_async() 
                # logger.info("VirusTotal client (potentially) closed.")
                pass # vt.Client usually handles its own session lifecycle
            except Exception as e_close_final:
                logger.error(f"Error attempting to close VirusTotal client in finally block: {e_close_final}")

    # Fallback if something unexpected happens and no return was hit
    return {"error": "Unknown error in get_virustotal_data after API call attempt"}

def calculate_vendor_risk_score(vt_detections, flagged_vendors, creation_date):
    """Enhanced risk score calculation based on vendor reputation and detection patterns."""
    def vt_score(detections):
        if detections >= 30:
            return 40
        elif detections >= 20:
            return 35
        elif detections >= 15:
            return 30
        elif detections >= 10:
            return 25
        elif detections >= 5:
            return 15
        elif detections >= 1:
            return 10
        return 0

    reputable_vendors = {
        "ESET", "Kaspersky", "Sophos", "Fortinet", "BitDefender", "Avira",
        "F-Secure", "TrendMicro", "Symantec", "McAfee", "Webroot", "G-Data"
    }

    def vendor_score(flagged_vendors):
        flagged_reputable = reputable_vendors.intersection(set(flagged_vendors))
        count = len(flagged_reputable)
        if count >= 8:
            return 30
        elif count >= 6:
            return 25
        elif count >= 4:
            return 20
        elif count >= 2:
            return 15
        elif count >= 1:
            return 10
        return 0

    def domain_age_score(creation_date):
        try:
            if isinstance(creation_date, datetime):
                creation = creation_date
            else:
                # Try to parse the creation date string
                creation = datetime.strptime(creation_date, "%Y-%m-%d")
            
            age_months = (datetime.utcnow().year - creation.year) * 12 + (datetime.utcnow().month - creation.month)
            if age_months <= 1:
                return 30
            elif age_months <= 3:
                return 25
            elif age_months <= 6:
                return 20
            elif age_months <= 12:
                return 15
            elif age_months <= 36:
                return 10
            return 5
        except Exception as e:
            logger.warning(f"Error calculating domain age score: {e}")
            return 0

    vt = vt_score(vt_detections)
    vendor = vendor_score(flagged_vendors)
    age = domain_age_score(creation_date)
    total_score = vt + vendor + age

    risk_factors = []
    if vt_detections > 0:
        risk_factors.append({
            "description": f"Domain flagged as malicious by {vt_detections} security vendors",
            "severity": "high" if total_score >= 60 else "medium"
        })

    return total_score, risk_factors

def calculate_risk_score(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk score and identify risk factors based on analysis data."""
    score = 0
    risk_factors = []
    
    # Check domain age for non-VT risk factors
    whois_data = analysis_data.get("whois_data", {})
    creation_date = whois_data.get("creation_date")
    domain_age_days = 365  # Default to 1 year if we can't calculate
    
    # Try to calculate domain age for display purposes
    if whois_data and not whois_data.get("error"):
        domain_age = whois_data.get("domain_age")
        if domain_age and domain_age != "Unknown":
            # If we have a calculated age string like "2 years, 3 months" or "5 days"
            # we can extract the approximate age in days
            try:
                if "year" in domain_age:
                    years = int(domain_age.split(" ")[0])
                    domain_age_days = years * 365
                    if "month" in domain_age:
                        months_str = domain_age.split(",")[1].strip()
                        months = int(months_str.split(" ")[0])
                        domain_age_days += months * 30
                elif "month" in domain_age:
                    months = int(domain_age.split(" ")[0])
                    domain_age_days = months * 30
                elif "day" in domain_age:
                    domain_age_days = int(domain_age.split(" ")[0])
            except Exception as e:
                logger.warning(f"Error parsing domain_age string: {e}")
        # If we couldn't parse domain_age, try to calculate from creation_date
        elif creation_date and creation_date != "Unknown":
            try:
                # If creation_date is a datetime object
                if isinstance(creation_date, datetime):
                    domain_age_days = (datetime.now(timezone.utc) - creation_date).days
                # If creation_date is a string, try to parse it
                elif isinstance(creation_date, str):
                    # Try common date formats
                    formats = [
                        "%Y-%m-%d",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                    ]
                    parsed_date = None
                    for fmt in formats:
                        try:
                            parsed_date = datetime.strptime(creation_date, fmt)
                            break
                        except ValueError:
                            continue
                    
                    if parsed_date:
                        # Make the parsed date timezone-aware
                        if parsed_date.tzinfo is None:
                            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                        domain_age_days = (datetime.now(timezone.utc) - parsed_date).days
            except Exception as e:
                logger.warning(f"Error calculating domain age days: {e}")
    
    # Check VirusTotal results using the enhanced scoring function
    vt_data = analysis_data.get("virustotal_data", {})
    if vt_data and not vt_data.get("error"):
        malicious_count = vt_data.get("malicious_count", 0)
        
        # Use the enhanced risk score calculation
        vendor_risk_score, vt_risk_factors = calculate_vendor_risk_score(
            malicious_count,
            [d['engine'] for d in vt_data.get("detections", [])],
            creation_date or "1970-01-01"
        )
        
        score += vendor_risk_score
        risk_factors.extend(vt_risk_factors)
    
    # Check SSL certificate
    ssl_data = analysis_data.get("ssl_data", {})
    if ssl_data:
        if not ssl_data.get("is_valid", False):
            score += 15
            risk_factors.append({
                "description": "Invalid or missing SSL certificate",
                "severity": "medium"
            })
    
    # Generate risk summary
    risk_summary = "Low risk domain"
    if score >= 70:
        risk_summary = "High risk domain with multiple security concerns"
    elif score >= 30:
        risk_summary = "Medium risk domain with some suspicious indicators"
    
    return {
        "risk_score": score,
        "risk_factors": risk_factors,
        "risk_summary": risk_summary
    }

def generate_timeline(analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate a timeline of events for the domain."""
    timeline = []
    
    # Helper function to safely parse dates
    def parse_date_safely(date_value):
        if date_value is None or date_value == "Unknown":
            return None
            
        if isinstance(date_value, datetime):
            return date_value
            
        if isinstance(date_value, str):
            try:
                # Try common date formats
                formats = [
                    "%Y-%m-%d",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                ]
                for fmt in formats:
                    try:
                        parsed_date = datetime.strptime(date_value, fmt)
                        # Make the parsed date timezone-aware
                        if parsed_date.tzinfo is None:
                            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                        return parsed_date
                    except ValueError:
                        continue
            except Exception as e:
                logger.warning(f"Error parsing date string: {e}")
                
        return None
    
    # Add analysis time
    timeline.append({
        "timestamp": datetime.now(timezone.utc),
        "event": "Analysis Performed",
        "description": f"TakedownIQ analyzed the domain {analysis_data.get('domain')}"
    })
    
    # Add domain registration
    whois_data = analysis_data.get("whois_data", {})
    if whois_data and not whois_data.get("error"):
        creation_date = whois_data.get("creation_date")
        parsed_creation_date = parse_date_safely(creation_date)
        
        if parsed_creation_date:
            timeline.append({
                "timestamp": parsed_creation_date,
                "event": "Domain Registration",
                "description": f"Domain was registered with {whois_data.get('registrar', 'Unknown Registrar')}"
            })
        
        updated_date = whois_data.get("updated_date")
        parsed_updated_date = parse_date_safely(updated_date)
        
        if parsed_updated_date and (not parsed_creation_date or parsed_updated_date != parsed_creation_date):
            timeline.append({
                "timestamp": parsed_updated_date,
                "event": "Domain Updated",
                "description": "Domain registration was updated"
            })
    
    # Add VirusTotal first scan if available
    vt_data = analysis_data.get("virustotal_data", {})
    if vt_data and not vt_data.get("error"):
        last_analysis_date = vt_data.get("last_analysis_date")
        if last_analysis_date:
            try:
                scan_date = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)
                timeline.append({
                    "timestamp": scan_date,
                    "event": "VirusTotal Scan",
                    "description": f"Domain was scanned by VirusTotal with {vt_data.get('malicious_count', 0)} detections"
                })
            except Exception as e:
                logger.warning(f"Error parsing VirusTotal date: {e}")
    
    # Filter out any entries with None timestamps
    timeline = [entry for entry in timeline if entry["timestamp"] is not None]
    
    # Sort timeline by timestamp
    if timeline:
        try:
            timeline.sort(key=lambda x: x["timestamp"])
        except Exception as e:
            logger.error(f"Error sorting timeline: {e}")
    
    return timeline

def generate_pdf_report(analysis_data: Dict[str, Any], image_path: Optional[str] = None) -> str:
    """Generate a PDF report for the domain analysis."""
    domain = analysis_data.get("domain", "unknown-domain")
    report_id = analysis_data.get("upload_id", str(uuid.uuid4()))
    
    # Create a temporary file for the PDF
    pdf_path = TEMP_DIR / f"{report_id}.pdf"
    
    # Create the PDF document
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    subheading_style = styles["Heading2"]
    normal_style = styles["Normal"]
    
    # Create custom styles
    risk_high_style = ParagraphStyle(
        "RiskHigh",
        parent=normal_style,
        textColor=colors.red,
        fontSize=12,
        fontName="Helvetica-Bold"
    )
    risk_medium_style = ParagraphStyle(
        "RiskMedium",
        parent=normal_style,
        textColor=colors.orange,
        fontSize=12,
        fontName="Helvetica-Bold"
    )
    risk_low_style = ParagraphStyle(
        "RiskLow",
        parent=normal_style,
        textColor=colors.green,
        fontSize=12,
        fontName="Helvetica-Bold"
    )
    
    # Content elements
    elements = []
    
    # Title
    elements.append(Paragraph(f"TakedownIQ Domain Analysis Report", title_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Domain and timestamp
    elements.append(Paragraph(f"Domain: {domain}", heading_style))
    elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Risk assessment
    risk_score = analysis_data.get("risk_score", 0)
    risk_summary = analysis_data.get("risk_summary", "Unknown risk")
    
    if risk_score >= 70:
        risk_style = risk_high_style
        risk_level = "High"
    elif risk_score >= 30:
        risk_style = risk_medium_style
        risk_level = "Medium"
    else:
        risk_style = risk_low_style
        risk_level = "Low"
    
    elements.append(Paragraph("Risk Assessment", heading_style))
    elements.append(Paragraph(f"Risk Level: {risk_level} ({risk_score}/100)", risk_style))
    elements.append(Paragraph(f"Summary: {risk_summary}", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Screenshot if available
    if image_path and os.path.exists(image_path):
        try:
            # Add the screenshot
            elements.append(Paragraph("Evidence Screenshot", heading_style))
            img = Image(image_path, width=6*inch, height=4*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.25*inch))
        except Exception as e:
            logger.error(f"Error adding image to PDF: {e}")
    
    # Risk factors
    elements.append(Paragraph("Risk Factors", heading_style))
    risk_factors = analysis_data.get("risk_factors", [])
    if risk_factors:
        for factor in risk_factors:
            severity = factor.get("severity", "low")
            if severity == "high":
                style = risk_high_style
            elif severity == "medium":
                style = risk_medium_style
            else:
                style = normal_style
            
            elements.append(Paragraph(f"• {factor.get('description')}", style))
    else:
        elements.append(Paragraph("No specific risk factors identified.", normal_style))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # WHOIS data
    elements.append(Paragraph("WHOIS Information", heading_style))
    whois_data = analysis_data.get("whois_data", {})
    if whois_data and not whois_data.get("error"):
        # Only include registrar name, domain status, and name servers
        whois_table_data = []
        registrar = whois_data.get("registrar")
        status = whois_data.get("status")
        name_servers = whois_data.get("name_servers")
        if registrar:
            whois_table_data.append(["Registrar", str(registrar)])
        if status:
            if isinstance(status, (list, tuple)):
                status_str = ", ".join(str(s) for s in status)
            else:
                status_str = str(status)
            whois_table_data.append(["Domain Status", status_str])
        if name_servers:
            if isinstance(name_servers, (list, tuple)):
                ns_str = ", ".join(str(ns) for ns in name_servers)
            else:
                ns_str = str(name_servers)
            whois_table_data.append(["Name Servers", ns_str])
        if whois_table_data:
            table = Table(whois_table_data, colWidths=[2*inch, 3.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No WHOIS data available.", normal_style))
    else:
        elements.append(Paragraph("No WHOIS data available.", normal_style))

    
    elements.append(Spacer(1, 0.25*inch))
    
    # DNS records
    elements.append(Paragraph("DNS Records", heading_style))
    dns_data = analysis_data.get("dns_data", {})
    if dns_data and not dns_data.get("error"):
        # A Records
        if dns_data.get("a_records"):
            elements.append(Paragraph("A Records:", subheading_style))
            for record in dns_data["a_records"]:
                elements.append(Paragraph(f"• {record}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # MX Records
        if dns_data.get("mx_records"):
            elements.append(Paragraph("MX Records:", subheading_style))
            for record in dns_data["mx_records"]:
                elements.append(Paragraph(f"• {record}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # NS Records
        if dns_data.get("ns_records"):
            elements.append(Paragraph("NS Records:", subheading_style))
            for record in dns_data["ns_records"]:
                elements.append(Paragraph(f"• {record}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # TXT Records
        if dns_data.get("txt_records"):
            elements.append(Paragraph("TXT Records:", subheading_style))
            for record in dns_data["txt_records"]:
                elements.append(Paragraph(f"• {record}", normal_style))
    else:
        elements.append(Paragraph("No DNS data available.", normal_style))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # VirusTotal data
    elements.append(Paragraph("VirusTotal Analysis", heading_style))
    vt_data = analysis_data.get("virustotal_data", {})
    if vt_data and not vt_data.get("error"):
        malicious_count = vt_data.get("malicious_count", 0)
        total_engines = vt_data.get("total_engines", 0)
        
        elements.append(Paragraph(f"Detection Rate: {malicious_count}/{total_engines} engines", 
                                 risk_high_style if malicious_count > 0 else normal_style))
        
        # Categories
        if vt_data.get("categories"):
            elements.append(Paragraph("Categories:", subheading_style))
            for vendor, category in vt_data["categories"].items():
                elements.append(Paragraph(f"• {category} (according to {vendor})", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # Detections
        if vt_data.get("detections"):
            elements.append(Paragraph("Detection Details:", subheading_style))
            for detection in vt_data["detections"]:
                elements.append(Paragraph(
                    f"• {detection.get('engine')}: {detection.get('result')} ({detection.get('category')})", 
                    risk_high_style
                ))
    else:
        elements.append(Paragraph("No VirusTotal data available.", normal_style))
    
    # Build the PDF
    doc.build(elements)
    
    return str(pdf_path)

# API Routes

@app.get("/api/test-openai")
@app.get("/test-openai")
async def test_openai():
    """
    Test endpoint to verify the OpenAI API connection is working correctly.
    """
    logger.info("Test OpenAI endpoint called")
    try:
        # Import OpenAI client from chatgpt_impact module
        from chatgpt_impact import client
        
        if not client:
            error_msg = "OpenAI client not initialized. API key may be missing or invalid."
            logger.error(error_msg)
            return JSONResponse(status_code=500, content={"error": error_msg})
        
        # Simple test request
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "You are a helpful assistant."},
                      {"role": "user", "content": "Say hello"}],
            temperature=0.3,
            max_tokens=10
        )
        
        result = response.choices[0].message.content
        logger.info(f"OpenAI test successful. Response: {result}")
        return JSONResponse(content={"success": True, "message": "OpenAI connection is working", "response": result})
    except Exception as e:
        import traceback
        error_msg = f"Error testing OpenAI connection: {str(e)}"
        logger.error(error_msg)
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(status_code=500, content={"error": error_msg})

@app.post("/api/test-risk")
async def test_risk_assessment(request: Request):
    """
    Test endpoint for the improved risk assessment calculation.
    """
    try:
        data = await request.json()
        domain = data.get("domain", "example.com")
        whois_data = data.get("whois_data", {})
        virustotal_data = data.get("virustotal_data", {})
        
        # Extract the necessary data for the risk assessment
        malicious_count = virustotal_data.get("malicious_count", 0)
        flagged_vendors = [d["engine"] for d in virustotal_data.get("detections", [])]
        creation_date = whois_data.get("creation_date", "1970-01-01")
        
        # Calculate the vendor risk score directly
        vendor_score, vendor_factors = calculate_vendor_risk_score(
            malicious_count,
            flagged_vendors,
            creation_date
        )
        
        # Calculate the full risk assessment
        risk_assessment = calculate_risk_score(data)
        
        return JSONResponse(content={
            "status": "success",
            "domain": domain,
            "vendor_score": vendor_score,
            "vendor_factors": vendor_factors,
            "risk_assessment": risk_assessment
        })
    except Exception as e:
        import traceback
        error_msg = f"Error testing risk assessment: {str(e)}"
        logger.error(error_msg)
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(status_code=500, content={"error": error_msg})

@app.post("/api/chatgpt-impact")
@app.post("/chatgpt-impact")
async def chatgpt_impact(request: Request):
    """
    Receives domain analysis data and returns ChatGPT-based impact analysis and scores.
    Expects JSON body with at least: domain, whois_data, dns_data, ssl_data.
    """
    try:
        logger.info("ChatGPT impact analysis endpoint called")
        data = await request.json()
        logger.info(f"Received data for domain: {data.get('domain', 'unknown')}")
        
        # Check if we have the required fields
        required_fields = ['domain', 'whois_data', 'dns_data', 'ssl_data']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            logger.error(f"Missing required fields in request: {missing_fields}")
            return JSONResponse(status_code=400, content={"error": f"Missing required fields: {', '.join(missing_fields)}"})
            
        # Remove VirusTotal data if present (we no longer use it for impact analysis)
        if 'virustotal_data' in data:
            logger.info("Removing VirusTotal data from ChatGPT impact analysis input")
            data.pop('virustotal_data')
        
        # Call the analyze_domain_impact function
        logger.info("Calling analyze_domain_impact function")
        result = analyze_domain_impact(data)
        
        # Check if there was an error in the result
        if isinstance(result, dict) and 'error' in result:
            logger.error(f"Error in analyze_domain_impact: {result['error']}")
            return JSONResponse(status_code=500, content=result)
        
        logger.info("Successfully completed ChatGPT impact analysis")
        return JSONResponse(content=result)
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in request: {str(e)}")
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON in request: {str(e)}"})
    except Exception as e:
        logger.error(f"Unexpected error in chatgpt_impact endpoint: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(status_code=500, content={"error": f"Server error: {str(e)}"})

@app.post("/upload", response_model=AnalysisResponse)
@app.post("/api/upload", response_model=AnalysisResponse)
async def upload_file(
    file: UploadFile = File(...),
    domain: str = Form(...),
    notes: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    background_tasks: BackgroundTasks = None
):
    global TEMP_DIR
    # Log the request details
    logger.info(f"Received upload request for domain: {domain}, file: {file.filename}, content_type: {file.content_type}")
    # Add a simple test response for debugging
    logger.info("TEST: Upload endpoint called successfully")
    """Upload a file and start domain analysis."""
    # Validate file type - be more permissive with content types
    allowed_types = ["image/jpeg", "image/png", "application/pdf", "image/gif", "text/plain", "text/html"]
    
    # Some browsers/clients might send slightly different content types
    content_type_base = file.content_type.split(';')[0].strip().lower()
    
    if not any(allowed_type in content_type_base for allowed_type in ["image/", "application/pdf", "text/plain", "text/html"]):
        logger.warning(f"Rejected file upload with content type: {file.content_type}")
        raise HTTPException(status_code=400, detail="File type not allowed. Please upload an image, PDF, or text file.")
        
    # Log accepted file
    logger.info(f"Accepted file upload with content type: {file.content_type}")
    
    # Generate a unique ID for this upload
    upload_id = str(uuid.uuid4())
    
    # Create a temporary directory for this analysis
    # First check if TEMP_DIR exists and is writable
    if not os.path.exists(TEMP_DIR):
        logger.warning(f"TEMP_DIR does not exist, creating it: {TEMP_DIR}")
        try:
            os.makedirs(TEMP_DIR, mode=0o755, exist_ok=True)
        except Exception as temp_dir_error:
            logger.error(f"Failed to create TEMP_DIR: {temp_dir_error}")
            # Use a fallback directory in the current working directory
            TEMP_DIR = Path(os.getcwd()) / "uploads"
            os.makedirs(TEMP_DIR, mode=0o755, exist_ok=True)
            logger.info(f"Using fallback TEMP_DIR: {TEMP_DIR}")
    
    # Create analysis directory using os.makedirs for better reliability
    analysis_dir = TEMP_DIR / upload_id
    try:
        os.makedirs(analysis_dir, mode=0o755, exist_ok=True)
        logger.info(f"Created analysis directory at: {analysis_dir}")
    except Exception as dir_error:
        logger.error(f"Error creating analysis directory: {dir_error}")
        # Try a different approach if the first one fails
        try:
            # Use absolute path for reliability
            alt_dir = Path(os.path.abspath(os.getcwd())) / "uploads" / upload_id
            os.makedirs(alt_dir, mode=0o755, exist_ok=True)
            analysis_dir = alt_dir
            logger.info(f"Created alternative analysis directory at: {analysis_dir}")
        except Exception as alt_dir_error:
            logger.error(f"Error creating alternative analysis directory: {alt_dir_error}")
            # Last resort - use /tmp directly
            try:
                last_resort_dir = Path("/tmp") / "takedowniq_uploads" / upload_id
                os.makedirs(last_resort_dir, mode=0o777, exist_ok=True)
                analysis_dir = last_resort_dir
                logger.info(f"Created last resort directory at: {analysis_dir}")
            except Exception as last_error:
                logger.error(f"All directory creation attempts failed: {last_error}")
                raise HTTPException(status_code=500, detail=f"Server storage error. Please contact support.")
    
    # Save the uploaded file with improved error handling
    try:
        # Sanitize the filename to avoid path traversal issues
        safe_filename = os.path.basename(file.filename or "")
        if not safe_filename:  # If filename is empty for some reason
            safe_filename = f"upload_{upload_id}.jpg"
        
        # Ensure filename is safe and unique
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', safe_filename)
        file_path = os.path.join(str(analysis_dir), safe_filename)
        
        # Log the file details
        logger.info(f"Saving uploaded file: {safe_filename} (type: {file.content_type}) to {file_path}")
        
        # Read the file content with a size limit
        try:
            # Reset file position to start
            await file.seek(0)
            
            # Read with a size limit (10MB)
            MAX_SIZE = 10 * 1024 * 1024  # 10MB
            content = await file.read(MAX_SIZE)
            
            if len(content) == 0:
                raise ValueError("Empty file uploaded")
                
            logger.info(f"Read {len(content)} bytes from uploaded file")
            
            # Save using standard file operations for reliability
            try:
                with open(file_path, 'wb') as out_file:
                    out_file.write(content)
                logger.info(f"Successfully saved file to {file_path}")
            except IOError as io_error:
                logger.error(f"IOError writing file: {io_error}")
                # Try alternative approach with lower-level file operations
                with os.fdopen(os.open(file_path, os.O_WRONLY | os.O_CREAT, 0o644), 'wb') as out_file:
                    out_file.write(content)
                logger.info(f"Successfully saved file using alternative method to {file_path}")
                
        except ValueError as val_error:
            logger.error(f"Value error with file: {val_error}")
            raise HTTPException(status_code=400, detail=f"Invalid file: {str(val_error)}")
        except Exception as read_error:
            logger.error(f"Error reading or writing file: {read_error}")
            raise HTTPException(status_code=500, detail="Error processing uploaded file. Please try again.")
            
    except Exception as e:
        logger.error(f"Error in file upload process: {e}")
        raise HTTPException(status_code=500, detail="Error uploading file. Please try again.")
    
    # Start the analysis process
    try:
        # Get WHOIS data
        whois_data = get_whois_data(domain)
        
        # Get DNS records
        dns_data = get_dns_records(domain)
        
        # Get SSL certificate info
        ssl_data = get_ssl_info(domain)
        
        # Get VirusTotal data
        try:
            logger.info(f"Getting VirusTotal data for domain: {domain}")
            virustotal_data = await get_virustotal_data(domain)
            logger.info(f"Successfully retrieved VirusTotal data for domain: {domain}")
        except Exception as vt_error:
            logger.error(f"Error getting VirusTotal data: {vt_error}")
            # Don't fail the entire analysis if VirusTotal fails
            virustotal_data = {"error": f"Error retrieving VirusTotal data: {str(vt_error)}"}
        
        # Compile analysis data
        analysis_data = {
            "upload_id": upload_id,
            "domain": domain,
            "timestamp": datetime.now(),
            "whois_data": whois_data,
            "dns_data": dns_data,
            "ssl_data": ssl_data,
            "virustotal_data": virustotal_data,
            "file_path": str(file_path),
            "notes": notes,
            "tags": tags
        }
        
        # Calculate risk score and factors
        risk_data = calculate_risk_score(analysis_data)
        analysis_data.update(risk_data)

        # Make virustotal data available as 'virustotal' for backward compatibility
        if 'virustotal_data' in analysis_data and not analysis_data.get('virustotal_data', {}).get('error'):
            analysis_data['virustotal'] = analysis_data['virustotal_data']
        
        # Generate timeline
        # Ensure generate_timeline returns a list of dicts/TimelineEvent compatible items
        timeline_events = generate_timeline(analysis_data) 
        analysis_data["timeline"] = timeline_events

        logger.info(f"Preparing to store final analysis_data for upload_id {upload_id}. VT date: {analysis_data.get('virustotal_data', {}).get('last_analysis_date')}, Risk score: {analysis_data.get('risk_score')}")
        
        # Store the comprehensive analysis data in active_sessions
        # This includes all collected data, notes, tags, file_path etc.
        active_sessions[upload_id] = analysis_data 
        logger.info(f"Analysis for {upload_id} (domain: {domain}) stored successfully in active sessions.")
        
        # Prepare a payload strictly for the AnalysisResponse model
        # Pydantic will validate fields and use defaults from the model if not provided
        response_payload_data = {
            "upload_id": analysis_data.get("upload_id"),
            "domain": analysis_data.get("domain"),
            "timestamp": analysis_data.get("timestamp", datetime.now()),
            "risk_score": analysis_data.get("risk_score", 0),
            "risk_summary": analysis_data.get("risk_summary", "Summary not available"),
            "risk_factors": analysis_data.get("risk_factors", []),
            "timeline": analysis_data.get("timeline", []),
            "whois_data": analysis_data.get("whois_data"),
            "dns_data": analysis_data.get("dns_data"),
            "ssl_data": analysis_data.get("ssl_data"),
            "virustotal_data": analysis_data.get("virustotal_data")
            # file_path, notes, tags are not part of AnalysisResponse model, so not included here
        }
        
        return AnalysisResponse(**response_payload_data)

    except HTTPException: # Important to re-raise HTTPExceptions from called functions or FastAPI itself
        raise
    except Exception as e_analysis: # Catch all other exceptions during the analysis phase
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Critical error during analysis phase for upload_id {upload_id}, domain {domain}: {str(e_analysis)}\n{error_trace}")
        
        error_detail = f"Critical error during analysis: {str(e_analysis)}. Some data may be incomplete."
        
        # Store error information in active_sessions for the /analysis/{upload_id} endpoint
        active_sessions[upload_id] = {
            "upload_id": upload_id,
            "domain": domain,
            "timestamp": datetime.now(), # Time of failure
            "error": error_detail,
            "status": "failed_analysis",
            "whois_data": analysis_data.get("whois_data"), # Store whatever was collected before failure
            "dns_data": analysis_data.get("dns_data"),
            "ssl_data": analysis_data.get("ssl_data"),
            "virustotal_data": analysis_data.get("virustotal_data"),
            "file_path": str(file_path) if 'file_path' in locals() and file_path else analysis_data.get("file_path"),
            "notes": notes if 'notes' in locals() else analysis_data.get("notes"),
            "tags": tags if 'tags' in locals() else analysis_data.get("tags")
        }
        logger.info(f"Stored error state for upload_id {upload_id} in active_sessions due to analysis failure.")
        
        # The /upload endpoint itself should signal an error to the client
        raise HTTPException(status_code=500, detail=error_detail)

@app.get("/api/analysis/{upload_id}", response_model=AnalysisResponse)
@app.get("/analysis/{upload_id}", response_model=AnalysisResponse)
async def get_analysis(upload_id: str):
    """Get analysis results for a specific upload ID."""
    logger.error(f"DIAGNOSTIC TEST - THIS IS THE UPDATED CODE - GET /analysis/{upload_id} called. Checking active_sessions.")
    logger.info(f"GET /analysis/{upload_id} called. Checking active_sessions.")
    if upload_id not in active_sessions:
        current_keys = list(active_sessions.keys())
        logger.warning(f"Upload ID '{upload_id}' not found in active_sessions. Current keys: {current_keys}")
        raise HTTPException(status_code=404, detail="Analysis not found or processing incomplete.")
    
    analysis_data = active_sessions[upload_id]
    logger.info(f"Found data for upload_id '{upload_id}'. Status: {analysis_data.get('status', 'completed')}, Keys: {list(analysis_data.keys())}")

    if analysis_data.get("status") == "failed_analysis":
        logger.error(f"Analysis for upload_id '{upload_id}' previously failed. Error: {analysis_data.get('error')}")
        raise HTTPException(status_code=500, detail=f"Analysis previously failed: {analysis_data.get('error', 'Unknown error')}")

    # Prepare a payload strictly for the AnalysisResponse model
    response_payload = {
        "upload_id": analysis_data.get("upload_id"),
        "domain": analysis_data.get("domain"),
        "timestamp": analysis_data.get("timestamp", datetime.now()),
        "risk_score": analysis_data.get("risk_score", 0),
        "risk_summary": analysis_data.get("risk_summary", "Summary not available"),
        "risk_factors": analysis_data.get("risk_factors", []),
        "timeline": analysis_data.get("timeline", []),
        "whois_data": analysis_data.get("whois_data"),
        "dns_data": analysis_data.get("dns_data"),
        "ssl_data": analysis_data.get("ssl_data"),
        "virustotal_data": analysis_data.get("virustotal_data")
    }
    logger.debug(f"Response payload: {response_payload}")
    return AnalysisResponse(**response_payload)

@app.post("/report/{upload_id}", response_model=ReportResponse)
async def generate_report(upload_id: str):
    """Generate a PDF report for the analysis."""
    if upload_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    analysis_data = active_sessions[upload_id]
    
    # Generate the PDF report
    try:
        file_path = analysis_data.get("file_path")
        pdf_path = generate_pdf_report(analysis_data, file_path)
        
        # Create report response
        report_id = str(uuid.uuid4())
        report_data = {
            "report_id": report_id,
            "analysis_id": upload_id,
            "domain": analysis_data["domain"],
            "timestamp": datetime.now(),
            "risk_level": "high" if analysis_data["risk_score"] >= 70 else "medium" if analysis_data["risk_score"] >= 30 else "low",
            "risk_score": analysis_data["risk_score"],
            "risk_summary": analysis_data["risk_summary"],
            "analysis_date": analysis_data["timestamp"],
            "report_sections": [
                "Executive Summary",
                "Domain Information",
                "Risk Assessment",
                "WHOIS Data",
                "DNS Records",
                "SSL Certificate",
                "VirusTotal Analysis",
                "Timeline"
            ],
            "pdf_path": pdf_path
        }
        
        # Store report data in memory
        active_sessions[report_id] = report_data
        
        return report_data
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@app.get("/report/{report_id}")
async def get_report(report_id: str):
    """Get report data."""
    if report_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return active_sessions[report_id]

@app.get("/report/{report_id}/download")
async def download_report(report_id: str):
    """Download the PDF report."""
    if report_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report_data = active_sessions[report_id]
    pdf_path = report_data.get("pdf_path")
    
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found")
    
    return FileResponse(
        path=pdf_path,
        filename=f"takedowniq-report-{report_id}.pdf",
        media_type="application/pdf"
    )

@app.on_event("shutdown")
async def cleanup():
    """Clean up temporary files on shutdown."""
    try:
        shutil.rmtree(TEMP_DIR)
    except Exception as e:
        logger.error(f"Error cleaning up temporary files: {e}")

# Run the application
if __name__ == "__main__":
    import uvicorn
    # Use port 12345 to avoid conflicts
    port = 12345
    logger.info(f"Starting server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
