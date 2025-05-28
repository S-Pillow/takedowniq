import os
import uuid
import tempfile
import shutil
import re
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pathlib import Path

import whoisit
import tldextract
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
    If both fail to provide complete data, use additional sources to get critical information.
    Returns registrar, creation date, expiration date, domain age, and status.
    """
    import rdap
    from datetime import datetime, timezone
    import re
    import socket
    import requests
    import tldextract
    
    # Initialize result with default values
    result = {
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "domain_age": "Unknown",
        "status": "Unknown",
        "whois_privacy": "Unknown",
        "name_servers": [],
        "method_used": None,  # Track which method was used for debugging
        "data_sources": []    # Track which data sources contributed to the result
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
            # Try to parse the date string and remove the time component
            try:
                # Check if this is an ISO format date with time
                if 'T' in date_value or ' ' in date_value:
                    # Try to parse the date with various formats
                    formats = [
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d %H:%M:%S.%f"
                    ]
                    
                    for fmt in formats:
                        try:
                            parsed_date = datetime.strptime(date_value, fmt)
                            return parsed_date.strftime("%Y-%m-%d")
                        except ValueError:
                            continue
                            
                # If we couldn't parse it or it doesn't have a time component, return as is
                return date_value
            except Exception as e:
                logger.warning(f"Error parsing date string: {e}")
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
    
    # Extract domain components for additional lookups
    extracted = tldextract.extract(domain)
    tld = extracted.suffix
    
    # Try RDAP first
    rdap_success = False
    try:
        logger.info(f"Attempting RDAP lookup for {domain}")
        
        # Try whoisit library first as an alternative RDAP client
        try:
            # Bootstrap whoisit if needed
            if not whoisit.is_bootstrapped():
                whoisit.bootstrap()
                
            # Perform domain lookup using whoisit
            whoisit_data = whoisit.domain(domain)
            
            if whoisit_data:
                logger.info(f"Successfully retrieved whoisit RDAP data for {domain}")
                result["method_used"] = "RDAP (whoisit)"
                result["data_sources"].append("RDAP (whoisit)")
                
                # Extract registrar information
                if whoisit_data.get("entities", {}).get("registrar"):
                    registrars = whoisit_data["entities"]["registrar"]
                    if registrars and len(registrars) > 0:
                        result["registrar"] = registrars[0].get("name", "Unknown")
                
                # Extract creation date
                if whoisit_data.get("registration_date"):
                    result["creation_date"] = whoisit_data["registration_date"]
                
                # Extract expiration date
                if whoisit_data.get("expiration_date"):
                    result["expiration_date"] = whoisit_data["expiration_date"]
                
                # Extract status
                if whoisit_data.get("status"):
                    result["status"] = whoisit_data["status"]
                
                # Extract nameservers
                if whoisit_data.get("nameservers"):
                    result["name_servers"] = whoisit_data["nameservers"]
                
                rdap_success = True
                
        except Exception as whoisit_error:
            logger.warning(f"whoisit RDAP lookup failed for {domain}: {whoisit_error}")
            # Continue to standard RDAP lookup
        
        # Standard RDAP lookup if whoisit failed
        if not rdap_success:
            client = rdap.client.RdapClient()
            rdap_data = client.get_domain(domain)
            
            # Extract registrar
            try:
                if hasattr(rdap_data, 'entities') and rdap_data.entities:
                    for entity in rdap_data.entities:
                        if entity.role and 'registrar' in entity.role:
                            result["registrar"] = entity.name
                            break
                        # Some RDAP servers put registrar info in different roles
                        elif entity.role and ('registration' in entity.role or 'registry' in entity.role):
                            if not result["registrar"] or result["registrar"] == "Unknown":
                                result["registrar"] = entity.name
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
                        # Some RDAP servers use different event names
                        elif event.action == 'created' or event.action == 'registered':
                            if not result["creation_date"] or result["creation_date"] == "Unknown":
                                result["creation_date"] = event.date
                        elif event.action == 'expires' or event.action == 'expiry':
                            if not result["expiration_date"] or result["expiration_date"] == "Unknown":
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
            result["data_sources"].append("RDAP")
            rdap_success = True
            logger.info(f"Successfully retrieved RDAP data for {domain}")
        
    except Exception as rdap_error:
        logger.warning(f"RDAP lookup failed for {domain}: {rdap_error}. Falling back to WHOIS.")
    
    # Fall back to WHOIS if RDAP failed or didn't provide complete information
    whois_success = False
    whois_data = None
    if not rdap_success or result["creation_date"] == "Unknown" or result["expiration_date"] == "Unknown":
        try:
            w = whois.whois(domain)
            whois_data = w
            
            # Extract registrar
            try:
                if hasattr(w, 'registrar') and w.registrar:
                    if result["registrar"] == "Unknown":  # Only update if RDAP didn't provide it
                        result["registrar"] = w.registrar
            except Exception as e:
                logger.warning(f"Error extracting registrar from WHOIS: {e}")
            
            # Extract creation date
            try:
                if hasattr(w, 'creation_date') and w.creation_date:
                    if result["creation_date"] == "Unknown":  # Only update if RDAP didn't provide it
                        if isinstance(w.creation_date, list):
                            result["creation_date"] = w.creation_date[0]
                        else:
                            result["creation_date"] = w.creation_date
            except Exception as e:
                logger.warning(f"Error extracting creation date from WHOIS: {e}")
            
            # Extract expiration date
            try:
                if hasattr(w, 'expiration_date') and w.expiration_date:
                    if result["expiration_date"] == "Unknown":  # Only update if RDAP didn't provide it
                        if isinstance(w.expiration_date, list):
                            result["expiration_date"] = w.expiration_date[0]
                        else:
                            result["expiration_date"] = w.expiration_date
            except Exception as e:
                logger.warning(f"Error extracting expiration date from WHOIS: {e}")
            
            # Extract status
            try:
                if hasattr(w, 'status') and w.status:
                    if not result["status"] or result["status"] == "Unknown":  # Only update if RDAP didn't provide it
                        result["status"] = clean_domain_status(w.status)
            except Exception as e:
                logger.warning(f"Error extracting status from WHOIS: {e}")
            
            # Extract nameservers
            try:
                if hasattr(w, 'name_servers') and w.name_servers:
                    if not result["name_servers"]:  # Only update if RDAP didn't provide it
                        result["name_servers"] = w.name_servers
            except Exception as e:
                logger.warning(f"Error extracting nameservers from WHOIS: {e}")
            
            # Check WHOIS privacy
            try:
                has_emails = hasattr(w, 'emails') and w.emails
                has_privacy_registrar = hasattr(w, 'registrar') and w.registrar and "privacy" in str(w.registrar).lower()
                if result["whois_privacy"] == "Unknown":  # Only update if RDAP didn't provide it
                    result["whois_privacy"] = "Enabled" if not has_emails or has_privacy_registrar else "Disabled"
            except Exception as e:
                logger.warning(f"Error determining WHOIS privacy from WHOIS: {e}")
            
            if not result["method_used"]:  # Only update if RDAP didn't succeed
                result["method_used"] = "WHOIS"
            result["data_sources"].append("WHOIS")
            whois_success = True
            logger.info(f"Successfully retrieved WHOIS data for {domain}")
            
        except Exception as whois_error:
            logger.warning(f"WHOIS lookup failed for {domain}: {whois_error}")
            if not rdap_success:
                logger.error(f"Both RDAP and WHOIS lookups failed for {domain}.")
    
    
    # If we still don't have creation date or expiration date, try additional sources
    if result["creation_date"] == "Unknown" or result["expiration_date"] == "Unknown":
        # Try WHOIS server directly for specific TLDs
        try:
            if tld in ["com", "net", "org", "info", "biz", "us"]:
                logger.info(f"Trying direct WHOIS server query for {domain} with TLD: {tld}")
                import socket
                
                # Use the correct WHOIS server for each TLD
                if tld == "us":
                    whois_server = "whois.nic.us"
                elif tld in ["com", "net"]:
                    whois_server = "whois.verisign-grs.com"
                else:
                    whois_server = f"whois.{tld}"
                    
                logger.info(f"Using WHOIS server: {whois_server} for {domain}")
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((whois_server, 43))
                s.send((domain + "\r\n").encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                s.close()
                
                whois_text = response.decode("utf-8", errors="ignore")
                logger.debug(f"WHOIS response for {domain}: {whois_text[:500]}...")
                
                # Different TLDs use different formats for dates
                if tld == "us":
                    # .US specific date formats
                    if result["creation_date"] == "Unknown":
                        # Try multiple patterns for .US domains
                        creation_patterns = [
                            r"Created Date:\s*(.+)",
                            r"Domain Registration Date:\s*(.+)",
                            r"Creation Date:\s*(.+)"
                        ]
                        
                        for pattern in creation_patterns:
                            creation_match = re.search(pattern, whois_text, re.IGNORECASE)
                            if creation_match:
                                result["creation_date"] = creation_match.group(1).strip()
                                result["data_sources"].append("Direct WHOIS (.US)")
                                break
                    
                    if result["expiration_date"] == "Unknown":
                        # Try multiple patterns for .US domains
                        expiration_patterns = [
                            r"Expiration Date:\s*(.+)",
                            r"Domain Expiration Date:\s*(.+)",
                            r"Registry Expiry Date:\s*(.+)"
                        ]
                        
                        for pattern in expiration_patterns:
                            expiration_match = re.search(pattern, whois_text, re.IGNORECASE)
                            if expiration_match:
                                result["expiration_date"] = expiration_match.group(1).strip()
                                result["data_sources"].append("Direct WHOIS (.US)")
                                break
                    
                    # Extract registrar for .US domains
                    if result["registrar"] == "Unknown":
                        registrar_patterns = [
                            r"Registrar:\s*(.+)",
                            r"Sponsoring Registrar:\s*(.+)"
                        ]
                        
                        for pattern in registrar_patterns:
                            registrar_match = re.search(pattern, whois_text, re.IGNORECASE)
                            if registrar_match:
                                result["registrar"] = registrar_match.group(1).strip()
                                result["data_sources"].append("Direct WHOIS (.US)")
                                break
                    
                    # Extract nameservers for .US domains
                    if not result["name_servers"]:
                        ns_matches = re.findall(r"Name Server:\s*(.+)", whois_text, re.IGNORECASE)
                        if ns_matches:
                            result["name_servers"] = [ns.strip() for ns in ns_matches]
                            result["data_sources"].append("Direct WHOIS (.US)")
                    
                    # Extract status for .US domains
                    if result["status"] == "Unknown":
                        status_patterns = [
                            r"Domain Status:\s*(.+)",
                            r"Status:\s*(.+)",
                            r"State:\s*(.+)"
                        ]
                        
                        all_statuses = []
                        for pattern in status_patterns:
                            status_matches = re.findall(pattern, whois_text, re.IGNORECASE)
                            if status_matches:
                                for status in status_matches:
                                    clean_status = status.strip().split(' ')[0]  # Get just the status code
                                    if clean_status and clean_status not in all_statuses:
                                        all_statuses.append(clean_status)
                        
                        if all_statuses:
                            result["status"] = all_statuses
                            result["data_sources"].append("Direct WHOIS (.US)")
                else:
                    # Standard patterns for other TLDs
                    if result["creation_date"] == "Unknown":
                        creation_match = re.search(r"Creation Date:\s*(.+)", whois_text, re.IGNORECASE)
                        if creation_match:
                            result["creation_date"] = creation_match.group(1).strip()
                            result["data_sources"].append("Direct WHOIS")
                    
                    if result["expiration_date"] == "Unknown":
                        expiration_match = re.search(r"Registry Expiry Date:\s*(.+)", whois_text, re.IGNORECASE)
                        if expiration_match:
                            result["expiration_date"] = expiration_match.group(1).strip()
                            result["data_sources"].append("Direct WHOIS")
                
                logger.info(f"Direct WHOIS query completed for {domain} with results: creation_date={result['creation_date']}, expiration_date={result['expiration_date']}, registrar={result['registrar']}")
        except Exception as direct_whois_error:
            logger.warning(f"Direct WHOIS server query failed for {domain}: {direct_whois_error}")
    
    # Try DNS SOA record for an estimation of domain creation
    if result["creation_date"] == "Unknown":
        try:
            logger.info(f"Trying DNS SOA record for {domain}")
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                # SOA serial can sometimes give a clue about creation date
                serial = rdata.serial
                if serial > 20000000:  # Likely a date-based serial (YYYYMMDDNN)
                    year = serial // 10000000
                    if 1990 <= year <= datetime.now().year:  # Sanity check for reasonable years
                        month = (serial // 100000) % 100
                        day = (serial // 1000) % 100
                        if 1 <= month <= 12 and 1 <= day <= 31:  # Valid date
                            estimated_date = datetime(year, month, day, tzinfo=timezone.utc)
                            result["creation_date"] = estimated_date
                            result["creation_date_note"] = "Estimated from DNS SOA serial"
                            result["data_sources"].append("DNS SOA")
                            logger.info(f"Estimated creation date from SOA serial: {estimated_date}")
                            break
        except Exception as soa_error:
            logger.warning(f"DNS SOA lookup failed for {domain}: {soa_error}")
    
    # We're removing the TLD launch date fallback as requested to avoid confusion
    
    # Format dates and calculate domain age
    try:
        # Format creation date
        result["creation_date"] = format_date_safely(result["creation_date"])
        
        # Format expiration date
        result["expiration_date"] = format_date_safely(result["expiration_date"])
        
        # Calculate domain age based on creation date
        if result["creation_date"] and result["creation_date"] != "Unknown":
            result["domain_age"] = calculate_domain_age(result["creation_date"])
            
            # We're not using estimated dates anymore
    except Exception as e:
        logger.error(f"Error formatting dates or calculating domain age: {e}")
    
    # If we still don't have any data, try one more fallback for .US domains
    if tld == "us" and (result["creation_date"] == "Unknown" or result["expiration_date"] == "Unknown"):
        try:
            logger.info(f"Trying additional fallback for .US domain: {domain}")
            # Use python-whois with explicit server for .US domains
            import whois
            w = whois.query(domain, force=True)
            
            if w:
                if result["creation_date"] == "Unknown" and hasattr(w, 'creation_date') and w.creation_date:
                    result["creation_date"] = w.creation_date
                    result["data_sources"].append("WHOIS Fallback (.US)")
                
                if result["expiration_date"] == "Unknown" and hasattr(w, 'expiration_date') and w.expiration_date:
                    result["expiration_date"] = w.expiration_date
                    result["data_sources"].append("WHOIS Fallback (.US)")
                    
                if result["registrar"] == "Unknown" and hasattr(w, 'registrar') and w.registrar:
                    result["registrar"] = w.registrar
                    result["data_sources"].append("WHOIS Fallback (.US)")
                    
                logger.info(f"Additional .US fallback successful for {domain}")
        except Exception as us_fallback_error:
            logger.warning(f"Additional .US fallback failed for {domain}: {us_fallback_error}")
    
    # If we still don't have any data, set an error
    if (not rdap_success and not whois_success and 
        result["creation_date"] == "Unknown" and 
        result["expiration_date"] == "Unknown" and
        not result["name_servers"]):
        result["error"] = "Domain information lookup failed through all available methods"
    
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

async def submit_url_to_virustotal(url: str) -> Dict[str, Any]:
    """Submit a URL to VirusTotal for scanning.
    
    Args:
        url: The URL to scan (should include http:// or https://)
        
    Returns:
        Dictionary with scan results or error information
    """
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key is not available for URL submission.")
        return {"error": "VirusTotal API key not configured"}
    
    # Ensure URL has a scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    
    logger.info(f"Attempting to submit URL to VirusTotal: {url}")
    client = None
    try:
        # Initialize the VirusTotal client
        client = vt.Client(VIRUSTOTAL_API_KEY)
        logger.info("VirusTotal client initialized successfully for URL submission.")
        
        try:
            # Generate the URL identifier
            url_id = vt.url_id(url)
            logger.info(f"Generated URL ID for {url}: {url_id}")
            
            # Submit the URL for analysis
            try:
                logger.info(f"Submitting URL to VirusTotal: {url}")
                await client.scan_url_async(url)
                logger.info(f"Successfully submitted URL for scanning: {url}")
            except Exception as scan_error:
                logger.error(f"Error during VirusTotal scan_url_async: {scan_error}", exc_info=True)
                return {"error": f"Failed to submit URL for scanning: {str(scan_error)}"}
            
            # Wait a moment for the scan to start processing
            try:
                logger.info("Waiting for scan to initialize...")
                await asyncio.sleep(2)
                logger.info("Wait completed, attempting to retrieve initial results")
            except Exception as sleep_error:
                logger.error(f"Error during asyncio.sleep: {sleep_error}", exc_info=True)
                # Continue despite sleep error - we can still try to get results
            
            # Try to get the initial analysis results
            try:
                logger.info(f"Retrieving initial analysis for URL ID: {url_id}")
                analysis = await client.get_object_async(f"/urls/{url_id}")
                last_analysis_stats = analysis.get("last_analysis_stats", {})
                last_analysis_date = analysis.get("last_analysis_date")
                
                logger.info(f"Retrieved initial analysis stats: {last_analysis_stats}")
                
                result = {
                    "success": True,
                    "message": "URL submitted for scanning",
                    "url": url,
                    "last_analysis_stats": last_analysis_stats,
                    "last_analysis_date": last_analysis_date,
                    "scan_id": url_id
                }
            except Exception as analysis_error:
                logger.warning(f"Could not retrieve initial analysis results: {analysis_error}")
                # If we can't get results yet, that's okay - scanning might take time
                result = {
                    "success": True,
                    "message": "URL submitted for scanning. Results may take a few minutes to process.",
                    "url": url,
                    "scan_id": url_id
                }
            
            logger.info(f"Returning scan submission result for {url}")
            return result
            
        except Exception as url_error:
            logger.error(f"Error processing URL {url}: {url_error}", exc_info=True)
            return {"error": f"Error processing URL: {str(url_error)}"}
        
    except Exception as client_error:
        logger.error(f"Error initializing VirusTotal client: {client_error}", exc_info=True)
        return {"error": f"Failed to initialize VirusTotal client: {str(client_error)}"}
    finally:
        if client:
            try:
                logger.info("Closing VirusTotal client")
                await client.close()
                logger.info("VirusTotal client closed successfully")
            except Exception as close_error:
                logger.error(f"Error closing VirusTotal client: {close_error}", exc_info=True)

async def get_virustotal_data(domain: str, force_scan: bool = False) -> Dict[str, Any]:
    """Get VirusTotal information for a domain.
    
    Args:
        domain: The domain to look up
        force_scan: If True, submit the domain for a fresh scan before retrieving results
        
    Returns:
        Dictionary containing VirusTotal data
    """
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
        # If force_scan is True, submit the domain for a fresh scan first
        if force_scan:
            logger.info(f"Force scan requested for domain: {domain}")
            # Submit the domain URL for scanning
            url = f"https://{domain}"
            url_id = vt.url_id(url)
            await client.scan_url_async(url)
            logger.info(f"Successfully submitted domain for forced scanning: {domain}")
            
            # Wait a moment for the scan to start processing
            await asyncio.sleep(3)
            
            # Note: We continue with the regular domain lookup as the scan may take time to complete
            # The next analysis will show the updated results once they're available
        
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
        
        # Get last analysis date and convert it to a Unix timestamp (seconds since epoch)
        raw_vt_date = domain_obj.get("last_analysis_date")
        timestamp_value = None

        try:
            # First, handle the case where raw_vt_date is already an integer (Unix timestamp)
            if isinstance(raw_vt_date, int) and raw_vt_date > 0:
                timestamp_value = raw_vt_date
                logger.info(f"Successfully used existing VirusTotal timestamp: {raw_vt_date}")
            # Next, handle the case where raw_vt_date is a string
            elif isinstance(raw_vt_date, str) and raw_vt_date.strip():
                # Try to parse as ISO format string first
                try:
                    # If it's in ISO format, convert to Unix timestamp
                    parsed_date = datetime.fromisoformat(raw_vt_date.replace('Z', '+00:00'))
                    timestamp_value = int(parsed_date.timestamp())
                    logger.info(f"Successfully converted ISO date to timestamp: {raw_vt_date} -> {timestamp_value}")
                except ValueError:
                    # If not ISO format, try to convert directly to integer timestamp
                    try:
                        timestamp_int = int(raw_vt_date)
                        if timestamp_int > 0:
                            timestamp_value = timestamp_int
                            logger.info(f"Successfully parsed VirusTotal timestamp from string: {raw_vt_date}")
                        else:
                            logger.info(f"VirusTotal timestamp '{raw_vt_date}' is non-positive: {timestamp_int}, using current time")
                            timestamp_value = int(datetime.now(tz=timezone.utc).timestamp())
                    except ValueError:
                        logger.info(f"VirusTotal last_analysis_date is not a valid format: '{raw_vt_date}', using current time")
                        timestamp_value = int(datetime.now(tz=timezone.utc).timestamp())
            elif raw_vt_date is None or raw_vt_date == "":
                logger.info("VirusTotal last_analysis_date is None or empty, using current time")
                timestamp_value = int(datetime.now(tz=timezone.utc).timestamp())
            else:
                logger.info(f"VirusTotal last_analysis_date is of unexpected type: {type(raw_vt_date).__name__}, using current time")
                timestamp_value = int(datetime.now(tz=timezone.utc).timestamp())
        except Exception as e:
            logger.info(f"Error parsing VirusTotal date: {e}, using current time")
            timestamp_value = int(datetime.now(tz=timezone.utc).timestamp())
        
        # Build the result
        result = {
            "malicious_count": last_analysis_stats.get("malicious", 0),
            "suspicious_count": last_analysis_stats.get("suspicious", 0),
            "harmless_count": last_analysis_stats.get("harmless", 0),
            "undetected_count": last_analysis_stats.get("undetected", 0),
            "total_engines": sum(last_analysis_stats.values()),
            "detections": detections,
            "categories": categories,
            "last_analysis_date": timestamp_value  # Use the Unix timestamp value
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
    """Enhanced risk score calculation based on vendor reputation and detection patterns.
    Implements a weighted scoring system that gives higher importance to well-established
    security vendors based on their industry reputation and reliability.
    """
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

    # Define vendor tiers with different weights
    # Tier 1: Highest reputation vendors (weight 3)
    tier1_vendors = {
        "Kaspersky", "Symantec", "Microsoft", "ESET"
    }
    
    # Tier 2: Well-established vendors (weight 2)
    tier2_vendors = {
        "BitDefender", "Sophos", "Fortinet", "McAfee", 
        "TrendMicro", "F-Secure", "CrowdStrike", "Palo Alto Networks"
    }
    
    # Tier 3: Other reputable vendors (weight 1)
    tier3_vendors = {
        "Avira", "Webroot", "G-Data", "Avast", "AVG", "Malwarebytes",
        "SentinelOne", "Cylance", "Emsisoft", "Comodo", "AhnLab"
    }
    
    # All reputable vendors (for backward compatibility)
    reputable_vendors = tier1_vendors.union(tier2_vendors).union(tier3_vendors)
    
    def weighted_vendor_score(flagged_vendors):
        # Convert flagged_vendors to a set for efficient lookups
        flagged_set = set(flagged_vendors)
        
        # Calculate weighted score based on vendor tiers
        tier1_detections = tier1_vendors.intersection(flagged_set)
        tier2_detections = tier2_vendors.intersection(flagged_set)
        tier3_detections = tier3_vendors.intersection(flagged_set)
        
        # Apply weights to each tier
        weighted_count = (len(tier1_detections) * 3) + (len(tier2_detections) * 2) + len(tier3_detections)
        
        # Log the weighted detection information
        logger.info(f"Weighted vendor detections: Tier 1: {len(tier1_detections)} (weight 3), "
                   f"Tier 2: {len(tier2_detections)} (weight 2), "
                   f"Tier 3: {len(tier3_detections)} (weight 1), "
                   f"Total weighted count: {weighted_count}")
        
        # Calculate score based on weighted count
        if weighted_count >= 12:  # Equivalent to 4 Tier 1 vendors
            return 30
        elif weighted_count >= 9:  # Equivalent to 3 Tier 1 vendors
            return 25
        elif weighted_count >= 6:  # Equivalent to 2 Tier 1 vendors
            return 20
        elif weighted_count >= 3:  # Equivalent to 1 Tier 1 vendor
            return 15
        elif weighted_count >= 1:  # At least one lower-tier vendor
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
    vendor = weighted_vendor_score(flagged_vendors)
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
    section_heading_style = ParagraphStyle(
        "SectionHeading",
        parent=heading_style,
        fontSize=16,
        spaceAfter=6,
        spaceBefore=12,
        backColor=colors.lightgrey,
        borderWidth=1,
        borderColor=colors.black,
        borderPadding=5,
        borderRadius=2
    )
    
    # Content elements
    elements = []
    
    # Title
    elements.append(Paragraph(f"TakedownIQ Domain Analysis Report", title_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # SECTION 1: Domain Information
    elements.append(Paragraph("DOMAIN INFORMATION", section_heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    # Domain and timestamp
    elements.append(Paragraph(f"Domain: {domain}", heading_style))
    elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.15*inch))
    
    # WHOIS data
    elements.append(Paragraph("WHOIS Information", heading_style))
    whois_data = analysis_data.get("whois_data", {})
    if whois_data and not whois_data.get("error"):
        # Create a better formatted WHOIS table
        whois_table_data = []
        registrar = whois_data.get("registrar")
        creation_date = whois_data.get("creation_date")
        expiration_date = whois_data.get("expiration_date")
        domain_age = whois_data.get("domain_age")
        status = whois_data.get("status")
        name_servers = whois_data.get("name_servers")
        
        if registrar:
            whois_table_data.append(["Registrar", str(registrar)])
        if creation_date:
            whois_table_data.append(["Registration Date", str(creation_date)])
        if expiration_date:
            whois_table_data.append(["Expiration Date", str(expiration_date)])
        if domain_age:
            whois_table_data.append(["Domain Age", str(domain_age)])
        
        # Add the table if we have data
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
            elements.append(Spacer(1, 0.1*inch))
        
        # Domain Status as a list
        if status:
            elements.append(Paragraph("Domain Status:", subheading_style))
            if isinstance(status, (list, tuple)):
                for s in status:
                    elements.append(Paragraph(f"• {s}", normal_style))
            else:
                elements.append(Paragraph(f"• {status}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # Name Servers as a list
        if name_servers:
            elements.append(Paragraph("Name Servers:", subheading_style))
            if isinstance(name_servers, (list, tuple)):
                for ns in name_servers:
                    elements.append(Paragraph(f"• {ns}", normal_style))
            else:
                elements.append(Paragraph(f"• {name_servers}", normal_style))
        
        if not (whois_table_data or status or name_servers):
            elements.append(Paragraph("No WHOIS data available.", normal_style))
    else:
        elements.append(Paragraph("No WHOIS data available.", normal_style))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # SECTION 2: Risk Assessment and Impact Analysis
    elements.append(Paragraph("RISK ASSESSMENT & IMPACT ANALYSIS", section_heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
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
    elements.append(Spacer(1, 0.15*inch))
    
    # ChatGPT Impact Analysis
    elements.append(Paragraph("ChatGPT Impact Analysis", heading_style))
    chatgpt_data = analysis_data.get("chatgpt_impact", {})
    if chatgpt_data and not chatgpt_data.get("error"):
        # Add disruption impact score
        disruption_score = chatgpt_data.get("disruption_impact_score", 0)
        disruption_style = risk_high_style if disruption_score >= 7 else \
                          risk_medium_style if disruption_score >= 4 else \
                          normal_style
        elements.append(Paragraph(f"Disruption Impact Score: {disruption_score}/10", disruption_style))
        
        # Add news impact score if available
        news_score = chatgpt_data.get("news_impact_score")
        if news_score is not None:
            news_style = risk_high_style if news_score >= 7 else \
                        risk_medium_style if news_score >= 4 else \
                        normal_style
            elements.append(Paragraph(f"News Impact Score: {news_score}/10", news_style))
        
        # Add impact analysis
        impact_analysis = chatgpt_data.get("impact_analysis")
        if impact_analysis:
            elements.append(Paragraph("Impact Analysis:", subheading_style))
            elements.append(Paragraph(impact_analysis, normal_style))
        
        # Add justification
        justification = chatgpt_data.get("justification")
        if justification:
            elements.append(Paragraph("Justification:", subheading_style))
            elements.append(Paragraph(justification, normal_style))
    else:
        elements.append(Paragraph("No ChatGPT impact analysis available.", normal_style))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # SECTION 3: Evidence and Analysis
    elements.append(Paragraph("EVIDENCE & ANALYSIS", section_heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    # Screenshot if available
    if image_path and os.path.exists(image_path):
        try:
            # Add the screenshot
            elements.append(Paragraph("Evidence Screenshot", heading_style))
            img = Image(image_path, width=6*inch, height=4*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.15*inch))
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
    
    elements.append(Spacer(1, 0.15*inch))
    
    # VirusTotal data with improved formatting
    elements.append(Paragraph("VirusTotal Analysis", heading_style))
    vt_data = analysis_data.get("virustotal_data", {})
    if vt_data and not vt_data.get("error"):
        malicious_count = vt_data.get("malicious_count", 0)
        suspicious_count = vt_data.get("suspicious_count", 0)
        harmless_count = vt_data.get("harmless_count", 0)
        undetected_count = vt_data.get("undetected_count", 0)
        total_engines = vt_data.get("total_engines", 0)
        
        # Create a summary table for VirusTotal results
        vt_summary_data = [
            ["Status", "Count", "Percentage"],
            ["Malicious", str(malicious_count), f"{(malicious_count/total_engines*100) if total_engines else 0:.1f}%"],
            ["Suspicious", str(suspicious_count), f"{(suspicious_count/total_engines*100) if total_engines else 0:.1f}%"],
            ["Harmless", str(harmless_count), f"{(harmless_count/total_engines*100) if total_engines else 0:.1f}%"],
            ["Undetected", str(undetected_count), f"{(undetected_count/total_engines*100) if total_engines else 0:.1f}%"],
            ["Total", str(total_engines), "100%"]
        ]
        
        vt_table = Table(vt_summary_data, colWidths=[1.5*inch, 1*inch, 1*inch])
        vt_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Highlight malicious row if there are detections
            ('BACKGROUND', (0, 1), (-1, 1), colors.pink if malicious_count > 0 else colors.white),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold' if malicious_count > 0 else 'Helvetica'),
            # Highlight suspicious row if there are suspicious results
            ('BACKGROUND', (0, 2), (-1, 2), colors.lightgrey if suspicious_count > 0 else colors.white),
        ]))
        elements.append(vt_table)
        elements.append(Spacer(1, 0.1*inch))
        
        # Categories
        if vt_data.get("categories"):
            elements.append(Paragraph("Categories:", subheading_style))
            for vendor, category in vt_data["categories"].items():
                elements.append(Paragraph(f"• {category} (according to {vendor})", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        # Detections
        if vt_data.get("detections"):
            elements.append(Paragraph("Detection Details:", subheading_style))
            # Create a table for detections
            detection_data = [["Engine", "Category", "Result"]]
            for detection in vt_data["detections"]:
                detection_data.append([
                    detection.get('engine', 'Unknown'),
                    detection.get('category', 'Unknown'),
                    detection.get('result', 'Unknown')
                ])
            
            if len(detection_data) > 1:  # Only create table if we have detections
                detection_table = Table(detection_data, colWidths=[1.5*inch, 1*inch, 2*inch])
                detection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    # Highlight malicious rows
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightpink),
                ]))
                elements.append(detection_table)
    else:
        elements.append(Paragraph("No VirusTotal data available.", normal_style))
    
    # SECTION 4: Additional Notes
    elements.append(Spacer(1, 0.25*inch))
    elements.append(Paragraph("ADDITIONAL NOTES", section_heading_style))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph("Additional Notes", heading_style))
    notes = analysis_data.get("notes")
    if notes and notes.strip():
        elements.append(Paragraph(notes, normal_style))
    else:
        elements.append(Paragraph("No additional notes provided.", normal_style))
    
    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph("This report was generated by TakedownIQ for investigation purposes.", 
                             ParagraphStyle("Footer", parent=normal_style, alignment=1, fontSize=8, textColor=colors.gray)))
    elements.append(Paragraph("All data is processed in-memory and not stored after the session ends.", 
                             ParagraphStyle("Footer", parent=normal_style, alignment=1, fontSize=8, textColor=colors.gray)))
    
    # Build the PDF
    doc.build(elements)
    
    return str(pdf_path)

# API Routes

# Match the pattern of other working endpoints
@app.post("/virustotal/force-scan")
@app.post("/api/virustotal/force-scan")
@app.options("/virustotal/force-scan")
@app.options("/api/virustotal/force-scan")
async def force_virustotal_scan(request: Request):
    """
    Force a new VirusTotal scan for a domain.
    
    Expects a JSON body with:
    - domain: The domain to scan
    
    Returns the scan submission result.
    """
    # Log the request method and headers for debugging
    request_id = str(uuid.uuid4())[:8]  # Generate a short request ID for tracking
    logger.info(f"[{request_id}] Received force scan request: {request.method} {request.url}")
    logger.info(f"[{request_id}] Request headers: {dict(request.headers)}")
    
    # Handle OPTIONS requests for CORS preflight
    if request.method == "OPTIONS":
        logger.info(f"[{request_id}] Handling OPTIONS preflight request")
        return JSONResponse(
            status_code=200,
            content={"detail": "OK"}
        )
    
    try:
        # Get the request body
        try:
            data = await request.json()
            logger.info(f"[{request_id}] Request body: {data}")
            domain = data.get("domain")
        except Exception as json_err:
            logger.error(f"[{request_id}] Error parsing JSON: {json_err}", exc_info=True)
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Invalid JSON: {str(json_err)}",
                    "request_id": request_id
                }
            )
        
        if not domain:
            logger.error(f"[{request_id}] Missing domain parameter")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Domain is required",
                    "request_id": request_id
                }
            )
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            logger.error(f"[{request_id}] Invalid domain format: {domain}")
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Invalid domain format: {domain}",
                    "request_id": request_id
                }
            )
        
        logger.info(f"[{request_id}] Submitting domain for VirusTotal scanning: {domain}")
        
        # Submit the domain for scanning
        url = f"https://{domain}"
        scan_result = await submit_url_to_virustotal(url)
        
        # Add request tracking information
        scan_result["request_id"] = request_id
        
        # Add a message to indicate the scan was requested
        if "error" not in scan_result:
            scan_result["message"] = "Scan requested successfully. Results will be available in a few minutes."
            logger.info(f"[{request_id}] Successfully submitted domain for scanning: {domain}")
            return JSONResponse(
                status_code=200,
                content=scan_result
            )
        else:
            logger.error(f"[{request_id}] Error from VirusTotal submission: {scan_result['error']}")
            return JSONResponse(
                status_code=500,
                content=scan_result
            )
    
    except Exception as e:
        logger.error(f"[{request_id}] Unhandled error in force_virustotal_scan: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to submit scan: {str(e)}",
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

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
        
        # Store the ChatGPT impact analysis in the active_sessions
        # First, check if we can identify the session from the domain
        domain = data.get('domain')
        upload_id = None
        
        for session_id, session_data in active_sessions.items():
            if session_data.get('domain') == domain:
                upload_id = session_id
                break
        
        if upload_id:
            logger.info(f"Found matching session for domain {domain}, storing ChatGPT impact analysis")
            # Store the ChatGPT impact analysis in the session data
            active_sessions[upload_id]['chatgpt_impact'] = result
        else:
            logger.warning(f"Could not find matching session for domain {domain}, ChatGPT impact analysis won't be included in PDF report")
        
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
