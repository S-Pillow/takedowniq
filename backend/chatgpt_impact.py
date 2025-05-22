import os
import openai
import httpx # Import httpx
from typing import Dict, Any

from dotenv import load_dotenv
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# openai.api_key = OPENAI_API_KEY # Old way

import logging
logger = logging.getLogger(__name__)

# New: Initialize the OpenAI client explicitly with a custom httpx client
if OPENAI_API_KEY:
    # Create an httpx client with proxies explicitly set to None
    custom_httpx_client = httpx.Client(proxies=None)
    client = openai.OpenAI(api_key=OPENAI_API_KEY, http_client=custom_httpx_client)
else:
    client = None # Or handle error appropriately
    logger.error("[OpenAI] API key not found. Cannot initialize client.")
    custom_httpx_client = None # Ensure it's defined for potential later cleanup if needed

def analyze_domain_impact(domain_data: Dict[str, Any]) -> Dict[str, Any]:
    if not client:
        return {"error": "OpenAI client not initialized. API key may be missing."}
    """
    Calls the OpenAI API (ChatGPT) to analyze and score the impact of placing a domain on registry server hold.
    Returns a structured response with Disruption Impact Score, News Impact Score, and rationale.
    """
    domain = domain_data.get("domain", "[unknown]")
    whois_data = domain_data.get("whois_data", {})
    dns_data = domain_data.get("dns_data", {})
    ssl_data = domain_data.get("ssl_data", {})
    virustotal_data = domain_data.get("virustotal_data", {})

    prompt = f"""
You are a cybersecurity domain analyst. Given the following data for a domain, estimate the impact of placing this domain on registry server hold. 
Provide your answer in the following JSON format:
{{
  "disruption_impact_score": <1-10 integer>,
  "news_impact_score": <1-10 integer>,
  "rationale": "<short explanation for stakeholders>",
  "criteria": {{
    "disruption": "<how you estimated the disruption impact>",
    "news": "<how you estimated the news impact>"
  }}
}}

Domain: {domain}
WHOIS: {whois_data}
DNS: {dns_data}
SSL: {ssl_data}
VirusTotal: {virustotal_data}

If data is missing, make reasonable assumptions. Be concise and structured. Only return valid JSON.
"""

    # Log the request payload (excluding API key)
    logger.info("[OpenAI] Sending domain impact analysis request: %s", {
        "domain": domain,
        "whois_data": whois_data,
        "dns_data": dns_data,
        "ssl_data": ssl_data,
        "virustotal_data": virustotal_data,
    })

    if not client:
        # This check is redundant if the one at the start of the function is present
        # but kept for safety in case of future refactoring.
        return {"error": "OpenAI client not initialized."}

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "system", "content": "You are a cybersecurity domain analyst."},
                  {"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=400,
        response_format={"type": "json_object"}
    )
    # Parse and return the JSON result
    try:
        result = response.choices[0].message.content
        logger.info("[OpenAI] Response: %s", result)
        import json
        return json.loads(result)
    except Exception as e:
        logger.error("[OpenAI] Error parsing response: %s", str(e))
        return {"error": str(e), "raw_response": str(response)}
