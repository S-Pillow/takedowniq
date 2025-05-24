import os
import openai
import httpx
import json
import datetime
import traceback
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

# Initialize logging
import logging
logger = logging.getLogger(__name__)

# Get OpenAI API key from environment
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if OPENAI_API_KEY:
    logger.info(f"OpenAI API key is set. First 4 characters: {OPENAI_API_KEY[:4] if len(OPENAI_API_KEY) > 4 else '[too short]'}")
    logger.info(f"API key length: {len(OPENAI_API_KEY)}")
    if not OPENAI_API_KEY.startswith('sk-'):
        logger.error("OpenAI API key does not start with 'sk-', which is the expected format")
else:
    logger.error("OpenAI API key is not set in environment variables")

# Initialize OpenAI client
client = None
custom_httpx_client = None

if OPENAI_API_KEY:
    custom_httpx_client = httpx.Client(
        transport=httpx.HTTPTransport(retries=3),
        timeout=60.0,
        event_hooks={
            "request": [lambda r: logger.info(f"HTTP Request: {r.method} {r.url}")],
            "response": [lambda r: logger.info(f"HTTP Response: {r.request.method} {r.request.url} {r.status_code}")],
        }
    )
    client = openai.OpenAI(api_key=OPENAI_API_KEY, http_client=custom_httpx_client)
    logger.info("OpenAI client initialized successfully")
else:
    logger.error("Failed to initialize OpenAI client due to missing API key")

def analyze_domain_impact(domain_data: Dict[str, Any]) -> Dict[str, Any]:
    if not domain_data:
        logger.error("Empty domain data provided to analyze_domain_impact")
        return {"error": "No domain data provided for analysis"}

    required_fields = ['domain', 'whois_data', 'dns_data', 'ssl_data', 'virustotal_data']
    missing_fields = [field for field in required_fields if field not in domain_data]
    if missing_fields:
        logger.error(f"Missing required fields in domain data: {missing_fields}")
        return {"error": f"Missing required data: {', '.join(missing_fields)}"}

    if not client:
        logger.error("OpenAI client not initialized. API key may be missing or invalid.")
        return {"error": "OpenAI service unavailable. Please check API configuration."}

    domain = domain_data.get("domain", "[unknown]")
    whois_data = domain_data.get("whois_data", {})
    dns_data = domain_data.get("dns_data", {})
    ssl_data = domain_data.get("ssl_data", {})
    virustotal_data = domain_data.get("virustotal_data", {})

    input_data = f"""
You are a cybersecurity and internet infrastructure analyst. Your task is to assess the global disruption impact and public news relevance if the following domain were placed on ServerHold or ClientHold status. Use the provided technical and contextual data to form a concise, structured, and professionally grounded analysis.

## INPUT DATA:
- Domain: {domain}
- WHOIS: {whois_data}
- DNS: {dns_data}
- SSL: {ssl_data}
- VirusTotal: {virustotal_data}
"""

    output_format = """
## REQUIRED OUTPUT FORMAT:
```json
{
  "summary": "1-3 sentences describing the domain's role, audience, and relevance to global internet infrastructure.",
  "disruption_impact_score": 5,
  "news_impact_score": 5,
  "rationale": "Explanation of the rationale for the scores discussing DNS traffic volume, critical systems usage, service dependencies, and difficulty to replace. Include references to malware findings or SSL issues if relevant."
}
```

## SCORING FRAMEWORK:

### Disruption Impact Score (1-10 scale):
- 1-3: Minimal/localized - personal blogs, niche sites, or inactive domains
- 4-6: Moderate - business tools, regional services, non-critical infrastructure
- 7-8: High - high-traffic platforms, important APIs, financial or communication systems
- 9-10: Catastrophic - root DNS, cloud/CDN providers, payment networks, global services

### News Impact Score (1-10 scale):
- 1-3: Low - no coverage, tech forums only
- 4-6: Notable - regional news, tech media, moderate online attention
- 7-8: High - major tech press, mainstream media attention
- 9-10: Global - widespread news, government statements, global trends

## IMPORTANT CLARIFICATION FOR EVALUATION LOGIC:

- Do not inflate the Disruption Impact Score due to the presence of SPF records, SSL certificates, or MX entries alone — these are common on many domains (legit or malicious) and do not imply widespread infrastructure usage.
- Assign higher disruption scores only if the domain is shown to support:
  - Public service access (e.g., education, healthcare, government portals)
  - Embedded third-party APIs or identity/authentication systems
  - Major cloud or communication platforms with significant user dependency
- Presence of phishing, malware, or abuse flags on VirusTotal does not equal high disruption potential unless:
  - The domain is widely trusted or used by legitimate services
  - It is part of a known exploit chain or has caused public damage
- Treat malicious domains with no legitimate dependency as low disruption/high risk. Their takedown is usually beneficial and should be scored conservatively.
- News Impact Score should be low (1-3) unless the domain is involved in a breach, incident, or campaign covered by mainstream media or trending online.

Base your evaluation on observable data and reasoned inference. Be conservative if data is unclear or incomplete. Return your analysis in a structured, professional tone suitable for automated tools and dashboards.
"""

    prompt = input_data + output_format

    logger.info("[OpenAI] Sending domain impact analysis request for domain: %s", domain)

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity domain analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=400,
            response_format={"type": "json_object"}
        )
        result = response.choices[0].message.content
        parsed_result = json.loads(result)
        return parsed_result
    except Exception as e:
        logger.error("OpenAI error: %s", str(e))
        return {"error": str(e)}
