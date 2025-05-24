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

    required_fields = ['domain', 'whois_data', 'dns_data', 'ssl_data']
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

    input_data = f"""
You are an internet infrastructure analyst specializing in domain criticality assessment. Your task is to evaluate the real-world disruption impact and potential news visibility if the following domain were suddenly taken offline through ServerHold or ClientHold status.

## IMPORTANT: This is strictly a DISRUPTION IMPACT ANALYSIS, not a security or threat assessment.

## INPUT DATA:
- Domain: {domain}
- WHOIS: {whois_data}
- DNS: {dns_data}
- SSL: {ssl_data}
"""

    output_format = """
## REQUIRED OUTPUT FORMAT:
```json
{
  "summary": "1-3 sentences describing the domain's role, audience, and relevance to global internet infrastructure.",
  "disruption_impact_score": 5,
  "news_impact_score": 5,
  "rationale": "Explanation of the rationale for the scores discussing DNS traffic volume, critical systems usage, service dependencies, and difficulty to replace."
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

## CRITICAL SCORING INSTRUCTIONS - READ CAREFULLY:

**You are NOT evaluating threat level or abuse potential. You are evaluating what would break if this domain was taken offline today.**

You are scoring the **global and systemic impact of placing the domain on ServerHold/ClientHold** — which would remove its DNS records from the zone and make the site inaccessible.

## DOMAIN EVALUATION GUIDELINES:

1. **For standard websites with basic configuration:**
   - Evaluate based on their actual usage and dependencies
   - Consider audience size, geographic reach, and service criticality
   - A personal blog might score 1-2, while a regional news site might score 3-4

2. **For business and organizational domains:**
   - Consider the number of users who rely on the service
   - Evaluate the presence of email services, APIs, or embedded functionality
   - Assess whether the domain hosts critical business functions

3. **For high-impact domains (scores 7-10):**
   - These must demonstrate clear evidence of widespread usage
   - Should support critical infrastructure (healthcare, education, government, financial)
   - Must be essential for business continuity across multiple organizations
   - Examples: major cloud providers, payment processors, communication platforms

4. **News Impact Score:**
   - Consider the domain's public profile and visibility
   - Evaluate how widely the disruption would be reported
   - Major platforms like social media sites would score 8-10
   - Business services might score 4-7 depending on their prominence
   - Personal or small business sites typically score 1-3

Even if a domain might be problematic in some ways, your task is to assess the real-world disruption that would occur if it went offline. For example, a major platform like Zoom would cause significant disruption if taken down, regardless of any other considerations.

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
