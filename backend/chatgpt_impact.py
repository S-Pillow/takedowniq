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
- Domain: {domain} – Use your general knowledge and search your internal understanding of the internet to identify if this domain is publicly known or critical.
- WHOIS: {whois_data} – Look for signs of organizational backing, domain age, and registrar reputation. Is an organization listed? Does the domain appear longstanding or newly registered?
- DNS: {dns_data} – Evaluate whether the domain has real infrastructure: multiple records, MX entries (email usage), CNAMEs or records pointing to platforms like AWS, Google Cloud, or enterprise services. Are there signs of embedded services or external dependency?
- SSL: {ssl_data} – Determine whether the certificate is valid, wildcarded, issued by a known authority, and supports subdomains. This can suggest professional infrastructure, but **SSL alone does not justify higher scores**.
"""

    output_format = """
## REQUIRED OUTPUT FORMAT:
```json
{
  "summary": "1–3 sentence overview of what this domain appears to do and who might use it.",
  "disruption_impact_score": 1,
  "news_impact_score": 1,
  "rationale": "Explain how critical this domain is to real-time services, infrastructure, or global operations. Discuss whether it's likely to be embedded in workflows, serve institutions, or impact public services. Consider user reach, business dependencies, and brand recognition."
}
```

---

## DETAILED DOMAIN IMPACT SCORING CRITERIA

### Disruption Impact Score (1–10)

**Level 1: Minimal Localized Impact**
- Personal blogs/websites with virtually no visitors
- Inactive domains or placeholder sites
- Domains used only for testing or development
- No dependencies from other services
- Content that is entirely duplicated elsewhere

**Level 2: Very Limited Impact**
- Small personal/hobby websites with few daily visitors
- Non-essential content repositories
- Sites with complete functional equivalents readily available
- Domains used primarily for email by a small number of users
- Niche forums or communities with minimal active users

**Level 3: Minor Impact**
- Small business websites serving as brochures
- Low-traffic blogs or content sites (thousands of daily visitors)
- Non-critical tools with many alternatives
- Specialized content sites with limited but dedicated users
- Sites without real-time requirements or dependencies

**Level 4: Moderate Local Impact** ⚠️
- Regional service providers with moderate user bases
- Small SaaS tools used by businesses but with alternatives
- Specialized professional forums or communities
- Secondary sites for larger organizations
- Domains hosting resources referenced by other sites

**Level 5: Notable Sectoral Impact** ⚠️
- Industry-specific platforms with substantial user bases
- Medium-sized business services affecting workflows
- Regional news or information portals
- Specialized B2B services with industry importance
- Sites with hundreds of thousands of daily users

**Level 6: Significant Regional Impact** ⚠️
- Major regional services affecting millions
- Business tools with significant market share
- Secondary infrastructure components
- Primary sites for large organizations
- Services depended upon by smaller sites

**Level 7: Major Impact** ⚠️
- Major services with tens of millions of users
- Critical business infrastructure affecting multiple industries
- Popular communication platforms
- Important financial services
- Major cloud service components

**Level 8: Severe Impact** ⚠️
- Global platforms with hundreds of millions of users
- Critical infrastructure components
- Major payment processors
- Primary communication platforms for businesses
- Services with few practical alternatives

**Level 9: Critical Global Impact** ⚠️
- Essential global platforms with billions of users
- Critical internet infrastructure components
- Major CDN providers
- Primary global cloud services
- Core financial infrastructure

**Level 10: Catastrophic Impact** ⚠️
- Core internet infrastructure (DNS roots, global platforms)
- Services relied on by billions daily
- Cascading outages across internet services
- Outages could threaten life safety or national security

---

### News Impact Score Criteria (1–10)

**Level 1: Virtually Unnoticed**
- No coverage outside specialized forums
- Only noticed by site owners
- No social media or search activity
- No industry attention

**Level 2: Minimal Notice**
- Mentioned only in niche tech communities
- Affected users might post about it
- No coverage in tech publications

**Level 3: Limited Awareness**
- Discussed in industry forums or niche blogs
- Scattered social media mentions
- Might appear in specialized newsletters

**Level 4: Notable Coverage** 📰
- Coverage in technology news sites
- Discussions across online communities
- Industry publication mentions
- Minor search interest spike

**Level 5: Industry-Wide Coverage** 📰
- Coverage in multiple tech publications
- Trending in professional communities
- Active social discussions
- Brief mentions in mainstream tech outlets

**Level 6: Broad Tech Coverage** 📰
- Featured in major tech publications
- Discussions extend to broader business media
- Industry responses issued

**Level 7: Mainstream Attention** 📰
- Covered in mainstream media's tech sections
- General news mentions
- TV tech news segments
- Widespread online chatter

**Level 8: Major News Story** 📰
- Prominent mainstream media coverage
- Dedicated TV segments
- Trending widely on social platforms
- Official responses from major companies

**Level 9: Global News Event** 📰
- Breaking news on major outlets
- Lead tech headlines globally
- Government or regulatory response
- Sustained global conversation

**Level 10: Historic News Event** 📰
- Top story globally
- Media interruptions
- Investigations launched
- Future reference point in internet history

---

## CROSS-REFERENCING & CONTEXTUAL INFERENCE

You may use your general internet knowledge and training to evaluate the domain beyond the input data:

- Recognize public brands and services (e.g., `paypal.com`, `dropbox.com`, `zoom.us`, `microsoft.com`, `googleapis.com`)
- Infer real-world impact based on brand familiarity, public usage, and ecosystem relevance
- If the domain appears widely used or integrated into infrastructure, you may assign higher scores even if DNS/WHOIS data seems minimal

Conversely, if the domain is unfamiliar, unbranded, and lacks visibility or infrastructure signs — **you must default to lower scores (1–3)**.

When unsure, err on the side of underestimating rather than overstating impact.
Return a structured, reasoned judgment in your response suitable for automated tools and executive dashboards.
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
