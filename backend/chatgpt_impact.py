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

# Check if API key is available
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
    # Create a custom httpx client with logging
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


def test_openai_connection() -> Dict[str, Any]:
    """
    Test function to verify the OpenAI client is working correctly.
    Returns a success message if the connection is working, or an error message if not.
    """
    try:
        if not client:
            return {"error": "OpenAI client not initialized. API key may be missing or invalid."}
        
        logger.info("Testing OpenAI connection with a simple request")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "You are a helpful assistant."},
                      {"role": "user", "content": "Say hello"}],
            temperature=0.3,
            max_tokens=10
        )
        
        result = response.choices[0].message.content
        logger.info(f"OpenAI test successful. Response: {result}")
        return {"success": True, "message": "OpenAI connection is working", "response": result}
    except Exception as e:
        logger.error(f"Error testing OpenAI connection: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {"error": f"Error testing OpenAI connection: {str(e)}"}


def analyze_domain_impact(domain_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls the OpenAI API (ChatGPT) to analyze and score the impact of placing a domain on registry server hold.
    Returns a structured response with Disruption Impact Score, News Impact Score, and rationale.
    """
    # Validate input data
    if not domain_data:
        logger.error("Empty domain data provided to analyze_domain_impact")
        return {"error": "No domain data provided for analysis"}
        
    # Check for required fields
    required_fields = ['domain', 'whois_data', 'dns_data', 'ssl_data', 'virustotal_data']
    missing_fields = [field for field in required_fields if field not in domain_data]
    if missing_fields:
        logger.error(f"Missing required fields in domain data: {missing_fields}")
        return {"error": f"Missing required data: {', '.join(missing_fields)}"}
    
    # Check if OpenAI client is initialized
    if not client:
        logger.error("OpenAI client not initialized. API key may be missing or invalid.")
        return {"error": "OpenAI service unavailable. Please check API configuration."}
    
    # Log analysis start
    logger.info(f"Starting impact analysis for domain: {domain_data.get('domain')}")
    logger.info(f"Data provided: {list(domain_data.keys())}")
    
    # Extract data from the input
    domain = domain_data.get("domain", "[unknown]")
    whois_data = domain_data.get("whois_data", {})
    dns_data = domain_data.get("dns_data", {})
    ssl_data = domain_data.get("ssl_data", {})
    virustotal_data = domain_data.get("virustotal_data", {})
    
    #############################################################################
    #                                                                           #
    #                      !!! CRITICAL PROMPT SECTION !!!                      #
    #                                                                           #
    # WARNING: This prompt has been carefully crafted and calibrated.            #
    # Modifications may significantly impact analysis quality and consistency.   #
    # Consult with the security team before making ANY changes.                  #
    #                                                                           #
    #############################################################################
    
    # This prompt defines the entire structure and quality of the domain impact analysis.
    # It provides the framework for evaluating domains placed on ServerHold/ClientHold.
    # The exact wording, scoring criteria, and output format are essential for consistent
    # and accurate domain impact assessments across the application.
    # First part of the prompt with the input data (using f-string for variable substitution)
    input_data = f"""
You are a cybersecurity and internet infrastructure analyst. Your task is to assess the **global disruption impact** and **news visibility** if the following domain were placed on **ServerHold** or **ClientHold** status. Use the data provided and apply a structured framework to generate a concise but technically-informed response.

## INPUT DATA:
- Domain: {domain}
- WHOIS: {whois_data}
- DNS: {dns_data}
- SSL: {ssl_data}
- VirusTotal: {virustotal_data}
"""

    # Second part of the prompt with the output format and scoring framework (using raw string to avoid formatting issues)
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

Base your evaluation on observable data and reasoned inference. Be conservative if data is unclear or incomplete. Return your analysis in a structured, professional tone suitable for automated tools and dashboards.
"""

    # Combine the parts to create the full prompt
    prompt = input_data + output_format

    #############################################################################
    #                                                                         #
    #                     END OF CRITICAL PROMPT SECTION                     #
    #                                                                         #
    #############################################################################

    # Log the request payload and prompt
    logger.info("[OpenAI] Sending domain impact analysis request for domain: %s", domain)
    
    # Create a detailed log file for audit and debugging purposes
    import json
    import datetime
    import os
    
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chatgpt_logs")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(log_dir, f"chatgpt_request_{domain.replace('.', '_')}_{timestamp}.json")
    
    with open(log_filename, "w") as f:
        json.dump({
            "timestamp": datetime.datetime.now().isoformat(),
            "domain": domain,
            "request_data": {
                "domain": domain,
                "whois_data": whois_data,
                "dns_data": dns_data,
                "ssl_data": ssl_data,
                "virustotal_data": virustotal_data,
            },
            "prompt": prompt
        }, f, indent=2)
    
    logger.info("[OpenAI] Full request logged to: %s", log_filename)

    if not client:
        # This check is redundant if the one at the start of the function is present
        # but kept for safety in case of future refactoring.
        return {"error": "OpenAI client not initialized."}

    try:
        logger.info("[DEBUG] About to call OpenAI API")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "You are a cybersecurity domain analyst."},
                      {"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400,
            response_format={"type": "json_object"}
        )
        logger.info("[DEBUG] OpenAI API call successful")
    except Exception as e:
        logger.error(f"[DEBUG] Error calling OpenAI API: {str(e)}")
        logger.error(f"[DEBUG] Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"[DEBUG] Traceback: {traceback.format_exc()}")
        return {"error": f"Error calling OpenAI API: {str(e)}"}
    # Parse and return the JSON result
    try:
        result = response.choices[0].message.content
        logger.info("[OpenAI] Received response for domain: %s", domain)
        
        # Log the response to a file
        import json
        import datetime
        import os
        
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chatgpt_logs")
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(log_dir, f"chatgpt_response_{domain.replace('.', '_')}_{timestamp}.json")
        
        try:
            parsed_result = json.loads(result)
            
            with open(log_filename, "w") as f:
                json.dump({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "domain": domain,
                    "raw_response": result,
                    "parsed_response": parsed_result,
                    "model": "gpt-3.5-turbo",
                    "usage": {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens
                    }
                }, f, indent=2)
            
            logger.info("[OpenAI] Full response logged to: %s", log_filename)
            return parsed_result
        except json.JSONDecodeError as e:
            logger.error(f"[DEBUG] Error parsing JSON result: {str(e)}")
            logger.error(f"[DEBUG] Result content: {result}")
            return {"error": f"Error parsing ChatGPT response: {str(e)}"}
        except Exception as e:
            logger.error(f"[DEBUG] Unexpected error in analyze_domain_impact: {str(e)}")
            import traceback
            logger.error(f"[DEBUG] Traceback: {traceback.format_exc()}")
            return {"error": f"Unexpected error in ChatGPT analysis: {str(e)}"}
    except Exception as e:
        logger.error("[OpenAI] Error parsing response: %s", str(e))
        
        # Log the error
        import datetime
        import os
        
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chatgpt_logs")
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(log_dir, f"chatgpt_error_{domain.replace('.', '_')}_{timestamp}.txt")
        
        with open(log_filename, "w") as f:
            f.write(f"Error: {str(e)}\n\nRaw response:\n{str(response)}")
        
        logger.error("[OpenAI] Error details logged to: %s", log_filename)
        return {"error": str(e), "raw_response": str(response)}
