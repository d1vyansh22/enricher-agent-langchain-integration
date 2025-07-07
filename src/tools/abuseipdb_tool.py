"""
AbuseIPDB API integration tool for LangChain
"""
import requests
import time
from typing import Dict, Any
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from ..config.settings import settings

class AbuseIPDBInput(BaseModel):
    """Input schema for AbuseIPDB tool."""
    ip_address: str = Field(description="IP address to analyze with AbuseIPDB")

class AbuseIPDBTool(BaseTool):
    """Tool for checking IP addresses against AbuseIPDB's community-driven abuse database."""
    
    name: str = "abuseipdb_lookup"
    description: str = """
    Checks IP addresses against AbuseIPDB's community-driven database for abuse reports.
    Provides abuse confidence scores and community-reported threat intelligence.
    """
    args_schema = AbuseIPDBInput
    
    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB API."""
        if not settings.abuseipdb_api_key:
            return {
                "status": "error",
                "service": "abuseipdb",
                "ip_address": ip_address,
                "error_message": "AbuseIPDB API key not configured"
            }
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': settings.abuseipdb_api_key,
            'Accept': 'application/json',
            'User-Agent': 'langchain-ip-intelligence/1.0'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': getattr(settings, 'abuseipdb_max_age_days', 30)
        }
        
        for attempt in range(settings.max_retries):
            try:
                start_time = time.time()
                response = requests.get(url, headers=headers, params=params, timeout=settings.api_timeout)
                elapsed_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    ip_data = data.get("data", {})
                    
                    # Extract key information
                    abuse_confidence = ip_data.get("abuseConfidenceScore", 0)
                    total_reports = ip_data.get("totalReports", 0)
                    is_whitelisted = ip_data.get("isWhitelisted", False)
                    is_tor = ip_data.get("isTor", False)
                    
                    # Determine threat level based on confidence score
                    if abuse_confidence == 0:
                        threat_level = "clean"
                    elif abuse_confidence < 25:
                        threat_level = "low"
                    elif abuse_confidence < 50:
                        threat_level = "medium"
                    elif abuse_confidence < 75:
                        threat_level = "high"
                    else:
                        threat_level = "critical"
                    
                    # Determine if IP is considered malicious
                    is_malicious = abuse_confidence >= 25 and not is_whitelisted
                    
                    # Calculate enhanced risk score
                    risk_score = abuse_confidence
                    if is_tor:
                        risk_score = min(risk_score + 10, 100)
                    if total_reports > 10:
                        risk_score = min(risk_score + 5, 100)
                    
                    return {
                        "status": "success",
                        "service": "abuseipdb",
                        "ip_address": ip_address,
                        "reputation_analysis": {
                            "abuse_confidence_score": abuse_confidence,
                            "is_malicious": is_malicious,
                            "threat_level": threat_level,
                            "risk_score": risk_score,
                            "total_reports": total_reports,
                            "num_distinct_users": ip_data.get("numDistinctUsers", 0),
                            "is_whitelisted": is_whitelisted,
                            "is_tor": is_tor
                        },
                        "location_info": {
                            "country_code": ip_data.get("countryCode"),
                            "country_name": ip_data.get("countryName"),
                            "usage_type": ip_data.get("usageType"),
                            "isp": ip_data.get("isp"),
                            "domain": ip_data.get("domain"),
                            "hostnames": ip_data.get("hostnames", [])
                        },
                        "technical_info": {
                            "ip_version": ip_data.get("ipVersion"),
                            "is_public": ip_data.get("isPublic"),
                            "last_reported_at": ip_data.get("lastReportedAt")
                        },
                        "response_time": round(elapsed_time, 3),
                        "data_source": "abuseipdb"
                    }
                
                elif response.status_code == 429:
                    if attempt < settings.max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                
                elif response.status_code == 404:
                    return {
                        "status": "no_data",
                        "service": "abuseipdb",
                        "ip_address": ip_address,
                        "message": "No data found for this IP address in AbuseIPDB",
                        "reputation_analysis": {
                            "abuse_confidence_score": 0,
                            "is_malicious": False,
                            "threat_level": "unknown",
                            "total_reports": 0
                        }
                    }
                
                return {
                    "status": "error",
                    "service": "abuseipdb",
                    "ip_address": ip_address,
                    "error_message": f"API error: HTTP {response.status_code}",
                    "error_code": response.status_code
                }
                
            except requests.exceptions.RequestException as e:
                if attempt == settings.max_retries - 1:
                    return {
                        "status": "error",
                        "service": "abuseipdb",
                        "ip_address": ip_address,
                        "error_message": f"Request failed: {str(e)}",
                        "error_type": "request_error"
                    }
                time.sleep(2 ** attempt)
        
        return {
            "status": "error",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "error_message": "Max retries exceeded"
        }
    
    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Async version of the tool."""
        return self._run(ip_address)
