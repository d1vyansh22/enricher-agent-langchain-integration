"""
VirusTotal API integration tool for LangChain
"""
import requests
import time
from typing import Dict, Any
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from ..config.settings import settings

class VirusTotalInput(BaseModel):
    """Input schema for VirusTotal tool."""
    ip_address: str = Field(description="IP address to analyze with VirusTotal")

class VirusTotalTool(BaseTool):
    """Tool for checking IP addresses against VirusTotal's threat intelligence database."""
    
    name: str = "virustotal_lookup"
    description: str = """
    Checks IP addresses against VirusTotal's database for malicious activity reports.
    Provides vendor detection counts and reputation scoring from security engines.
    """
    args_schema = VirusTotalInput
    
    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation using VirusTotal API."""
        if not settings.virustotal_api_key:
            return {
                "status": "error",
                "service": "virustotal",
                "ip_address": ip_address,
                "error_message": "VirusTotal API key not configured"
            }
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": settings.virustotal_api_key,
            "User-Agent": "langchain-ip-intelligence/1.0"
        }
        
        for attempt in range(settings.max_retries):
            try:
                start_time = time.time()
                response = requests.get(url, headers=headers, timeout=settings.api_timeout)
                elapsed_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    
                    # Extract analysis statistics
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    reputation = attributes.get("reputation", 0)
                    total_votes = attributes.get("total_votes", {})
                    
                    # Calculate threat metrics
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    suspicious_count = last_analysis_stats.get("suspicious", 0)
                    clean_count = last_analysis_stats.get("harmless", 0)
                    total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0
                    
                    is_malicious = malicious_count > 0
                    threat_score = 0
                    if total_engines > 0:
                        threat_score = min(((malicious_count + suspicious_count * 0.5) / total_engines) * 100, 100)
                    
                    # Determine threat level
                    if threat_score == 0:
                        threat_level = "clean"
                    elif threat_score < 10:
                        threat_level = "low"
                    elif threat_score < 30:
                        threat_level = "medium"
                    elif threat_score < 70:
                        threat_level = "high"
                    else:
                        threat_level = "critical"
                    
                    # Extract detected engines if any
                    detected_engines = []
                    if malicious_count > 0 or suspicious_count > 0:
                        last_analysis_results = attributes.get("last_analysis_results", {})
                        for engine, details in last_analysis_results.items():
                            category = details.get("category", "")
                            if category in ["malicious", "suspicious"]:
                                detected_engines.append({
                                    "engine": engine,
                                    "category": category,
                                    "result": details.get("result", ""),
                                    "method": details.get("method", "")
                                })
                    
                    return {
                        "status": "success",
                        "service": "virustotal",
                        "ip_address": ip_address,
                        "threat_analysis": {
                            "is_malicious": is_malicious,
                            "threat_score": round(threat_score, 2),
                            "threat_level": threat_level,
                            "malicious_detections": malicious_count,
                            "suspicious_detections": suspicious_count,
                            "clean_detections": clean_count,
                            "total_engines": total_engines,
                            "reputation": reputation
                        },
                        "analysis_stats": last_analysis_stats,
                        "detected_engines": detected_engines,
                        "network_info": {
                            "asn": attributes.get("asn"),
                            "as_owner": attributes.get("as_owner"),
                            "country": attributes.get("country"),
                            "network": attributes.get("network")
                        },
                        "last_analysis_date": attributes.get("last_analysis_date"),
                        "response_time": round(elapsed_time, 3),
                        "data_source": "virustotal"
                    }
                
                elif response.status_code == 429:
                    if attempt < settings.max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                
                elif response.status_code == 404:
                    return {
                        "status": "no_data",
                        "service": "virustotal",
                        "ip_address": ip_address,
                        "message": "No analysis data found for this IP address",
                        "threat_analysis": {
                            "is_malicious": False,
                            "threat_score": 0,
                            "threat_level": "unknown"
                        }
                    }
                
                return {
                    "status": "error",
                    "service": "virustotal",
                    "ip_address": ip_address,
                    "error_message": f"API error: HTTP {response.status_code}",
                    "error_code": response.status_code
                }
                
            except requests.exceptions.RequestException as e:
                if attempt == settings.max_retries - 1:
                    return {
                        "status": "error",
                        "service": "virustotal",
                        "ip_address": ip_address,
                        "error_message": f"Request failed: {str(e)}",
                        "error_type": "request_error"
                    }
                time.sleep(2 ** attempt)
        
        return {
            "status": "error",
            "service": "virustotal", 
            "ip_address": ip_address,
            "error_message": "Max retries exceeded"
        }
    
    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Async version of the tool."""
        return self._run(ip_address)
