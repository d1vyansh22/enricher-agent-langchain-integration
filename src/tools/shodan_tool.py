"""
Shodan API integration tool for LangChain
"""
import time
import logging
from typing import Dict, Any
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from ..config.settings import settings

logger = logging.getLogger(__name__)

class ShodanInput(BaseModel):
    """Input schema for Shodan tool."""
    ip_address: str = Field(description="IP address to analyze with Shodan")

class ShodanTool(BaseTool):
    """Tool for gathering network information and vulnerabilities using Shodan API."""
    
    name: str = "shodan_lookup"
    description: str = """
    Retrieves network information including open ports, running services, and known vulnerabilities 
    for an IP address using Shodan API.
    """
    args_schema = ShodanInput
    
    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Fetch network information from Shodan API."""
        if not settings.shodan_api_key:
            return {
                "status": "error",
                "service": "shodan",
                "ip_address": ip_address,
                "error_message": "Shodan API key not configured"
            }
        
        # Import shodan library
        try:
            import shodan
        except ImportError:
            return {
                "status": "error",
                "service": "shodan",
                "ip_address": ip_address,
                "error_message": "Shodan library not installed. Install with: pip install shodan"
            }
        
        for attempt in range(settings.max_retries):
            try:
                # Initialize Shodan API
                api = shodan.Shodan(settings.shodan_api_key)
                start_time = time.time()
                
                # Make API request
                host_info = api.host(ip_address)
                elapsed_time = time.time() - start_time
                
                # Extract and structure the data
                ports = host_info.get("ports", [])
                hostnames = host_info.get("hostnames", [])
                vulnerabilities = host_info.get("vulns", [])
                tags = host_info.get("tags", [])
                
                # Analyze risk factors
                suspicious_tags = ["malware", "botnet", "spam", "phishing", "tor", "proxy"]
                has_suspicious_tags = any(tag.lower() in suspicious_tags for tag in tags)
                has_vulnerabilities = len(vulnerabilities) > 0
                
                # Calculate risk score
                risk_score = 0
                
                # Add points for vulnerabilities
                if vulnerabilities:
                    risk_score += min(len(vulnerabilities) * 10, 40)
                
                # Add points for suspicious tags
                if has_suspicious_tags:
                    risk_score += 30
                
                # Add points for excessive open ports
                if len(ports) > 10:
                    risk_score += 20
                
                # Check for commonly abused ports
                high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
                open_high_risk_ports = [port for port in ports if port in high_risk_ports]
                if open_high_risk_ports:
                    risk_score += len(open_high_risk_ports) * 5
                
                risk_score = min(risk_score, 100)
                
                # Determine risk level
                if risk_score == 0:
                    risk_level = "minimal"
                elif risk_score < 20:
                    risk_level = "low"
                elif risk_score < 40:
                    risk_level = "medium"
                elif risk_score < 70:
                    risk_level = "high"
                else:
                    risk_level = "critical"
                
                # Extract service details
                services = []
                data = host_info.get("data", [])
                if data:
                    for service in data[:10]:  # Limit to first 10 services
                        service_info = {
                            "port": service.get("port"),
                            "protocol": service.get("transport", "tcp"),
                            "service": service.get("product", "unknown"),
                            "version": service.get("version", ""),
                            "banner": service.get("data", "")[:200] + "..." if len(service.get("data", "")) > 200 else service.get("data", ""),
                            "timestamp": service.get("timestamp")
                        }
                        services.append(service_info)
                
                return {
                    "status": "success",
                    "service": "shodan",
                    "ip_address": ip_address,
                    "network_analysis": {
                        "open_ports": sorted(ports),
                        "port_count": len(ports),
                        "high_risk_ports": open_high_risk_ports,
                        "services": services,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "is_suspicious": has_suspicious_tags or has_vulnerabilities or risk_score > 30
                    },
                    "vulnerability_analysis": {
                        "vulnerabilities": vulnerabilities,
                        "vulnerability_count": len(vulnerabilities)
                    },
                    "location": {
                        "country": host_info.get("country_name", "Unknown"),
                        "country_code": host_info.get("country_code", "Unknown"),
                        "city": host_info.get("city", "Unknown"),
                        "region": host_info.get("region_code", "Unknown")
                    },
                    "network_info": {
                        "organization": host_info.get("org", "Unknown"),
                        "isp": host_info.get("isp", "Unknown"),
                        "asn": host_info.get("asn", "Unknown"),
                        "hostnames": hostnames
                    },
                    "system_info": {
                        "os": host_info.get("os"),
                        "tags": tags
                    },
                    "last_update": host_info.get("last_update"),
                    "response_time": round(elapsed_time, 3),
                    "data_source": "shodan"
                }
                
            except Exception as e:
                error_msg = str(e).lower()
                if "no information available" in error_msg or "not found" in error_msg:
                    return {
                        "status": "no_data",
                        "service": "shodan",
                        "ip_address": ip_address,
                        "message": "No information available for this IP address in Shodan",
                        "network_analysis": {
                            "open_ports": [],
                            "port_count": 0,
                            "risk_score": 0,
                            "risk_level": "unknown",
                            "is_suspicious": False
                        }
                    }
                
                elif "api key" in error_msg or "unauthorized" in error_msg:
                    return {
                        "status": "error",
                        "service": "shodan",
                        "ip_address": ip_address,
                        "error_message": "Shodan API authentication failed. Check your API key."
                    }
                
                elif "rate limit" in error_msg or "quota" in error_msg:
                    if attempt < settings.max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                
                if attempt == settings.max_retries - 1:
                    return {
                        "status": "error",
                        "service": "shodan",
                        "ip_address": ip_address,
                        "error_message": f"Shodan API error: {str(e)}"
                    }
                
                time.sleep(2 ** attempt)
        
        return {
            "status": "error",
            "service": "shodan",
            "ip_address": ip_address,
            "error_message": "Max retries exceeded"
        }
    
    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Async version of the tool."""
        return self._run(ip_address)
