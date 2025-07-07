"""
IPInfo API integration tool for LangChain
"""
import requests
import time
from typing import Dict, Any, Optional
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from ..config.settings import settings

class IPInfoInput(BaseModel):
    """Input schema for IPInfo tool."""
    ip_address: str = Field(description="IP address to analyze with IPInfo")

class IPInfoTool(BaseTool):
    """Tool for gathering geolocation and network information using IPInfo API."""
    
    name: str = "ipinfo_lookup"
    description: str = """
    Retrieves comprehensive geolocation and network information for an IP address using IPInfo API.
    Provides location, ISP, organization, and privacy detection (VPN/proxy/Tor).
    """
    args_schema = IPInfoInput
    
    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Fetch IP information from IPInfo API."""
        if not settings.ipinfo_api_key:
            return {
                "status": "error",
                "service": "ipinfo",
                "ip_address": ip_address,
                "error_message": "IPInfo API key not configured"
            }
        
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {
            'Authorization': f'Bearer {settings.ipinfo_api_key}',
            'User-Agent': 'langchain-ip-intelligence/1.0'
        }
        
        for attempt in range(settings.max_retries):
            try:
                start_time = time.time()
                response = requests.get(url, headers=headers, timeout=settings.api_timeout)
                elapsed_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Process privacy information
                    privacy_info = data.get('privacy', {})
                    privacy_flags = {
                        "vpn": privacy_info.get('vpn', False),
                        "proxy": privacy_info.get('proxy', False),
                        "tor": privacy_info.get('tor', False),
                        "relay": privacy_info.get('relay', False),
                        "hosting": privacy_info.get('hosting', False)
                    }
                    
                    return {
                        "status": "success",
                        "service": "ipinfo",
                        "ip_address": ip_address,
                        "location": {
                            "city": data.get('city'),
                            "region": data.get('region'),
                            "country": data.get('country'),
                            "country_name": data.get('country_name'),
                            "coordinates": data.get('loc'),
                            "postal_code": data.get('postal'),
                            "timezone": data.get('timezone')
                        },
                        "network": {
                            "organization": data.get('org'),
                            "asn": data.get('asn'),
                            "hostname": data.get('hostname')
                        },
                        "privacy": privacy_flags,
                        "has_privacy_concerns": any(privacy_flags.values()),
                        "response_time": round(elapsed_time, 3),
                        "data_source": "ipinfo"
                    }
                
                elif response.status_code == 429:
                    if attempt < settings.max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                
                return {
                    "status": "error",
                    "service": "ipinfo",
                    "ip_address": ip_address,
                    "error_message": f"API error: HTTP {response.status_code}",
                    "error_code": response.status_code
                }
                
            except requests.exceptions.RequestException as e:
                if attempt == settings.max_retries - 1:
                    return {
                        "status": "error",
                        "service": "ipinfo",
                        "ip_address": ip_address,
                        "error_message": f"Request failed: {str(e)}",
                        "error_type": "request_error"
                    }
                time.sleep(2 ** attempt)
        
        return {
            "status": "error",
            "service": "ipinfo",
            "ip_address": ip_address,
            "error_message": "Max retries exceeded"
        }
    
    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Async version of the tool."""
        return self._run(ip_address)
