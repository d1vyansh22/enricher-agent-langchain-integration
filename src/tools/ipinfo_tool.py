"""
Enhanced IPInfo API integration with comprehensive error handling.
"""

import requests
from typing import Dict, Any
from .base_tool import EnhancedIPAnalysisTool
from ..config.settings import settings


class IPInfoTool(EnhancedIPAnalysisTool):
    """Enhanced tool for gathering geolocation and network information using IPInfo API."""
    
    name: str = "ipinfo_lookup"
    description: str = """
    Retrieves comprehensive geolocation and network information for an IP address using IPInfo API.
    Provides location, ISP, organization, and privacy detection (VPN/proxy/Tor) with enhanced error handling.
    """
    
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """Fetch comprehensive IP information from IPInfo API."""
        if not settings.ipinfo_api_key:
            return {
                "status": "error",
                "service": "ipinfo", 
                "ip_address": ip_address,
                "error_message": "IPInfo API key not configured",
                "error_type": "configuration_error"
            }
        
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {
            'Authorization': f'Bearer {settings.ipinfo_api_key}',
            'User-Agent': 'langchain-ip-intelligence/2.0'
        }
        
        response = requests.get(url, headers=headers, timeout=settings.api_timeout)
        
        if response.status_code == 200:
            data = response.json()
            return self._process_successful_response(data, ip_address)
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded - retryable")
        elif response.status_code == 401:
            return {
                "status": "error",
                "service": "ipinfo",
                "ip_address": ip_address,
                "error_message": "Invalid API key or authentication failed",
                "error_type": "authentication_error"
            }
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
    
    def _process_successful_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Process successful API response with enhanced data extraction."""
        # Process privacy information with detailed analysis
        privacy_info = data.get('privacy', {})
        privacy_flags = {
            "vpn": privacy_info.get('vpn', False),
            "proxy": privacy_info.get('proxy', False), 
            "tor": privacy_info.get('tor', False),
            "relay": privacy_info.get('relay', False),
            "hosting": privacy_info.get('hosting', False)
        }
        
        # Enhanced location parsing
        coordinates = data.get('loc', '')
        lat, lon = None, None
        if coordinates and ',' in coordinates:
            try:
                lat_str, lon_str = coordinates.split(',')
                lat, lon = float(lat_str.strip()), float(lon_str.strip())
            except (ValueError, IndexError):
                pass
        
        return {
            "status": "success",
            "service": "ipinfo",
            "ip_address": ip_address,
            "location": {
                "city": data.get('city'),
                "region": data.get('region'),
                "country": data.get('country'),
                "country_name": data.get('country_name'),
                "coordinates": coordinates,
                "latitude": lat,
                "longitude": lon,
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
            "risk_indicators": self._assess_risk_indicators(privacy_flags, data),
            "data_source": "ipinfo"
        }
    
    def _assess_risk_indicators(self, privacy_flags: Dict[str, bool], data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk indicators from IPInfo data."""
        risk_score = 0
        indicators = []
        
        if privacy_flags.get("vpn"):
            risk_score += 30
            indicators.append("VPN usage detected")
            
        if privacy_flags.get("proxy"):
            risk_score += 25
            indicators.append("Proxy usage detected")
            
        if privacy_flags.get("tor"):
            risk_score += 40
            indicators.append("Tor exit node detected")
            
        if privacy_flags.get("hosting"):
            risk_score += 20
            indicators.append("Hosting/datacenter IP")
        
        return {
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "assessment": "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"
        }
