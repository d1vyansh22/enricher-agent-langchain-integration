"""
Enhanced Shodan API integration with comprehensive network analysis.
"""

import time
import logging
from typing import Dict, Any, List
from .base_tool import EnhancedIPAnalysisTool
from ..config.settings import settings

logger = logging.getLogger(__name__)


class ShodanTool(EnhancedIPAnalysisTool):
    """Enhanced tool for gathering network information using Shodan API."""
    
    name: str = "shodan_lookup"
    description: str = """
    Retrieves comprehensive network information including open ports, running services,
    and known vulnerabilities for an IP address using Shodan API with enhanced analysis.
    """
    
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """Fetch comprehensive network information from Shodan API."""
        if not settings.shodan_api_key:
            return {
                "status": "error",
                "service": "shodan",
                "ip_address": ip_address,
                "error_message": "Shodan API key not configured",
                "error_type": "configuration_error"
            }
        
        # Import shodan library with error handling
        try:
            import shodan
        except ImportError:
            return {
                "status": "error", 
                "service": "shodan",
                "ip_address": ip_address,
                "error_message": "Shodan library not installed. Install with: pip install shodan",
                "error_type": "dependency_error"
            }
        
        # Initialize Shodan API
        api = shodan.Shodan(settings.shodan_api_key)
        
        try:
            # Make API request
            host_info = api.host(ip_address)
            return self._process_successful_response(host_info, ip_address)
            
        except shodan.APIError as e:
            return self._handle_shodan_api_error(e, ip_address)
        except Exception as e:
            error_msg = str(e).lower()
            if "rate limit" in error_msg or "quota" in error_msg:
                raise Exception("Rate limit exceeded - retryable")
            raise
    
    def _process_successful_response(self, host_info: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Process successful Shodan API response with enhanced analysis."""
        # Extract basic information
        ports = host_info.get("ports", [])
        hostnames = host_info.get("hostnames", [])
        vulnerabilities = host_info.get("vulns", [])
        tags = host_info.get("tags", [])
        
        # Perform comprehensive network analysis
        network_analysis = self._analyze_network_data(ports, tags, vulnerabilities)
        
        # Extract detailed service information
        services = self._extract_service_details(host_info.get("data", []))
        
        # Analyze vulnerabilities
        vulnerability_analysis = self._analyze_vulnerabilities(vulnerabilities)
        
        return {
            "status": "success",
            "service": "shodan",
            "ip_address": ip_address,
            "network_analysis": network_analysis,
            "services": services,
            "vulnerability_analysis": vulnerability_analysis,
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
            "data_source": "shodan"
        }
    
    def _analyze_network_data(self, ports: List[int], tags: List[str], vulnerabilities: List[str]) -> Dict[str, Any]:
        """Perform comprehensive network analysis."""
        # Define suspicious and high-risk indicators
        suspicious_tags = ["malware", "botnet", "spam", "phishing", "tor", "proxy"]
        high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900, 5985, 5986]
        
        # Calculate risk factors
        has_suspicious_tags = any(tag.lower() in suspicious_tags for tag in tags)
        has_vulnerabilities = len(vulnerabilities) > 0
        open_high_risk_ports = [port for port in ports if port in high_risk_ports]
        
        # Calculate comprehensive risk score
        risk_score = 0
        
        # Vulnerability scoring
        if vulnerabilities:
            risk_score += min(len(vulnerabilities) * 15, 50)
        
        # Suspicious tags scoring
        if has_suspicious_tags:
            risk_score += 30
        
        # Port exposure scoring
        if len(ports) > 20:
            risk_score += 25
        elif len(ports) > 10:
            risk_score += 15
        
        # High-risk ports scoring
        if open_high_risk_ports:
            risk_score += len(open_high_risk_ports) * 8
        
        # Common service risks
        web_ports = [80, 443, 8080, 8443]
        db_ports = [1433, 3306, 5432, 27017]
        remote_access_ports = [22, 23, 3389, 5900]
        
        exposed_services = {
            "web": any(port in web_ports for port in ports),
            "database": any(port in db_ports for port in ports),
            "remote_access": any(port in remote_access_ports for port in ports)
        }
        
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "open_ports": sorted(ports),
            "port_count": len(ports),
            "high_risk_ports": open_high_risk_ports,
            "exposed_services": exposed_services,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_suspicious": has_suspicious_tags or has_vulnerabilities or risk_score > 40,
            "suspicious_indicators": [tag for tag in tags if tag.lower() in suspicious_tags]
        }
    
    def _extract_service_details(self, service_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract detailed service information with security analysis."""
        services = []
        
        for service in service_data[:15]:  # Limit to first 15 services
            banner = service.get("data", "")
            
            service_info = {
                "port": service.get("port"),
                "protocol": service.get("transport", "tcp"),
                "service_name": service.get("product", "unknown"),
                "version": service.get("version", ""),
                "banner": banner[:300] + "..." if len(banner) > 300 else banner,
                "timestamp": service.get("timestamp"),
                "ssl_info": service.get("ssl", {}),
                "location": service.get("location", {}),
                "security_analysis": self._analyze_service_security(service)
            }
            
            services.append(service_info)
        
        return services
    
    def _analyze_service_security(self, service: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual service for security issues."""
        security_issues = []
        risk_level = "low"
        
        # Check for outdated software
        version = service.get("version", "").lower()
        if any(old_version in version for old_version in ["2018", "2019", "2020"]):
            security_issues.append("Potentially outdated software version")
            risk_level = "medium"
        
        # Check for insecure protocols
        product = service.get("product", "").lower()
        if any(insecure in product for insecure in ["telnet", "ftp", "http"]):
            security_issues.append("Insecure protocol detected")
            risk_level = "high"
        
        # Check SSL/TLS issues
        ssl_info = service.get("ssl", {})
        if ssl_info:
            cert = ssl_info.get("cert", {})
            if cert.get("expired"):
                security_issues.append("Expired SSL certificate")
                risk_level = "high"
        
        return {
            "risk_level": risk_level,
            "security_issues": security_issues,
            "requires_attention": len(security_issues) > 0
        }
    
    def _analyze_vulnerabilities(self, vulnerabilities: List[str]) -> Dict[str, Any]:
        """Analyze vulnerability data with severity assessment."""
        if not vulnerabilities:
            return {
                "vulnerability_count": 0,
                "severity_breakdown": {},
                "critical_vulns": [],
                "recommendations": ["No known vulnerabilities detected"]
            }
        
        # Categorize vulnerabilities by severity (simplified analysis)
        critical_keywords = ["critical", "rce", "remote code execution", "privilege escalation"]
        high_keywords = ["high", "sql injection", "xss", "authentication bypass"]
        
        critical_vulns = []
        high_vulns = []
        other_vulns = []
        
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            if any(keyword in vuln_lower for keyword in critical_keywords):
                critical_vulns.append(vuln)
            elif any(keyword in vuln_lower for keyword in high_keywords):
                high_vulns.append(vuln)
            else:
                other_vulns.append(vuln)
        
        recommendations = []
        if critical_vulns:
            recommendations.append("Immediate patching required for critical vulnerabilities")
        if high_vulns:
            recommendations.append("High-priority patching recommended")
        if other_vulns:
            recommendations.append("Review and assess remaining vulnerabilities")
        
        return {
            "vulnerability_count": len(vulnerabilities),
            "severity_breakdown": {
                "critical": len(critical_vulns),
                "high": len(high_vulns),
                "other": len(other_vulns)
            },
            "critical_vulns": critical_vulns[:5],  # Top 5 critical
            "high_vulns": high_vulns[:5],  # Top 5 high
            "recommendations": recommendations
        }
    
    def _handle_shodan_api_error(self, error: Exception, ip_address: str) -> Dict[str, Any]:
        """Handle specific Shodan API errors."""
        error_msg = str(error).lower()
        
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
                "error_message": "Shodan API authentication failed. Check your API key.",
                "error_type": "authentication_error"
            }
        else:
            # For other errors, let the retry mechanism handle them
            raise Exception(f"Shodan API error: {str(error)}")
