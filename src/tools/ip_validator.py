"""
Enhanced IP Address validation tool with comprehensive classification.
"""

import ipaddress
import re
from typing import Dict, Any, Union, List
from .base_tool import EnhancedIPAnalysisTool


class IPValidatorTool(EnhancedIPAnalysisTool):
    """
    Enhanced tool for validating IP addresses and determining analysis suitability.
    Provides comprehensive IPv4/IPv6 classification with security assessment.
    """
    
    name: str = "ip_validator"
    description: str = """
    Validates IP address format and determines if it's suitable for threat intelligence analysis.
    Provides detailed classification including RFC compliance and security recommendations.
    Use this tool first before analyzing any IP address.
    """
    
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """
        Comprehensive IP address validation and classification.
        
        Args:
            ip_address: IP address to validate and classify
            
        Returns:
            Detailed validation and classification results
        """
        try:
            # Parse the IP address
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Determine detailed classification
            classification = self._classify_ip_address(ip_obj)
            
            # Determine if suitable for external analysis
            should_analyze, reason = self._assess_analysis_suitability(ip_obj, classification)
            
            # Generate security assessment
            security_assessment = self._generate_security_assessment(ip_obj, classification)
            
            # Create comprehensive response
            return {
                "status": "success",
                "service": "ip_validator",
                "ip_address": ip_address,
                "is_valid": True,
                "ip_version": "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6",
                "classification": classification,
                "should_analyze": should_analyze,
                "reason": reason,
                "security_assessment": security_assessment,
                "rfc_references": self._get_rfc_references(classification),
                "recommendations": self._generate_recommendations(should_analyze, classification)
            }
            
        except ValueError as e:
            return {
                "status": "error", 
                "service": "ip_validator",
                "ip_address": ip_address,
                "is_valid": False,
                "error_message": str(e),
                "classification": "invalid",
                "should_analyze": False,
                "reason": f"Invalid IP address format: {str(e)}"
            }
    
    def _classify_ip_address(self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
        """Provide detailed IP address classification."""
        if ip_obj.is_loopback:
            return "loopback"
        elif ip_obj.is_private:
            return "private"
        elif ip_obj.is_multicast:
            return "multicast"
        elif ip_obj.is_link_local:
            return "link_local"
        elif ip_obj.is_reserved:
            return "reserved"
        elif hasattr(ip_obj, 'is_global') and ip_obj.is_global:
            return "public"
        elif isinstance(ip_obj, ipaddress.IPv4Address):
            # Additional IPv4 classifications
            if ip_obj.is_unspecified:
                return "unspecified"
            else:
                return "public"
        else:
            # IPv6 specific classifications
            if ip_obj.is_unspecified:
                return "unspecified"
            elif ip_obj.is_site_local:
                return "site_local"
            else:
                return "public"
    
    def _assess_analysis_suitability(self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], 
                                   classification: str) -> tuple[bool, str]:
        """Assess whether IP is suitable for threat intelligence analysis."""
        suitable_classifications = {"public", "global_unicast"}
        
        if classification in suitable_classifications:
            return True, "Public IP address suitable for threat intelligence analysis"
        elif classification == "private":
            return False, "Private IP address - not suitable for external threat intelligence"
        elif classification == "loopback":
            return False, "Loopback address - localhost, not suitable for analysis"
        elif classification == "multicast":
            return False, "Multicast address - not suitable for individual host analysis"
        elif classification == "reserved":
            return False, "Reserved IP address range - not suitable for analysis"
        else:
            return False, f"IP classification '{classification}' not suitable for analysis"
    
    def _generate_security_assessment(self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                                    classification: str) -> Dict[str, Any]:
        """Generate security-focused assessment of the IP address."""
        security_concerns: List[str] = []
        assessment: Dict[str, Any] = {
            "exposure_risk": "none",
            "analysis_priority": "low",
            "security_concerns": security_concerns
        }
        
        if classification in ["public", "global_unicast"]:
            assessment["exposure_risk"] = "high"
            assessment["analysis_priority"] = "high"
            assessment["security_concerns"].append("Internet-facing address")
            
        elif classification == "private":
            assessment["exposure_risk"] = "low"
            assessment["analysis_priority"] = "low"
            assessment["security_concerns"].append("Internal network address")
            
        elif classification == "loopback":
            assessment["exposure_risk"] = "none"
            assessment["analysis_priority"] = "none"
            
        return assessment
    
    def _get_rfc_references(self, classification: str) -> List[str]:
        """Get relevant RFC references for the IP classification."""
        rfc_mapping = {
            "private": ["RFC 1918", "RFC 4193"],
            "loopback": ["RFC 5735", "RFC 4291"],
            "multicast": ["RFC 3171", "RFC 4291"],
            "link_local": ["RFC 3927", "RFC 4291"],
            "reserved": ["RFC 5735", "RFC 4291"],
            "public": ["RFC 791", "RFC 2460"],
            "global_unicast": ["RFC 4291"]
        }
        return rfc_mapping.get(classification, [])
    
    def _generate_recommendations(self, should_analyze: bool, classification: str) -> List[str]:
        """Generate actionable recommendations based on classification."""
        if should_analyze:
            return [
                "Proceed with comprehensive threat intelligence analysis",
                "Query multiple threat intelligence sources",
                "Monitor for suspicious activity patterns",
                "Consider geolocation and network ownership analysis"
            ]
        else:
            return [
                f"Skip external threat intelligence for {classification} addresses",
                "Consider internal security monitoring if applicable",
                "Validate network configuration if unexpected classification"
            ]
