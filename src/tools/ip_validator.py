"""
IP Address validation tool for LangChain
"""
import ipaddress
import re
from typing import Dict, Any, Tuple
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

class IPValidatorInput(BaseModel):
    """Input schema for IP validator tool."""
    ip_address: str = Field(description="IP address to validate")

class IPValidatorTool(BaseTool):
    """Tool for validating IP addresses and determining analysis suitability."""
    
    name: str = "ip_validator"
    description: str = """
    Validates IP address format and determines if it's suitable for threat intelligence analysis.
    Use this tool first before analyzing any IP address.
    """
    args_schema = IPValidatorInput
    
    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Validate IP address and classify its type."""
        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
            
            # Determine classification
            if ip_obj.is_loopback:
                classification = 'loopback'
            elif ip_obj.is_private:
                classification = 'private'
            elif ip_obj.is_multicast:
                classification = 'multicast'
            elif ip_obj.is_link_local:
                classification = 'link_local'
            elif ip_obj.is_reserved:
                classification = 'reserved'
            else:
                classification = 'public'
            
            # Determine if suitable for analysis
            should_analyze = classification == 'public'
            reason = f"Public IP address suitable for analysis" if should_analyze else f"{classification.title()} IP address not suitable for external analysis"
            
            return {
                "ip_address": ip_address,
                "is_valid": True,
                "ip_type": "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6",
                "classification": classification,
                "should_analyze": should_analyze,
                "reason": reason,
                "status": "success"
            }
            
        except ValueError as e:
            return {
                "ip_address": ip_address,
                "is_valid": False,
                "error": str(e),
                "status": "error"
            }
    
    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Async version of the tool."""
        return self._run(ip_address)
