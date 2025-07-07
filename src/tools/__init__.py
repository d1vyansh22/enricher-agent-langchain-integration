"""
LangChain Tools Module

This module contains all the LangChain BaseTool implementations for IP intelligence gathering.
Each tool integrates with a specific threat intelligence API and follows the LangChain tool
pattern for consistent error handling, input validation, and response formatting.

Available Tools:
- IPValidatorTool: IP address validation and classification
- IPInfoTool: Geolocation and network information via IPInfo API
- VirusTotalTool: Malware and threat detection via VirusTotal API  
- ShodanTool: Network scanning and vulnerability detection via Shodan API
- AbuseIPDBTool: Community-driven abuse reporting via AbuseIPDB API

Tool Architecture:
All tools inherit from LangChain's BaseTool and implement:
- Pydantic input schemas for validation
- Async and sync execution methods
- Comprehensive error handling
- Structured response formatting
- Built-in retry logic with exponential backoff

Usage:
    from src.tools import IPValidatorTool, IPInfoTool
    
    # Create tool instances
    validator = IPValidatorTool()
    ipinfo = IPInfoTool()
    
    # Use tools
    validation_result = validator.run("8.8.8.8")
    info_result = ipinfo.run("8.8.8.8")
"""

from .ip_validator import IPValidatorTool
from .ipinfo_tool import IPInfoTool
from .virustotal_tool import VirusTotalTool
from .shodan_tool import ShodanTool
from .abuseipdb_tool import AbuseIPDBTool

# Export all tools
__all__ = [
    "IPValidatorTool",
    "IPInfoTool", 
    "VirusTotalTool",
    "ShodanTool",
    "AbuseIPDBTool"
]
