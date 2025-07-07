"""
LangChain IP Intelligence Agent

A comprehensive IP address intelligence and threat analysis system built with 
LangChain and LangGraph. This package integrates multiple threat intelligence 
sources (IPInfo, VirusTotal, Shodan, AbuseIPDB) to provide detailed analysis 
of IP addresses for security and threat detection.

The system uses LangGraph for sophisticated workflow orchestration and LangSmith 
for debugging and monitoring. It's designed to be part of a larger security 
copilot project for preventing malicious attacks.

Features:
- Multi-source threat intelligence gathering
- LangGraph-based workflow orchestration
- Gemini LLM integration for analysis
- Comprehensive threat scoring and risk assessment
- Production-ready error handling and validation

Author: IP Intelligence Team
Version: 2.0.0 (LangChain Migration)
"""

__version__ = "2.0.0"
__author__ = "IP Intelligence Team"
__description__ = "LangChain IP Intelligence and Threat Analysis System"

# Package-level imports for convenience
from .config.settings import settings
from .models.gemini_client import gemini_llm, create_gemini_llm
from .graph.workflow import ip_analysis_app
from .tools.ip_validator import IPValidatorTool

# Define public API
__all__ = [
    "settings",
    "gemini_llm", 
    "create_gemini_llm",
    "ip_analysis_app",
    "IPValidatorTool",
    "__version__",
    "__author__",
    "__description__"
]
