"""
State definition for LangGraph workflow
"""
from typing import Dict, Any, List, Optional, TypedDict
from langchain_core.messages import BaseMessage

class IPAnalysisState(TypedDict):
    """State schema for IP analysis workflow."""
    
    # Input
    ip_address: str
    user_query: str
    
    # Messages for conversation
    messages: List[BaseMessage]
    
    # Validation results
    ip_validation: Optional[Dict[str, Any]]
    
    # Tool results
    ipinfo_result: Optional[Dict[str, Any]]
    virustotal_result: Optional[Dict[str, Any]]
    shodan_result: Optional[Dict[str, Any]]
    abuseipdb_result: Optional[Dict[str, Any]]
    
    # Analysis
    threat_analysis: Optional[Dict[str, Any]]
    final_report: Optional[str]
    
    # Workflow control
    next_action: Optional[str]
    error_message: Optional[str]
    completed: bool
