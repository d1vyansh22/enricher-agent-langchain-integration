"""
Enhanced state definition with proper TypedDict implementation for LangGraph.
"""

from typing import Dict, Any, List, Optional
from typing_extensions import TypedDict, Annotated
from langchain_core.messages import BaseMessage

# Type aliases for clarity and type safety
StateUpdate = Dict[str, Any]
NodeResult = Dict[str, Any]


class IPAnalysisState(TypedDict, total=False):
    """
    Enhanced state schema with strict typing and partial update support.
    
    Using total=False allows nodes to return partial state updates
    while maintaining full type safety for the complete state.
    This is crucial for LangGraph compatibility.
    """
    
    # Core required fields (these should be in initial state)
    ip_address: str
    user_query: str
    messages: List[BaseMessage]
    completed: bool
    
    # Optional analysis results (updated by different nodes)
    ip_validation: Optional[Dict[str, Any]]
    ipinfo_result: Optional[Dict[str, Any]]
    virustotal_result: Optional[Dict[str, Any]]
    shodan_result: Optional[Dict[str, Any]]
    abuseipdb_result: Optional[Dict[str, Any]]
    threat_analysis: Optional[Dict[str, Any]]
    final_report: Optional[str]
    
    # Workflow control fields
    next_action: Optional[str]
    error_message: Optional[str]
    
    # Execution metadata
    execution_start_time: Optional[float]
    execution_duration: Optional[float]


def create_initial_state(ip_address: str, user_query: str) -> IPAnalysisState:
    """
    Create a properly typed initial state for the workflow.
    
    Args:
        ip_address: The IP address to analyze
        user_query: User's query about the IP
        
    Returns:
        Properly initialized state object
    """
    return IPAnalysisState(
        ip_address=ip_address,
        user_query=user_query,
        messages=[],
        completed=False,
        ip_validation=None,
        ipinfo_result=None,
        virustotal_result=None,
        shodan_result=None,
        abuseipdb_result=None,
        threat_analysis=None,
        final_report=None,
        next_action=None,
        error_message=None,
        execution_start_time=None,
        execution_duration=None
    )


def validate_state_update(update: StateUpdate) -> bool:
    """
    Validate that a state update contains only valid keys.
    
    Args:
        update: State update dictionary to validate
        
    Returns:
        True if valid, False otherwise
    """
    valid_keys = {
        "ip_address", "user_query", "messages", "completed",
        "ip_validation", "ipinfo_result", "virustotal_result", 
        "shodan_result", "abuseipdb_result", "threat_analysis",
        "final_report", "next_action", "error_message",
        "execution_start_time", "execution_duration"
    }
    
    return all(key in valid_keys for key in update.keys())


def create_error_state(error_message: str, ip_address: str = "") -> StateUpdate:
    """
    Create a standardized error state update.
    
    Args:
        error_message: Description of the error
        ip_address: IP address being processed (if available)
        
    Returns:
        Error state update dictionary
    """
    return {
        "error_message": error_message,
        "next_action": "complete",
        "completed": True
    }
