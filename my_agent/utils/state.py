# state.py
from typing import List, TypedDict, Optional, Dict, Any

"""
Defines the state for the LangGraph workflow.
This state will be passed between nodes and updated by each agent.
"""

class IPAnalysisState(TypedDict):
    """
    Represents the state of the IP analysis workflow.

    Attributes:
        user_query (str): The original natural language query from the user.
        ip_address (Optional[str]): The extracted IP address from the user query.
        ipinfo_data (Optional[Dict[str, Any]]): Data retrieved from IPInfo API.
        virustotal_data (Optional[Dict[str, Any]]): Data retrieved from VirusTotal API.
        shodan_data (Optional[Dict[str, Any]]): Data retrieved from Shodan API.
        abuseipdb_data (Optional[Dict[str, Any]]): Data retrieved from AbuseIPDB API.
        analysis_report (Optional[str]): The final synthesized threat intelligence report.
        error_message (Optional[str]): Any error message encountered during the process.
    """
    user_query: str
    ip_address: Optional[str]
    ipinfo_data: Optional[Dict[str, Any]]
    virustotal_data: Optional[Dict[str, Any]]
    shodan_data: Optional[Dict[str, Any]]
    abuseipdb_data: Optional[Dict[str, Any]]
    analysis_report: Optional[str]
    error_message: Optional[str]

