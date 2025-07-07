"""
Simple IP analysis example using LangGraph workflow
"""
import asyncio
from src.graph.workflow import ip_analysis_app
from src.graph.state import IPAnalysisState

async def analyze_ip(ip_address: str, user_query: str = "Analyze this IP for threats"):
    """Analyze a single IP address."""
    
    initial_state: IPAnalysisState = {
        "ip_address": ip_address,
        "user_query": user_query,
        "messages": [],
        "ip_validation": None,
        "ipinfo_result": None,
        "virustotal_result": None,
        "shodan_result": None,
        "abuseipdb_result": None,
        "threat_analysis": None,
        "final_report": None,
        "next_action": None,
        "error_message": None,
        "completed": False
    }
    
    # Execute the workflow
    result = await ip_analysis_app.ainvoke(initial_state)
    
    # Return the final report
    return result.get("final_report", "Analysis failed")

if __name__ == "__main__":
    # Example usage
    ip_to_analyze = "8.8.8.8"
    report = asyncio.run(analyze_ip(ip_to_analyze))
    print(f"Analysis Report for {ip_to_analyze}:")
    print("=" * 50)
    print(report)
