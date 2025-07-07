"""
Batch IP analysis using LangGraph
"""
import asyncio
from typing import List, Dict, Any
from src.graph.workflow import ip_analysis_app

async def analyze_multiple_ips(ip_addresses: List[str]) -> Dict[str, Any]:
    """Analyze multiple IP addresses concurrently."""
    
    tasks = []
    for ip in ip_addresses:
        initial_state = {
            "ip_address": ip,
            "user_query": f"Analyze {ip} for security threats",
            "messages": [],
            "completed": False
        }
        tasks.append(ip_analysis_app.ainvoke(initial_state))
    
    # Execute all analyses concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    analysis_results = {}
    for i, result in enumerate(results):
        ip = ip_addresses[i]
        if isinstance(result, Exception):
            analysis_results[ip] = {"error": str(result)}
        else:
            analysis_results[ip] = {
                "threat_analysis": result.get("threat_analysis"),
                "final_report": result.get("final_report")
            }
    
    return analysis_results
