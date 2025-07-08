# graph.py
from langgraph.graph import StateGraph, END
from state import IPAnalysisState
from agents import (
    context_agent_node,
    ipinfo_agent_node,
    virustotal_agent_node,
    shodan_agent_node,
    abuseipdb_agent_node,
    report_generation_agent_node
)
from typing import Literal

"""
This module defines the LangGraph workflow for the threat intelligence system.
It orchestrates the execution of different agents based on the graph state.
"""

def should_continue_analysis(state: IPAnalysisState) -> Literal["api_calls", "end_no_ip"]:
    """
    Conditional edge: Determines if the analysis should proceed with API calls
    or terminate if no IP address was found.
    """
    if state.get("ip_address"):
        print("---DECISION: IP found, proceeding to API calls.---")
        return "api_calls"
    else:
        print("---DECISION: No IP found, ending analysis.---")
        return "end_no_ip"

def build_graph():
    """
    Builds and compiles the LangGraph workflow.
    """
    workflow = StateGraph(IPAnalysisState)

    # Define the nodes
    workflow.add_node("context_agent", context_agent_node)
    workflow.add_node("ipinfo_agent", ipinfo_agent_node)
    workflow.add_node("virustotal_agent", virustotal_agent_node)
    workflow.add_node("shodan_agent", shodan_agent_node)
    workflow.add_node("abuseipdb_agent", abuseipdb_agent_node)
    workflow.add_node("report_generation_agent", report_generation_agent_node)

    # Set the entry point
    workflow.set_entry_point("context_agent")

    # Define the edges
    # After context_agent, decide whether to proceed or end
    workflow.add_conditional_edges(  
        "context_agent",
        should_continue_analysis,
        {
            "api_calls": ["ipinfo_agent", "virustotal_agent", "shodan_agent", "abuseipdb_agent"], # type: ignore
            "end_no_ip": END 
        }
    )

    # After all API agents, proceed to report generation.
    # Note: LangGraph automatically handles waiting for all parallel branches to complete
    # before proceeding if they all point to the same next node.
    workflow.add_edge("ipinfo_agent", "report_generation_agent")
    workflow.add_edge("virustotal_agent", "report_generation_agent")
    workflow.add_edge("shodan_agent", "report_generation_agent")
    workflow.add_edge("abuseipdb_agent", "report_generation_agent")

    # After report generation, the workflow ends
    workflow.add_edge("report_generation_agent", END)

    # Compile the graph
    app = workflow.compile()
    return app

