# my_agent/agent.py
from langgraph.graph import StateGraph, END
from typing import Literal

# UPDATED IMPORTS: Use relative imports based on the new structure
from my_agent.utils.state import IPAnalysisState
from my_agent.utils.nodes import ( # Import all node functions from nodes.py
    context_agent_node,
    start_api_calls_node,
    ipinfo_agent_node,
    virustotal_agent_node,
    shodan_agent_node,
    abuseipdb_agent_node,
    report_generation_agent_node
)

"""
This module defines the LangGraph workflow for the threat intelligence system.
It orchestrates the execution of different agents based on the graph state.
"""

def should_continue_analysis(state: IPAnalysisState) -> Literal["start_api_calls", "end_no_ip"]:
    """
    Conditional edge: Determines if the analysis should proceed with API calls
    or terminate if no IP address was found (e.g., due to invalid IP or LLM not finding one).
    """
    # If ip_address is None or there's an error message indicating no valid IP
    if state.get("ip_address") is None:
        print("---DECISION: No valid IP found, ending analysis.---")
        return "end_no_ip"
    else:
        print("---DECISION: IP found, proceeding to API calls.---")
        return "start_api_calls"


def build_graph():
    """
    Builds and compiles the LangGraph workflow.
    """
    workflow = StateGraph(IPAnalysisState)

    # Define the nodes
    workflow.add_node("context_agent", context_agent_node)
    workflow.add_node("start_api_calls", start_api_calls_node)
    workflow.add_node("ipinfo_agent", ipinfo_agent_node)
    workflow.add_node("virustotal_agent", virustotal_agent_node)
    workflow.add_node("shodan_agent", shodan_agent_node)
    workflow.add_node("abuseipdb_agent", abuseipdb_agent_node)
    workflow.add_node("report_generation_agent", report_generation_agent_node)

    # Set the entry point
    workflow.set_entry_point("context_agent")

    # Define the edges
    # After context_agent, decide whether to proceed to API calls or end
    workflow.add_conditional_edges(
        "context_agent",
        should_continue_analysis,
        {
            "start_api_calls": "start_api_calls",
            "end_no_ip": END
        }
    )

    # From the dispatcher node, fan out to all parallel API agents
    workflow.add_edge("start_api_calls", "ipinfo_agent")
    workflow.add_edge("start_api_calls", "virustotal_agent")
    workflow.add_edge("start_api_calls", "shodan_agent")
    workflow.add_edge("start_api_calls", "abuseipdb_agent")

    # After all API agents, proceed to report generation.
    # LangGraph automatically handles waiting for all incoming branches to complete
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

