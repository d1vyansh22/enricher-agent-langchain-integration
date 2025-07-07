"""
LangGraph workflow definition for IP analysis
"""
from typing import Literal
from langgraph.graph import StateGraph, END
from .state import IPAnalysisState
from .nodes import (
    validate_ip_node,
    gather_intelligence_node,
    analyze_threats_node,
    generate_report_node
)

def should_continue(state: IPAnalysisState) -> Literal["gather_intelligence", "analyze_threats", "generate_report", "complete"]:
    """Determine next step in the workflow."""
    next_action = state.get("next_action")
    
    if next_action == "gather_intelligence":
        return "gather_intelligence"
    elif next_action == "analyze_threats":
        return "analyze_threats"
    elif next_action == "generate_report":
        return "generate_report"
    else:
        return "complete"

def create_ip_analysis_workflow():
    """Create the IP analysis workflow using LangGraph."""
    
    # Create the state graph
    workflow = StateGraph(IPAnalysisState)
    
    # Add nodes
    workflow.add_node("validate_ip", validate_ip_node)
    workflow.add_node("gather_intelligence", gather_intelligence_node)
    workflow.add_node("analyze_threats", analyze_threats_node)
    workflow.add_node("generate_report", generate_report_node)
    
    # Set entry point
    workflow.set_entry_point("validate_ip")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "validate_ip",
        should_continue,
        {
            "gather_intelligence": "gather_intelligence",
            "complete": END
        }
    )
    
    workflow.add_conditional_edges(
        "gather_intelligence",
        should_continue,
        {
            "analyze_threats": "analyze_threats",
            "complete": END
        }
    )
    
    workflow.add_conditional_edges(
        "analyze_threats",
        should_continue,
        {
            "generate_report": "generate_report",
            "complete": END
        }
    )
    
    workflow.add_conditional_edges(
        "generate_report",
        should_continue,
        {
            "complete": END
        }
    )
    
    return workflow.compile()

# Create the compiled workflow
ip_analysis_app = create_ip_analysis_workflow()
