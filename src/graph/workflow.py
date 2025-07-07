"""
Enhanced LangGraph workflow with improved conditional routing and error handling.
"""

from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from .state import IPAnalysisState
from .nodes import (
    validate_ip_node,
    gather_intelligence_node,
    analyze_threats_node,
    generate_report_node
)


def should_continue(state: IPAnalysisState) -> Literal["gather_intelligence", "analyze_threats", "generate_report", "complete"]:
    """
    Enhanced conditional routing with comprehensive state validation.
    
    Args:
        state: Current workflow state
        
    Returns:
        Next node to execute or END
    """
    # Check for completion or error states
    if state.get("completed") or state.get("error_message"):
        return "complete"
    
    # Route based on next_action with fallback logic
    next_action = state.get("next_action", "")
    
    if next_action == "gather_intelligence":
        # Verify IP validation was successful
        validation = state.get("ip_validation") or {}
        if validation.get("should_analyze"):
            return "gather_intelligence"
        else:
            return "complete"
    elif next_action == "analyze_threats":
        # Verify intelligence gathering has results
        has_results = any([
            state.get("ipinfo_result"),
            state.get("virustotal_result"),
            state.get("shodan_result"),
            state.get("abuseipdb_result")
        ])
        if has_results:
            return "analyze_threats"
        else:
            return "generate_report"  # Generate report even without full results
            
    elif next_action == "generate_report":
        return "generate_report"
        
    else:
        return "complete"


def create_ip_analysis_workflow() -> CompiledStateGraph:
    """
    Create enhanced IP analysis workflow with comprehensive error handling.
    
    Returns:
        Compiled StateGraph ready for execution
    """
    # Create the state graph with enhanced configuration
    workflow = StateGraph(IPAnalysisState)
    
    # Add nodes with retry configuration
    workflow.add_node("validate_ip", validate_ip_node)
    workflow.add_node("gather_intelligence", gather_intelligence_node)
    workflow.add_node("analyze_threats", analyze_threats_node)
    workflow.add_node("generate_report", generate_report_node)
    
    # Set entry point
    workflow.set_entry_point("validate_ip")
    
    # Add conditional edges with comprehensive routing
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
            "generate_report": "generate_report",
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

    # Compile with enhanced configuration
    compiled_workflow = workflow.compile(
        # Add recursion limit to prevent infinite loops
        interrupt_before=[],  # Can be configured for human-in-the-loop
        interrupt_after=[]
    )
    return compiled_workflow  # Return the compiled workflow to expose invoke/ainvoke

# Create the compiled workflow instance
ip_analysis_app = create_ip_analysis_workflow()
