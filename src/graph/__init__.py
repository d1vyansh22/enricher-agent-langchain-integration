"""
LangGraph Workflow Orchestration Module

This module contains the LangGraph-based workflow system for IP intelligence analysis.
It implements a sophisticated state machine that orchestrates the analysis process
through multiple stages: validation, intelligence gathering, threat analysis, and reporting.

Key Components:
- State: TypedDict defining the workflow state schema
- Nodes: Individual workflow steps (validate, gather, analyze, report)
- Workflow: Complete LangGraph workflow definition and compilation
- StateGraph: Main workflow orchestration logic

Architecture:
The workflow follows a linear progression with conditional branching:
1. IP Validation → 2. Intelligence Gathering → 3. Threat Analysis → 4. Report Generation

Usage:
    from src.graph import ip_analysis_app, IPAnalysisState
    
    # Execute workflow
    initial_state = IPAnalysisState(...)
    result = await ip_analysis_app.ainvoke(initial_state)
"""

from .state import IPAnalysisState
from .workflow import ip_analysis_app, create_ip_analysis_workflow
from .nodes import (
    validate_ip_node,
    gather_intelligence_node, 
    analyze_threats_node,
    generate_report_node
)

# Export main workflow components
__all__ = [
    "IPAnalysisState",
    "ip_analysis_app", 
    "create_ip_analysis_workflow",
    "validate_ip_node",
    "gather_intelligence_node",
    "analyze_threats_node", 
    "generate_report_node"
]
