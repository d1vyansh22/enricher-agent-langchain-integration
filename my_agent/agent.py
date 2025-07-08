# my_agent/agent.py
from langgraph.graph import StateGraph, END
from typing import Literal, Dict, Any
from langchain.tools import Tool # Import Tool class
# Removed: from langchain.agents import AgentExecutor, create_tool_calling_agent, RunnableLambda
# These are not strictly necessary for simple tool execution within LangGraph nodes

# UPDATED IMPORTS: Use relative imports based on the new structure
from my_agent.utils.state import IPAnalysisState
from my_agent.utils import tools as api_tools # Renamed to avoid conflict with langchain.tools.Tool
from my_agent.utils import ip_validator # Import the IP validator module
from my_agent.utils.nodes import (
    extract_and_validate_ip_node, # Renamed from context_agent_node
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
This file also defines the LangChain Tools and the ToolExecutor.
"""

# --- Define LangChain Tools ---
# These tools wrap the functions from my_agent.utils.tools and ip_validator
ip_info_tool = Tool(
    name="ipinfo_tool",
    func=api_tools.get_ipinfo_data,
    description="Useful for getting general IP information like geolocation, ISP, and organization."
)

virustotal_tool = Tool(
    name="virustotal_tool",
    func=api_tools.get_virustotal_data,
    description="Useful for checking an IP address against VirusTotal's database for malicious activity and reputation."
)

shodan_tool = Tool(
    name="shodan_tool",
    func=api_tools.get_shodan_data,
    description="Useful for gathering information about open ports, services, and vulnerabilities for an IP address."
)

abuseipdb_tool = Tool(
    name="abuseipdb_tool",
    func=api_tools.get_abuseipdb_data,
    description="Useful for checking an IP address for reported abuse activity and abuse confidence score."
)

# The IP validator tool is invoked directly by extract_and_validate_ip_node,
# so it doesn't need to be part of the `all_tools` list for the ToolExecutor.
# However, if you wanted the LLM to *decide* to call it, you would include it.
# For this setup, it's a direct function call within the node.
# ip_validator_tool = Tool(
#     name="ip_validator_tool",
#     func=ip_validator.check_ip_for_analysis_func,
#     description="Useful for validating an IP address format and determining if it is a public IP suitable for external analysis (e.g., not private, loopback, or reserved)."
# )

# Tools that will be executed by the tool_executor_node
# Note: ip_validator_tool is NOT included here as it's called directly by extract_and_validate_ip_node
executable_api_tools = [ip_info_tool, virustotal_tool, shodan_tool, abuseipdb_tool]

# --- Tool Executor Node ---
# This node executes the specified tool.
# It expects 'tool_name' and 'tool_input' in the state.
def tool_executor_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    A node that executes the specified tool based on 'tool_name' and 'tool_input' in the state.
    It updates the state with the result of the tool execution.
    """
    tool_name = state.get("tool_name")
    tool_input = state.get("tool_input")
    ip_address = state.get("ip_address") # Ensure IP is available for logging

    if not tool_name or tool_input is None:
        print("Error: tool_name or tool_input missing for tool_executor_node.")
        return {"error_message": "Tool execution failed: missing tool_name or tool_input."}

    print(f"---TOOL EXECUTOR: Executing {tool_name} for {ip_address} with input {tool_input}---")
    
    # Find the tool by name and execute it
    tool_to_execute = next((t for t in executable_api_tools if t.name == tool_name), None)
    if tool_to_execute:
        try:
            # CHANGED: Use tool_to_execute.run() instead of tool_to_execute.func()
            result = tool_to_execute.run(tool_input)
            # Update the state based on which tool was called
            if tool_name == "ipinfo_tool":
                return {"ipinfo_data": result}
            elif tool_name == "virustotal_tool":
                return {"virustotal_data": result}
            elif tool_name == "shodan_tool":
                return {"shodan_data": result}
            elif tool_name == "abuseipdb_tool":
                return {"abuseipdb_data": result}
            else:
                # This case should ideally not be hit if all tools are explicitly handled
                print(f"Warning: Unhandled tool name '{tool_name}' in tool_executor_node.")
                return {"tool_output": result} # Generic fallback
        except Exception as e:
            print(f"Error executing tool {tool_name}: {e}")
            return {"error_message": f"Tool {tool_name} execution failed: {str(e)}"}
    else:
        print(f"Error: Tool '{tool_name}' not found in executable_api_tools.")
        return {"error_message": f"Tool '{tool_name}' not found for execution."}


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
    # extract_and_validate_ip_node directly calls ip_validator.check_ip_for_analysis_func
    workflow.add_node("extract_and_validate_ip", extract_and_validate_ip_node)
    workflow.add_node("start_api_calls", start_api_calls_node)

    # These nodes prepare the input for the tool_executor_node
    workflow.add_node("ipinfo_agent", ipinfo_agent_node)
    workflow.add_node("virustotal_agent", virustotal_agent_node)
    workflow.add_node("shodan_agent", shodan_agent_node)
    workflow.add_node("abuseipdb_agent", abuseipdb_agent_node)

    # This node executes the actual tool call
    workflow.add_node("tool_executor", tool_executor_node)

    workflow.add_node("report_generation_agent", report_generation_agent_node)

    # Set the entry point
    workflow.set_entry_point("extract_and_validate_ip")

    # Define the edges
    workflow.add_conditional_edges(
        "extract_and_validate_ip",
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

    # Each API agent prepares the tool call, then routes to the tool_executor.
    # IMPORTANT: Since multiple agents route to 'tool_executor', LangGraph will
    # execute 'tool_executor' multiple times, once for each incoming edge.
    # Each execution will update the state with its specific tool's result.
    workflow.add_edge("ipinfo_agent", "tool_executor")
    workflow.add_edge("virustotal_agent", "tool_executor")
    workflow.add_edge("shodan_agent", "tool_executor")
    workflow.add_edge("abuseipdb_agent", "tool_executor")

    # After the tool_executor, all paths need to converge to the report generation.
    # Since tool_executor itself is a node that updates state and then completes,
    # we need to route its output to the report generation agent.
    # This implies that the report_generation_agent will run after *all* tool_executor
    # instances (triggered by the parallel API agents) have completed and updated the state.
    workflow.add_edge("tool_executor", "report_generation_agent")


    # After report generation, the workflow ends
    workflow.add_edge("report_generation_agent", END)

    # Compile the graph
    app = workflow.compile()
    return app

