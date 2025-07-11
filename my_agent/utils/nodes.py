# my_agent/utils/nodes.py
import re
from typing import Dict, Any, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
# Removed: from langchain.tools import tool # Tools will be defined in agent.py

# UPDATED IMPORTS: Use relative imports based on the new structure
from my_agent.utils.state import IPAnalysisState
from my_agent.utils import tools # Import the tools module
from my_agent.utils import ip_validator # Import the IP validator module (no _tool suffix)

"""
This module defines the core node functions for the LangGraph workflow.
These functions operate on the graph state. Tool invocation is handled externally.
"""

# Initialize the Gemini LLM (still needed here for context_agent_node and report_generation_agent_node)
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.0)

# --- Agent/Node Definitions (no @tool decorators here) ---

def extract_and_validate_ip_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Node responsible for extracting the IP address from the user's natural language query
    and then validating if it's suitable for external analysis.
    """
    print("---CONTEXT AGENT: Extracting and Validating IP Address---")
    user_query = state["user_query"]

    # Step 1: Extract IP using LLM
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an expert at extracting IP addresses from natural language queries. "
                   "If a single IP address is clearly present, return only that IP address. "
                   "If multiple IPs are present, return the first one. "
                   "If no valid IP address is found or the query is ambiguous, return 'NO_IP_FOUND'. "
                   "Examples: 'Analyze IP 192.168.1.1' -> '192.168.1.1', "
                   "'Check this address: 8.8.8.8 for threats' -> '8.8.8.8', "
                   "'What about this server?' -> 'NO_IP_FOUND'"),
        ("user", "{query}")
    ])

    chain = prompt | llm | StrOutputParser()
    extracted_ip = chain.invoke({"query": user_query}).strip()

    # Step 2: Validate the extracted IP using the ip_validator module
    if extracted_ip == 'NO_IP_FOUND':
        print("No IP address extracted by LLM.")
        return {"ip_address": None, "error_message": "No valid IP address found in the query."}
    else:
        validation_result = ip_validator.check_ip_for_analysis_func(extracted_ip)
        should_analyze = validation_result["should_analyze"]
        reason = validation_result["reason"]

        if should_analyze:
            print(f"Extracted and Validated IP: {extracted_ip}. Reason: {reason}")
            return {"ip_address": extracted_ip}
        else:
            print(f"Extracted IP {extracted_ip} is not suitable for analysis. Reason: {reason}")
            return {"ip_address": None, "error_message": f"Extracted IP is not suitable for external analysis: {reason}"}


def start_api_calls_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    A dispatcher node that simply passes the state along.
    Used to fan out to multiple parallel API agents after a conditional check.
    """
    print("---DISPATCHER: Starting parallel API calls---")
    return {}


def ipinfo_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the IPInfo tool and update the state with the results.
    This node will invoke the tool via the ToolExecutor in agent.py.
    """
    print("---IPINFO AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        # In this setup, the actual tool invocation logic is handled by the ToolExecutor
        # in agent.py. This node just prepares the input for that tool.
        # The graph will implicitly pass the ip_address to the tool_executor.
        # For this node's return, we just indicate it's ready for the tool call.
        return {"tool_input": ip_address, "tool_name": "ipinfo_tool"}
    return {"ipinfo_data": None}


def virustotal_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the VirusTotal tool and update the state with the results.
    """
    print("---VIRUSTOTAL AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        return {"tool_input": ip_address, "tool_name": "virustotal_tool"}
    return {"virustotal_data": None}


def shodan_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the Shodan tool and update the state with the results.
    """
    print("---SHODAN AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        return {"tool_input": ip_address, "tool_name": "shodan_tool"}
    return {"shodan_data": None}


def abuseipdb_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the AbuseIPDB tool and update the state with the results.
    """
    print("---ABUSEIPDB AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        return {"tool_input": ip_address, "tool_name": "abuseipdb_tool"}
    return {"abuseipdb_data": None}


def report_generation_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent responsible for synthesizing all collected data into a comprehensive threat intelligence report.
    Analyzes risks and vulnerabilities associated with the IP.
    """
    print("---REPORT GENERATION AGENT: Creating Report---")
    ip_address = state.get("ip_address")
    if not ip_address:
        return {"analysis_report": "No IP address provided for analysis.", "error_message": "No IP address for report."}

    ipinfo_data = state.get("ipinfo_data", {})
    virustotal_data = state.get("virustotal_data", {})
    shodan_data = state.get("shodan_data", {})
    abuseipdb_data = state.get("abuseipdb_data", {})

    # Construct the prompt for the LLM based on available data
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", "You are a highly skilled threat intelligence analyst. "
                   "Your task is to analyze the provided IP address data from various sources "
                   "and generate a concise, professional threat intelligence report. "
                   "Highlight potential risks, vulnerabilities, and any malicious indicators. "
                   "If data is missing for a source, mention it. "
                   "Structure the report clearly with sections for each data source and a summary of findings."),
        ("user", "Analyze the following IP address: {ip_address}\n\n"
                 "--- IPInfo Data ---\n{ipinfo_data}\n\n"
                 "--- VirusTotal Data ---\n{virustotal_data}\n\n"
                 "--- Shodan Data ---\n{shodan_data}\n\n"
                 "--- AbuseIPDB Data ---\n{abuseipdb_data}\n\n"
                 "Please provide a comprehensive report on potential risks and vulnerabilities.")
    ])

    # Format data for the prompt (handle None values gracefully)
    formatted_ipinfo = ipinfo_data if ipinfo_data else "No IPInfo data available."
    formatted_virustotal = virustotal_data if virustotal_data else "No VirusTotal data available."
    formatted_shodan = shodan_data if shodan_data else "No Shodan data available."
    formatted_abuseipdb = abuseipdb_data if abuseipdb_data else "No AbuseIPDB data available."

    chain = prompt_template | llm | StrOutputParser()
    try:
        report = chain.invoke({
            "ip_address": ip_address,
            "ipinfo_data": formatted_ipinfo,
            "virustotal_data": formatted_virustotal,
            "shodan_data": formatted_shodan,
            "abuseipdb_data": formatted_abuseipdb
        })
        print("Report Generated Successfully.")
        return {"analysis_report": report}
    except Exception as e:
        print(f"Error generating report: {e}")
        return {"analysis_report": "Failed to generate report.", "error_message": f"Report generation error: {e}"}

