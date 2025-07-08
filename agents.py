# agents.py
import re
from typing import Dict, Any, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.tools import tool

from state import IPAnalysisState
import tools # Import the tools module
import ip_validator_tool # NEW: Import the new IP validator tool module

"""
This module defines the agents (nodes) for the LangGraph workflow.
Each agent performs a specific task, leveraging LLMs or external APIs.
"""

# Initialize the Gemini LLM
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.0)

# --- Define LangChain Tools from the functions in tools.py ---
@tool
def ipinfo_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP information from IPInfo."""
    return tools.get_ipinfo_data(ip_address)

@tool
def virustotal_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP analysis from VirusTotal."""
    return tools.get_virustotal_data(ip_address)

@tool
def shodan_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP information from Shodan."""
    return tools.get_shodan_data(ip_address)

@tool
def abuseipdb_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP abuse report from AbuseIPDB."""
    return tools.get_abuseipdb_data(ip_address)

# --- Agent Definitions ---

def context_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent responsible for extracting the IP address from the user's natural language query
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

    # Step 2: Validate the extracted IP using the new tool
    if extracted_ip == 'NO_IP_FOUND':
        print("No IP address extracted by LLM.")
        return {"ip_address": None, "error_message": "No valid IP address found in the query."}
    else:
        # Invoke the IP validation tool
        validation_result = ip_validator_tool.check_ip_for_analysis.invoke(extracted_ip)
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
    """
    print("---IPINFO AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        ipinfo_data = ipinfo_tool.invoke(ip_address)
        print(f"IPInfo Data: {ipinfo_data}")
        return {"ipinfo_data": ipinfo_data}
    return {"ipinfo_data": None}


def virustotal_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the VirusTotal tool and update the state with the results.
    """
    print("---VIRUSTOTAL AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        virustotal_data = virustotal_tool.invoke(ip_address)
        print(f"VirusTotal Data: {virustotal_data}")
        return {"virustotal_data": virustotal_data}
    return {"virustotal_data": None}


def shodan_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the Shodan tool and update the state with the results.
    """
    print("---SHODAN AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        shodan_data = shodan_tool.invoke(ip_address)
        print(f"Shodan Data: {shodan_data}")
        return {"shodan_data": shodan_data}
    return {"shodan_data": None}


def abuseipdb_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent to call the AbuseIPDB tool and update the state with the results.
    """
    print("---ABUSEIPDB AGENT: Fetching data---")
    ip_address = state.get("ip_address")
    if ip_address:
        abuseipdb_data = abuseipdb_tool.invoke(ip_address)
        print(f"AbuseIPDB Data: {abuseipdb_data}")
        return {"abuseipdb_data": abuseipdb_data}
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

