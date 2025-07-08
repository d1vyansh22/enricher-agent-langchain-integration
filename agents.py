# agents.py
import re
from typing import Dict, Any, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.tools import tool
from state import IPAnalysisState
import tools # Import the tools module

"""
This module defines the agents (nodes) for the LangGraph workflow.
Each agent performs a specific task, leveraging LLMs or external APIs.
"""

# Initialize the Gemini LLM
llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0.0)

# --- Define LangChain Tools from the functions in tools.py ---
@tool
def ipinfo_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP information from IPInfo."""
    return tools.get_ipinfo_data(ip_address)

@tool
def virustotal_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP analysis from VirusTotal."""
    # No longer passing cache_service as it's removed from tools.py
    return tools.get_virustotal_data(ip_address)

@tool
def shodan_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP information from Shodan."""
    return tools.get_shodan_data(ip_address)

@tool
def abuseipdb_tool(ip_address: str) -> Optional[Dict[str, Any]]:
    """Tool to get IP abuse report from AbuseIPDB."""
    # No longer passing cache_service as it's removed from tools.py
    return tools.get_abuseipdb_data(ip_address)

# --- Agent Definitions ---

def context_agent_node(state: IPAnalysisState) -> Dict[str, Any]:
    """
    Agent responsible for extracting the IP address from the user's natural language query.
    Uses an LLM to identify and extract the IP.
    """
    print("---CONTEXT AGENT: Extracting IP Address---")
    user_query = state["user_query"]

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an expert at extracting IP addresses from natural language queries. "
                   "If an IP address is present, return only the IP address. "
                   "If no valid IP address is found, return 'NO_IP_FOUND'. "
                   "Examples: 'Analyze IP 192.168.1.1' -> '192.168.1.1', "
                   "'Check this address: 8.8.8.8 for threats' -> '8.8.8.8', "
                   "'What about this server?' -> 'NO_IP_FOUND'"),
        ("user", "{query}")
    ])

    chain = prompt | llm | StrOutputParser()
    extracted_ip = chain.invoke({"query": user_query}).strip()

    # Basic regex validation for IP address
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(extracted_ip):
        print(f"Extracted IP: {extracted_ip}")
        return {"ip_address": extracted_ip}
    else:
        print("No valid IP address extracted.")
        return {"ip_address": None, "error_message": "No valid IP address found in the query."}


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
    return {"ipinfo_data": None} # Return None if no IP address


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

