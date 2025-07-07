"""
LangGraph nodes for IP analysis workflow
"""
import logging
from typing import Dict, Any
from langchain_core.messages import HumanMessage, AIMessage
from ..tools.ip_validator import IPValidatorTool
from ..tools.ipinfo_tool import IPInfoTool
from ..tools.virustotal_tool import VirusTotalTool
from ..tools.shodan_tool import ShodanTool
from ..tools.abuseipdb_tool import AbuseIPDBTool
from ..models.gemini_client import gemini_llm
from .state import IPAnalysisState

logger = logging.getLogger(__name__)

# Initialize tools
ip_validator = IPValidatorTool()
ipinfo_tool = IPInfoTool()
virustotal_tool = VirusTotalTool()
shodan_tool = ShodanTool()
abuseipdb_tool = AbuseIPDBTool()

def validate_ip_node(state: IPAnalysisState) -> IPAnalysisState:
    """Validate IP address and determine if analysis should proceed."""
    ip_address = state["ip_address"]
    
    try:
        validation_result = ip_validator.run(ip_address)
        state["ip_validation"] = validation_result
        
        if validation_result["is_valid"] and validation_result["should_analyze"]:
            state["next_action"] = "gather_intelligence"
        else:
            state["next_action"] = "complete"
            state["error_message"] = validation_result.get("reason", "IP validation failed")
            
    except Exception as e:
        logger.error(f"IP validation error: {e}")
        state["error_message"] = f"IP validation failed: {str(e)}"
        state["next_action"] = "complete"
    
    return state

def gather_intelligence_node(state: IPAnalysisState) -> IPAnalysisState:
    """Gather intelligence from all available sources."""
    ip_address = state["ip_address"]
    
    # Collect data from all sources
    try:
        state["ipinfo_result"] = ipinfo_tool.run(ip_address)
    except Exception as e:
        logger.error(f"IPInfo lookup failed: {e}")
        state["ipinfo_result"] = {"status": "error", "error": str(e)}
    
    try:
        state["virustotal_result"] = virustotal_tool.run(ip_address)
    except Exception as e:
        logger.error(f"VirusTotal lookup failed: {e}")
        state["virustotal_result"] = {"status": "error", "error": str(e)}
    
    try:
        state["shodan_result"] = shodan_tool.run(ip_address)
    except Exception as e:
        logger.error(f"Shodan lookup failed: {e}")
        state["shodan_result"] = {"status": "error", "error": str(e)}
    
    try:
        state["abuseipdb_result"] = abuseipdb_tool.run(ip_address)
    except Exception as e:
        logger.error(f"AbuseIPDB lookup failed: {e}")
        state["abuseipdb_result"] = {"status": "error", "error": str(e)}
    
    state["next_action"] = "analyze_threats"
    return state

def analyze_threats_node(state: IPAnalysisState) -> IPAnalysisState:
    """Analyze collected intelligence to determine threat level."""
    threat_score = 0
    threat_indicators = []
    
    # Analyze VirusTotal results
    vt_result = state.get("virustotal_result") or {}
    if vt_result.get("status") == "success":
        threat_analysis = vt_result.get("threat_analysis") or {}
        if threat_analysis.get("is_malicious", False):
            threat_score += 40
            threat_indicators.append(f"VirusTotal: {threat_analysis.get('malicious_detections', 0)} vendors flagged as malicious")
    
    # Analyze AbuseIPDB results
    abuse_result = state.get("abuseipdb_result") or {}
    if abuse_result.get("status") == "success":
        reputation = abuse_result.get("reputation_analysis") or {}
        confidence_score = reputation.get("abuse_confidence_score", 0)
        if confidence_score >= 75:
            threat_score += 35
            threat_indicators.append(f"AbuseIPDB: High confidence abuse score ({confidence_score}%)")
    
    # Analyze Shodan results
    shodan_result = state.get("shodan_result") or {}
    if shodan_result.get("status") == "success":
        network_analysis = shodan_result.get("network_analysis") or {}
        if network_analysis.get("is_suspicious", False):
            threat_score += 25
            threat_indicators.append("Shodan: Suspicious network activity detected")
    
    # Determine risk level
    if threat_score >= 70:
        risk_level = "CRITICAL"
        recommendation = "BLOCK - High threat indicators detected"
    elif threat_score >= 40:
        risk_level = "HIGH"
        recommendation = "INVESTIGATE - Multiple threat indicators"
    elif threat_score >= 15:
        risk_level = "MEDIUM"
        recommendation = "MONITOR - Some security concerns"
    else:
        risk_level = "LOW"
        recommendation = "ALLOW - No significant threats detected"
    
    state["threat_analysis"] = {
        "threat_score": min(threat_score, 100),
        "risk_level": risk_level,
        "recommendation": recommendation,
        "threat_indicators": threat_indicators
    }
    
    state["next_action"] = "generate_report"
    return state

def generate_report_node(state: IPAnalysisState) -> IPAnalysisState:
    """Generate final analysis report using Gemini."""
    
    # Prepare context for Gemini
    context = {
        "ip_address": state["ip_address"],
        "validation": state.get("ip_validation", {}),
        "ipinfo": state.get("ipinfo_result", {}),
        "virustotal": state.get("virustotal_result", {}),
        "shodan": state.get("shodan_result", {}),
        "abuseipdb": state.get("abuseipdb_result", {}),
        "threat_analysis": state.get("threat_analysis", {})
    }
    
    prompt = f"""
    Based on the comprehensive analysis of IP address {state['ip_address']}, provide a detailed security assessment report.
    
    Analysis Results:
    {context}
    
    Generate a comprehensive report that includes:
    1. Executive Summary with risk level and recommendation
    2. Geolocation and Network Information
    3. Threat Intelligence Findings
    4. Detailed Risk Assessment
    5. Recommended Actions
    
    Format the response as a professional cybersecurity analysis report.
    """
    
    try:
        response = gemini_llm.invoke([HumanMessage(content=prompt)])
        state["final_report"] = response.content
        state["messages"].append(AIMessage(content=response.content))
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        state["error_message"] = f"Report generation failed: {str(e)}"
    
    state["next_action"] = "complete"
    state["completed"] = True
    return state
