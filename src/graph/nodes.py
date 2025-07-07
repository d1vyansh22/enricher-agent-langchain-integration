"""
Enhanced LangGraph nodes with proper type safety and comprehensive error handling.
"""

import logging
import time
from typing import Dict, Any
from langchain_core.messages import HumanMessage, AIMessage

from ..tools.ip_validator import IPValidatorTool
from ..tools.ipinfo_tool import IPInfoTool
from ..tools.virustotal_tool import VirusTotalTool
from ..tools.shodan_tool import ShodanTool
from ..tools.abuseipdb_tool import AbuseIPDBTool
from ..models.gemini_client import gemini_llm
from .state import IPAnalysisState, StateUpdate

logger = logging.getLogger(__name__)

# Initialize tools with enhanced configuration
ip_validator = IPValidatorTool()
ipinfo_tool = IPInfoTool()
virustotal_tool = VirusTotalTool()
shodan_tool = ShodanTool()
abuseipdb_tool = AbuseIPDBTool()


def validate_ip_node(state: IPAnalysisState) -> StateUpdate:
    """
    Validate IP address with comprehensive error handling and type safety.
    
    Args:
        state: Current workflow state
        
    Returns:
        State update dictionary with validation results
    """
    # Input validation
    if not state.get("ip_address"):
        return {
            "error_message": "IP address is required but not found in state",
            "next_action": "complete",
            "completed": True
        }

    ip_address = state.get("ip_address")
    if not ip_address:
        return {
            "error_message": "IP address is missing from state after initial check",
            "next_action": "complete",
            "completed": True
        }

    try:
        # Record execution start
        execution_start = time.time()
        
        # Perform IP validation
        validation_result = ip_validator.run(ip_address)
        
        # Type validation for tool results
        if not isinstance(validation_result, dict):
            raise ValueError("IP validator returned invalid format")
        
        # Determine next action based on validation
        if (validation_result.get("status") == "success" and 
            validation_result.get("is_valid") and 
            validation_result.get("should_analyze")):
            next_action = "gather_intelligence"
            error_message = None
        else:
            next_action = "complete"
            error_message = validation_result.get("reason", "IP validation failed")
        
        # Construct type-safe state update
        update: StateUpdate = {
            "ip_validation": validation_result,
            "next_action": next_action,
            "error_message": error_message,
            "execution_start_time": execution_start
        }
        if next_action == "complete":
            update["completed"] = True
        return dict(update)
        
    except Exception as e:
        logger.error(f"IP validation error for {ip_address}: {e}")
        return {
            "error_message": f"IP validation failed: {str(e)}",
            "next_action": "complete", 
            "completed": True
        }


def gather_intelligence_node(state: IPAnalysisState) -> StateUpdate:
    """
    Gather intelligence from all available sources with parallel execution.
    
    Args:
        state: Current workflow state
        
    Returns:
        State update dictionary with intelligence results
    """
    ip_address = state.get("ip_address", "")
    
    if not ip_address:
        return {
            "error_message": "IP address missing for intelligence gathering",
            "next_action": "complete",
            "completed": True
        }
    
    # Initialize results dictionary
    results: StateUpdate = {"next_action": "analyze_threats"}
    
    # Gather data from all sources with individual error handling
    intelligence_sources = [
        ("ipinfo_result", ipinfo_tool),
        ("virustotal_result", virustotal_tool),
        ("shodan_result", shodan_tool),
        ("abuseipdb_result", abuseipdb_tool)
    ]
    
    for result_key, tool in intelligence_sources:
        try:
            tool_result = tool.run(ip_address)
            results[result_key] = tool_result
            logger.info(f"Successfully gathered {result_key} for {ip_address}")
            
        except Exception as e:
            logger.error(f"{result_key} lookup failed for {ip_address}: {e}")
            results[result_key] = {
                "status": "error",
                "service": tool.name,
                "ip_address": ip_address,
                "error_message": str(e),
                "error_type": "tool_execution_error"
            }
    
    return dict(results)


def analyze_threats_node(state: IPAnalysisState) -> StateUpdate:
    """
    Analyze collected intelligence with enhanced threat scoring.
    
    Args:
        state: Current workflow state
        
    Returns:
        State update dictionary with threat analysis
    """
    try:
        # Initialize threat scoring
        threat_score = 0
        threat_indicators = []
        risk_factors = []

        # Analyze VirusTotal results
        vt_result = state.get("virustotal_result") or {}
        vt_score, vt_indicators = _analyze_virustotal_data(vt_result)
        threat_score += vt_score
        threat_indicators.extend(vt_indicators)

        # Analyze AbuseIPDB results  
        abuseipdb_result = state.get("abuseipdb_result") or {}
        abuse_score, abuse_indicators = _analyze_abuseipdb_data(abuseipdb_result)
        threat_score += abuse_score
        threat_indicators.extend(abuse_indicators)
        
        # Analyze Shodan results
        shodan_result = state.get("shodan_result") or {}
        shodan_score, shodan_indicators = _analyze_shodan_data(shodan_result)
        threat_score += shodan_score
        threat_indicators.extend(shodan_indicators)

        # Analyze IPInfo results for additional risk factors
        ipinfo_result = state.get("ipinfo_result") or {}
        ipinfo_score, ipinfo_indicators = _analyze_ipinfo_data(ipinfo_result)
        threat_score += ipinfo_score
        threat_indicators.extend(ipinfo_indicators)

        # Determine final risk assessment
        risk_assessment = _calculate_risk_assessment(threat_score, threat_indicators)
        
        threat_analysis = {
            "threat_score": min(threat_score, 100),
            "risk_level": risk_assessment["risk_level"],
            "recommendation": risk_assessment["recommendation"],
            "threat_indicators": threat_indicators,
            "risk_factors": risk_factors,
            "confidence_level": risk_assessment["confidence_level"],
            "analysis_summary": risk_assessment["summary"]
        }
        
        return dict({
            "threat_analysis": threat_analysis,
            "next_action": "generate_report"
        })
        
    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        return {
            "error_message": f"Threat analysis failed: {str(e)}",
            "next_action": "generate_report"  # Continue to report even with analysis errors
        }


def generate_report_node(state: IPAnalysisState) -> StateUpdate:
    """
    Generate comprehensive analysis report using Gemini LLM.
    
    Args:
        state: Current workflow state
        
    Returns:
        Final state update with generated report
    """
    try:
        # Calculate execution duration
        execution_duration = None
        execution_start_time = state.get("execution_start_time")
        if execution_start_time is not None:
            # Only compute if execution_start_time is a float
            try:
                execution_duration = time.time() - float(execution_start_time)
            except (TypeError, ValueError):
                execution_duration = None

        # Prepare comprehensive context for Gemini
        context = _prepare_analysis_context(state)
        # Generate detailed prompt
        prompt = _create_comprehensive_prompt(state, context)
        
        # Generate report using Gemini
        response = None
        try:
            response = gemini_llm.invoke([HumanMessage(content=prompt)])
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
        if response is not None and hasattr(response, 'content'):
            final_report = response.content
            # Create completion message
            completion_message = AIMessage(
                content=f"Analysis complete for {state.get('ip_address', 'unknown IP')}. "
                       f"Report generated successfully."
            )
            return dict({
                "final_report": final_report,
                "messages": [completion_message],
                "next_action": "complete",
                "completed": True,
                "execution_duration": execution_duration
            })
        else:
            # Fallback if LLM fails or returns None
            return dict({
                "error_message": "Report generation failed: LLM returned no content.",
                "final_report": _generate_fallback_report(state),
                "next_action": "complete",
                "completed": True
            })
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return dict({
            "error_message": f"Report generation failed: {str(e)}",
            "final_report": _generate_fallback_report(state),
            "next_action": "complete",
            "completed": True
        })


# Helper functions for threat analysis
def _analyze_virustotal_data(vt_result: Dict[str, Any]) -> tuple[int, list[str]]:
    """Analyze VirusTotal data and return threat score and indicators."""
    if vt_result.get("status") != "success":
        return 0, []
    
    threat_analysis = vt_result.get("threat_analysis", {})
    score = 0
    indicators = []
    
    if threat_analysis.get("is_malicious", False):
        malicious_count = threat_analysis.get("malicious_detections", 0)
        score += min(malicious_count * 8, 40)  # Max 40 points from VT
        indicators.append(f"VirusTotal: {malicious_count} security vendors flagged as malicious")
    
    return score, indicators


def _analyze_abuseipdb_data(abuse_result: Dict[str, Any]) -> tuple[int, list[str]]:
    """Analyze AbuseIPDB data and return threat score and indicators."""
    if abuse_result.get("status") != "success":
        return 0, []
    
    reputation = abuse_result.get("reputation_analysis", {})
    confidence_score = reputation.get("abuse_confidence_score", 0)
    score = 0
    indicators = []
    
    if confidence_score >= 75:
        score += 35
        indicators.append(f"AbuseIPDB: High confidence abuse score ({confidence_score}%)")
    elif confidence_score >= 25:
        score += 20
        indicators.append(f"AbuseIPDB: Moderate abuse confidence ({confidence_score}%)")
    
    return score, indicators


def _analyze_shodan_data(shodan_result: Dict[str, Any]) -> tuple[int, list[str]]:
    """Analyze Shodan data and return threat score and indicators."""
    if shodan_result.get("status") != "success":
        return 0, []
    
    network_analysis = shodan_result.get("network_analysis", {})
    score = 0
    indicators = []
    
    if network_analysis.get("is_suspicious", False):
        score += 25
        indicators.append("Shodan: Suspicious network activity detected")
    
    # Check for high-risk ports
    high_risk_ports = network_analysis.get("high_risk_ports", [])
    if high_risk_ports:
        score += min(len(high_risk_ports) * 5, 20)
        indicators.append(f"Shodan: High-risk ports detected: {high_risk_ports}")
    
    return score, indicators


def _analyze_ipinfo_data(ipinfo_result: Dict[str, Any]) -> tuple[int, list[str]]:
    """Analyze IPInfo data and return threat score and indicators."""
    if ipinfo_result.get("status") != "success":
        return 0, []
    
    risk_indicators = ipinfo_result.get("risk_indicators", {})
    score = 0
    indicators = []
    
    risk_score = risk_indicators.get("risk_score", 0)
    if risk_score >= 50:
        score += 15
        indicators.extend(risk_indicators.get("indicators", []))
    
    return score, indicators


def _calculate_risk_assessment(threat_score: int, indicators: list[str]) -> Dict[str, Any]:
    """Calculate comprehensive risk assessment from threat score and indicators."""
    if threat_score >= 70:
        risk_level = "CRITICAL"
        recommendation = "BLOCK - Immediate action required"
        confidence = "high"
        summary = "Multiple high-confidence threat indicators detected"
    elif threat_score >= 40:
        risk_level = "HIGH"
        recommendation = "INVESTIGATE - Multiple threat indicators present"
        confidence = "high" if len(indicators) >= 3 else "medium"
        summary = "Significant security concerns identified"
    elif threat_score >= 15:
        risk_level = "MEDIUM"
        recommendation = "MONITOR - Some security concerns present"
        confidence = "medium"
        summary = "Limited security concerns requiring monitoring"
    else:
        risk_level = "LOW"
        recommendation = "ALLOW - No significant threats detected"
        confidence = "high"
        summary = "No significant security threats identified"
    
    return {
        "risk_level": risk_level,
        "recommendation": recommendation,
        "confidence_level": confidence,
        "summary": summary
    }


def _prepare_analysis_context(state: IPAnalysisState) -> Dict[str, Any]:
    """Prepare comprehensive context for report generation."""
    return {
        "ip_address": state.get("ip_address", ""),
        "user_query": state.get("user_query", ""),
        "validation": state.get("ip_validation", {}),
        "ipinfo": state.get("ipinfo_result", {}),
        "virustotal": state.get("virustotal_result", {}),
        "shodan": state.get("shodan_result", {}),
        "abuseipdb": state.get("abuseipdb_result", {}),
        "threat_analysis": state.get("threat_analysis", {}),
        "execution_duration": state.get("execution_duration")
    }


def _create_comprehensive_prompt(state: IPAnalysisState, context: Dict[str, Any]) -> str:
    """Create comprehensive prompt for Gemini report generation."""
    return f"""
    Generate a comprehensive cybersecurity analysis report for IP address {context['ip_address']}.
    
    User Query: {context['user_query']}
    
    Analysis Results:
    {context}
    
    Please provide a detailed security assessment report that includes:
    
    1. **Executive Summary**
       - Overall risk level and immediate recommendations
       - Key findings summary
    
    2. **IP Address Classification**
       - Technical details and validation results
       - Network ownership and geolocation
    
    3. **Threat Intelligence Analysis**
       - Findings from multiple threat intelligence sources
       - Detailed threat indicators and evidence
    
    4. **Risk Assessment**
       - Comprehensive risk scoring methodology
       - Security implications and potential impact
    
    5. **Recommendations**
       - Immediate actions required
       - Long-term monitoring strategies
       - Security controls and mitigations
    
    6. **Technical Details**
       - Network analysis and port scan results
       - Privacy and anonymization indicators
       - Historical abuse reports
    
    Format the response as a professional cybersecurity analysis report suitable for 
    security teams and decision makers. Use clear headings and bullet points for readability.
    """


def _generate_fallback_report(state: IPAnalysisState) -> str:
    """Generate fallback report when LLM generation fails."""
    if state is None:
        state = {}
    ip_address = state.get("ip_address", "Unknown")
    threat_analysis = state.get("threat_analysis")
    if threat_analysis is None:
        threat_analysis = {}
    return f"""
    # IP Security Analysis Report - {ip_address}
    
    ## Executive Summary
    Risk Level: {threat_analysis.get("risk_level", "UNKNOWN")}
    Recommendation: {threat_analysis.get("recommendation", "Manual review required")}
    
    ## Analysis Status
    Report generation encountered technical difficulties. Please review raw analysis data 
    for detailed findings.
    
    ## Threat Score
    Overall Score: {threat_analysis.get("threat_score", 0)}/100
    
    ## Next Steps
    - Review individual tool results for detailed findings
    - Conduct manual verification if high-risk indicators present
    - Consider re-running analysis if technical issues persist
    """
