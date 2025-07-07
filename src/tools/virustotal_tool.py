"""
Enhanced VirusTotal API integration with comprehensive threat analysis.
"""

import requests
from typing import Dict, Any, List
from .base_tool import EnhancedIPAnalysisTool
from ..config.settings import settings


class VirusTotalTool(EnhancedIPAnalysisTool):
    """Enhanced tool for checking IP addresses against VirusTotal's threat intelligence database."""
    
    name: str = "virustotal_lookup"
    description: str = """
    Checks IP addresses against VirusTotal's database for malicious activity reports.
    Provides vendor detection counts, reputation scoring, and detailed threat analysis from security engines.
    """
    
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation using VirusTotal API with enhanced analysis."""
        if not settings.virustotal_api_key:
            return {
                "status": "error",
                "service": "virustotal",
                "ip_address": ip_address,
                "error_message": "VirusTotal API key not configured",
                "error_type": "configuration_error"
            }
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": settings.virustotal_api_key,
            "User-Agent": "langchain-ip-intelligence/2.0"
        }
        
        response = requests.get(url, headers=headers, timeout=settings.api_timeout)
        
        if response.status_code == 200:
            data = response.json()
            return self._process_successful_response(data, ip_address)
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded - retryable")
        elif response.status_code == 404:
            return self._create_no_data_response(ip_address)
        elif response.status_code == 401:
            return {
                "status": "error",
                "service": "virustotal", 
                "ip_address": ip_address,
                "error_message": "Invalid API key or authentication failed",
                "error_type": "authentication_error"
            }
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
    
    def _process_successful_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Process successful VirusTotal response with detailed threat analysis."""
        attributes = data.get("data", {}).get("attributes", {})
        
        # Extract analysis statistics
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)
        
        # Calculate comprehensive threat metrics
        threat_metrics = self._calculate_threat_metrics(last_analysis_stats, reputation)
        
        # Extract detected engines with detailed information
        detected_engines = self._extract_detected_engines(attributes.get("last_analysis_results", {}))
        
        # Generate threat assessment
        threat_assessment = self._generate_threat_assessment(threat_metrics, detected_engines)
        
        return {
            "status": "success",
            "service": "virustotal",
            "ip_address": ip_address,
            "threat_analysis": {
                "is_malicious": threat_metrics["is_malicious"],
                "threat_score": threat_metrics["threat_score"],
                "threat_level": threat_metrics["threat_level"],
                "malicious_detections": threat_metrics["malicious_count"],
                "suspicious_detections": threat_metrics["suspicious_count"],
                "clean_detections": threat_metrics["clean_count"],
                "total_engines": threat_metrics["total_engines"],
                "reputation": reputation,
                "confidence_level": threat_assessment["confidence_level"]
            },
            "analysis_stats": last_analysis_stats,
            "detected_engines": detected_engines,
            "network_info": {
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "country": attributes.get("country"),
                "network": attributes.get("network")
            },
            "threat_assessment": threat_assessment,
            "last_analysis_date": attributes.get("last_analysis_date"),
            "data_source": "virustotal"
        }
    
    def _calculate_threat_metrics(self, stats: Dict[str, Any], reputation: int) -> Dict[str, Any]:
        """Calculate comprehensive threat metrics from VirusTotal data."""
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0) 
        clean_count = stats.get("harmless", 0)
        total_engines = sum(stats.values()) if stats else 0
        
        is_malicious = malicious_count > 0
        
        # Calculate weighted threat score
        if total_engines > 0:
            threat_score = ((malicious_count * 1.0 + suspicious_count * 0.5) / total_engines) * 100
        else:
            threat_score = 0
        
        # Incorporate reputation score
        if reputation < 0:
            threat_score = min(threat_score + abs(reputation) * 5, 100)
        
        # Determine threat level
        if threat_score >= 70:
            threat_level = "critical"
        elif threat_score >= 50:
            threat_level = "high"
        elif threat_score >= 20:
            threat_level = "medium"
        elif threat_score > 0:
            threat_level = "low"
        else:
            threat_level = "clean"
        
        return {
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "clean_count": clean_count,
            "total_engines": total_engines,
            "is_malicious": is_malicious,
            "threat_score": round(threat_score, 2),
            "threat_level": threat_level
        }
    
    def _extract_detected_engines(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract detailed information about engines that detected threats."""
        detected_engines = []
        
        for engine, details in analysis_results.items():
            category = details.get("category", "")
            if category in ["malicious", "suspicious"]:
                detected_engines.append({
                    "engine": engine,
                    "category": category,
                    "result": details.get("result", ""),
                    "method": details.get("method", ""),
                    "engine_version": details.get("engine_version", ""),
                    "engine_update": details.get("engine_update", "")
                })
        
        return detected_engines
    
    def _generate_threat_assessment(self, metrics: Dict[str, Any], detected_engines: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment."""
        total_engines = metrics["total_engines"]
        malicious_count = metrics["malicious_count"]
        
        # Calculate confidence level
        if total_engines >= 50:
            confidence = "high"
        elif total_engines >= 20:
            confidence = "medium"
        else:
            confidence = "low"
        
        # Generate recommendations
        recommendations = []
        if metrics["is_malicious"]:
            recommendations.extend([
                "Block or restrict access to this IP address",
                "Investigate any connections from this IP",
                "Monitor for additional indicators of compromise"
            ])
            if malicious_count >= 5:
                recommendations.append("High confidence malicious - immediate action recommended")
        else:
            recommendations.append("No immediate threat detected - continue monitoring")
        
        return {
            "confidence_level": confidence,
            "risk_level": metrics["threat_level"],
            "detection_ratio": f"{malicious_count}/{total_engines}",
            "recommendations": recommendations,
            "notable_engines": [engine["engine"] for engine in detected_engines[:5]]
        }
    
    def _create_no_data_response(self, ip_address: str) -> Dict[str, Any]:
        """Create response for IPs with no data in VirusTotal."""
        return {
            "status": "no_data",
            "service": "virustotal",
            "ip_address": ip_address,
            "message": "No analysis data found for this IP address",
            "threat_analysis": {
                "is_malicious": False,
                "threat_score": 0,
                "threat_level": "unknown",
                "malicious_detections": 0,
                "suspicious_detections": 0,
                "total_engines": 0
            }
        }
