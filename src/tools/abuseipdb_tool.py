"""
Enhanced AbuseIPDB API integration with comprehensive abuse analysis.
"""

import requests
from typing import Dict, Any
from .base_tool import EnhancedIPAnalysisTool
from ..config.settings import settings


class AbuseIPDBTool(EnhancedIPAnalysisTool):
    """Enhanced tool for checking IP addresses against AbuseIPDB's community-driven database."""
    
    name: str = "abuseipdb_lookup"
    description: str = """
    Checks IP addresses against AbuseIPDB's community-driven database for abuse reports.
    Provides enhanced abuse confidence scores, community-reported threat intelligence,
    and comprehensive risk assessment based on historical abuse patterns.
    """
    
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB API with enhanced analysis."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': settings.abuseipdb_api_key,
            'Accept': 'application/json',
            'User-Agent': 'langchain-ip-intelligence/2.0'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': getattr(settings, 'abuseipdb_max_age_days', 90),
            'verbose': ''  # Get detailed information
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=settings.api_timeout)
        
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
                "service": "abuseipdb",
                "ip_address": ip_address,
                "error_message": "Invalid API key or authentication failed",
                "error_type": "authentication_error"
            }
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
    
    def _process_successful_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Process successful AbuseIPDB response with comprehensive analysis."""
        ip_data = data.get("data", {})
        
        # Extract key abuse metrics
        abuse_confidence = ip_data.get("abuseConfidenceScore", 0)
        total_reports = ip_data.get("totalReports", 0)
        is_whitelisted = ip_data.get("isWhitelisted", False)
        is_tor = ip_data.get("isTor", False)
        
        # Generate comprehensive reputation analysis
        reputation_analysis = self._analyze_reputation(abuse_confidence, total_reports, is_whitelisted, is_tor)
        
        # Analyze abuse categories if available
        abuse_categories = self._analyze_abuse_categories(ip_data.get("reports", []))
        
        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(reputation_analysis, abuse_categories, ip_data)
        
        return {
            "status": "success",
            "service": "abuseipdb", 
            "ip_address": ip_address,
            "reputation_analysis": reputation_analysis,
            "abuse_categories": abuse_categories,
            "risk_assessment": risk_assessment,
            "location_info": {
                "country_code": ip_data.get("countryCode"),
                "country_name": ip_data.get("countryName"),
                "usage_type": ip_data.get("usageType"),
                "isp": ip_data.get("isp"),
                "domain": ip_data.get("domain"),
                "hostnames": ip_data.get("hostnames", [])
            },
            "technical_info": {
                "ip_version": ip_data.get("ipVersion"),
                "is_public": ip_data.get("isPublic"),
                "last_reported_at": ip_data.get("lastReportedAt"),
                "first_seen": ip_data.get("firstSeen"),
                "num_distinct_users": ip_data.get("numDistinctUsers", 0)
            },
            "data_source": "abuseipdb"
        }
    
    def _analyze_reputation(self, confidence: int, total_reports: int, 
                          is_whitelisted: bool, is_tor: bool) -> Dict[str, Any]:
        """Analyze reputation metrics with enhanced scoring."""
        # Base threat assessment
        if confidence == 0:
            threat_level = "clean"
            is_malicious = False
        elif confidence < 25:
            threat_level = "low"
            is_malicious = False
        elif confidence < 50:
            threat_level = "medium"
            is_malicious = True
        elif confidence < 75:
            threat_level = "high"
            is_malicious = True
        else:
            threat_level = "critical"
            is_malicious = True
        
        # Calculate enhanced risk score
        risk_score = confidence
        
        # Adjust for special characteristics
        if is_tor:
            risk_score = min(risk_score + 15, 100)
        if total_reports > 50:
            risk_score = min(risk_score + 10, 100)
        if is_whitelisted:
            risk_score = max(risk_score - 20, 0)
            is_malicious = False
        
        # Calculate reporting velocity (reports per day approximation)
        reporting_velocity = "unknown"
        if total_reports > 0:
            # Rough calculation based on total reports
            if total_reports > 100:
                reporting_velocity = "high"
            elif total_reports > 20:
                reporting_velocity = "medium"
            else:
                reporting_velocity = "low"
        
        return {
            "abuse_confidence_score": confidence,
            "is_malicious": is_malicious and not is_whitelisted,
            "threat_level": threat_level,
            "risk_score": risk_score,
            "total_reports": total_reports,
            "reporting_velocity": reporting_velocity,
            "is_whitelisted": is_whitelisted,
            "is_tor": is_tor,
            "reputation_summary": self._generate_reputation_summary(
                confidence, total_reports, is_whitelisted, is_tor, threat_level
            )
        }
    
    def _analyze_abuse_categories(self, reports: list) -> Dict[str, Any]:
        """Analyze abuse categories from detailed reports."""
        if not reports:
            return {
                "category_breakdown": {},
                "primary_abuse_types": [],
                "recent_activity": {},
                "attack_patterns": []
            }
        
        # AbuseIPDB category mapping
        category_mapping = {
            1: "DNS Compromise",
            2: "DNS Poisoning", 
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        
        category_counts: Dict[str, int] = {}
        recent_reports = []
        
        for report in reports[:20]:  # Analyze up to 20 most recent reports
            categories = report.get("categories", [])
            for cat_id in categories:
                cat_name = category_mapping.get(cat_id, f"Category {cat_id}")
                category_counts[cat_name] = category_counts.get(cat_name, 0) + 1
            
            recent_reports.append({
                "reported_at": report.get("reportedAt"),
                "categories": [category_mapping.get(cat, f"Category {cat}") for cat in categories],
                "comment": report.get("comment", "")[:200]  # Truncate comments
            })
        
        # Identify primary abuse types
        primary_types = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Analyze attack patterns
        attack_patterns = self._identify_attack_patterns(category_counts)
        
        return {
            "category_breakdown": category_counts,
            "primary_abuse_types": [{"type": ptype, "count": count} for ptype, count in primary_types],
            "recent_activity": {
                "report_count": len(recent_reports),
                "recent_reports": recent_reports[:5]  # Most recent 5
            },
            "attack_patterns": attack_patterns
        }
    
    def _identify_attack_patterns(self, categories: Dict[str, int]) -> list:
        """Identify common attack patterns from category data."""
        patterns = []
        
        # Check for brute force patterns
        brute_force_cats = ["SSH", "FTP Brute-Force", "Brute-Force"]
        if any(cat in categories for cat in brute_force_cats):
            patterns.append("Brute force attack patterns detected")
        
        # Check for web attack patterns
        web_attack_cats = ["Web App Attack", "SQL Injection", "Phishing"]
        if any(cat in categories for cat in web_attack_cats):
            patterns.append("Web application attack patterns detected")
        
        # Check for botnet/malware patterns
        botnet_cats = ["DDoS Attack", "Exploited Host", "Bad Web Bot"]
        if any(cat in categories for cat in botnet_cats):
            patterns.append("Botnet/malware activity patterns detected")
        
        # Check for scanning patterns
        if "Port Scan" in categories:
            patterns.append("Network reconnaissance patterns detected")
        
        return patterns
    
    def _generate_risk_assessment(self, reputation: Dict[str, Any], 
                                 categories: Dict[str, Any], ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment."""
        risk_factors = []
        mitigation_recommendations = []
        
        confidence = reputation["abuse_confidence_score"]
        is_malicious = reputation["is_malicious"]
        
        # Risk factor analysis
        if confidence >= 75:
            risk_factors.append("High community consensus on malicious activity")
            mitigation_recommendations.append("Immediate blocking recommended")
        
        if reputation["is_tor"]:
            risk_factors.append("Tor exit node - anonymized traffic source")
            mitigation_recommendations.append("Enhanced monitoring for Tor traffic")
        
        if categories.get("attack_patterns"):
            risk_factors.extend(categories["attack_patterns"])
            mitigation_recommendations.append("Deploy targeted security controls")
        
        primary_types = categories.get("primary_abuse_types", [])
        if primary_types:
            top_abuse = primary_types[0]["type"]
            risk_factors.append(f"Primary abuse type: {top_abuse}")
            mitigation_recommendations.append(f"Implement {top_abuse.lower()} specific protections")
        
        # Overall risk level
        if confidence >= 75 or len(risk_factors) >= 3:
            overall_risk = "critical"
        elif confidence >= 50 or len(risk_factors) >= 2:
            overall_risk = "high"
        elif confidence >= 25 or len(risk_factors) >= 1:
            overall_risk = "medium"
        else:
            overall_risk = "low"
        
        return {
            "overall_risk_level": overall_risk,
            "risk_factors": risk_factors,
            "mitigation_recommendations": mitigation_recommendations,
            "monitoring_priority": "high" if is_malicious else "normal",
            "recommended_actions": self._generate_recommended_actions(overall_risk, is_malicious)
        }
    
    def _generate_reputation_summary(self, confidence: int, total_reports: int,
                                   is_whitelisted: bool, is_tor: bool, threat_level: str) -> str:
        """Generate human-readable reputation summary."""
        if is_whitelisted:
            return "IP is whitelisted - considered safe despite any reports"
        elif confidence == 0:
            return "No abuse reports found - clean reputation"
        elif confidence >= 75:
            return f"High abuse confidence ({confidence}%) with {total_reports} reports - significant threat"
        elif confidence >= 25:
            return f"Moderate abuse confidence ({confidence}%) with {total_reports} reports - caution advised"
        else:
            return f"Low abuse confidence ({confidence}%) with {total_reports} reports - minimal concern"
    
    def _generate_recommended_actions(self, risk_level: str, is_malicious: bool) -> list:
        """Generate specific recommended actions based on risk assessment."""
        actions = []
        
        if risk_level == "critical":
            actions.extend([
                "Implement immediate IP blocking",
                "Review and investigate any recent connections",
                "Alert security team for potential incident response"
            ])
        elif risk_level == "high":
            actions.extend([
                "Consider blocking or rate limiting",
                "Enhanced monitoring and logging",
                "Review security controls and policies"
            ])
        elif risk_level == "medium":
            actions.extend([
                "Increase monitoring frequency",
                "Review access logs for suspicious activity",
                "Consider additional authentication requirements"
            ])
        else:
            actions.append("Continue normal monitoring procedures")
        
        return actions
    
    def _create_no_data_response(self, ip_address: str) -> Dict[str, Any]:
        """Create response for IPs with no data in AbuseIPDB."""
        return {
            "status": "no_data",
            "service": "abuseipdb",
            "ip_address": ip_address,
            "message": "No abuse reports found for this IP address in AbuseIPDB",
            "reputation_analysis": {
                "abuse_confidence_score": 0,
                "is_malicious": False,
                "threat_level": "unknown",
                "total_reports": 0,
                "reputation_summary": "No historical abuse data available"
            }
        }
