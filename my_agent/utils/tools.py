# tools.py
import os
import requests
import logging
import time
import json # Needed for Shodan's JSON parsing
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

"""
This module defines functions to interact with various threat intelligence APIs.
Each function is designed to be wrapped as a LangChain tool.
All functions include retry logic and detailed error handling.
"""

def get_ipinfo_data(ip_address: str,
                   timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP information from IPInfo API with retry logic (no caching).
    (Adapted from provided ipinfo_tool.py)

    Args:
        ip_address: The IP address to lookup (e.g., "8.8.8.8")
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        dict: IP information including location, ISP, and network details
    """
    service_name = "ipinfo"
    api_key = os.getenv("IPINFO_API_KEY") # IPInfo API key is optional for basic lookups but recommended

    base_url = "https://ipinfo.io"
    for attempt in range(max_retries):
        try:
            url = f"{base_url}/{ip_address}/json"
            headers = {'User-Agent': 'google-adk-ip-enricher/2.0'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'

            logger.debug(f"[-] IPInfo API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=timeout)
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()

                result = {
                    "ip": ip_address,
                    "hostname": data.get('hostname'),
                    "city": data.get('city'),
                    "region": data.get('region'),
                    "country": data.get('country'),
                    "country_name": data.get('country_name'),
                    "location": data.get('loc'),
                    "organization": data.get('org'),
                    "postal": data.get('postal'),
                    "timezone": data.get('timezone'),
                    "asn": data.get('asn'),
                    "company": data.get('company', {}),
                    "carrier": data.get('carrier', {}),
                    "privacy": data.get('privacy', {}),
                    "abuse": data.get('abuse', {}),
                    "domains": data.get('domains', []),
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }

                privacy_info = data.get('privacy', {})
                if privacy_info:
                    result["privacy_flags"] = {
                        "vpn": privacy_info.get('vpn', False),
                        "proxy": privacy_info.get('proxy', False),
                        "tor": privacy_info.get('tor', False),
                        "relay": privacy_info.get('relay', False),
                        "hosting": privacy_info.get('hosting', False)
                    }
                    result["has_privacy_concerns"] = any(result["privacy_flags"].values())

                logger.info(f"[-] IPInfo lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result

            elif response.status_code == 429:
                logger.warning(f"[x] IPInfo rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)

            elif response.status_code == 404:
                logger.error(f"[x] IPInfo: IP address not found: {ip_address}")
                return {
                    "ip": ip_address,
                    "error": f"IP address not found in IPInfo database",
                    "error_code": 404,
                    "source": service_name,
                    "status": "not_found"
                }

            elif response.status_code == 401:
                logger.error(f"[x] IPInfo: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "IPInfo API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }

            else:
                logger.error(f"[x] IPInfo HTTP Error {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"IPInfo API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }

        except requests.exceptions.Timeout:
            logger.error(f"[-] IPInfo timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"IPInfo API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }

        except requests.exceptions.ConnectionError:
            logger.error(f"[-] IPInfo connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"IPInfo API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }

        except Exception as e:
            logger.error(f"[x] Unexpected IPInfo error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during IPInfo lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }

        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying IPInfo in {wait_time} seconds...")
            time.sleep(wait_time)

    logger.error(f"[x] IPInfo lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"IPInfo lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }

def _get_virustotal_threat_level(threat_score: float) -> str:
    """Helper function to determine threat level based on VirusTotal score."""
    if threat_score == 0:
        return "clean"
    elif threat_score < 10:
        return "low"
    elif threat_score < 30:
        return "medium"
    elif threat_score < 70:
        return "high"
    else:
        return "critical"

def get_virustotal_data(ip_address: str,
                       timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP reputation data from VirusTotal API with retry logic (no caching).
    (Adapted from provided virustotal_tool.py)

    Args:
        ip_address: The IP address to check (e.g., "8.8.8.8")
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        dict: VirusTotal analysis results including vendor detections and reputation
              Returns error information if lookup fails
    """
    service_name = "virustotal"
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.error("VirusTotal API key not configured.")
        return {
            "status": "error",
            "service": service_name,
            "ip_address": ip_address,
            "error_message": "VirusTotal API key not configured",
            "error_type": "configuration_error",
            "data_source": service_name
        }

    base_url = "https://www.virustotal.com/api/v3"

    for attempt in range(max_retries):
        try:
            url = f"{base_url}/ip_addresses/{ip_address}"
            headers = {
                "x-apikey": api_key,
                "User-Agent": "google-adk-ip-enricher/1.0"
            }

            logger.debug(f"[-] VirusTotal API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=timeout)
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                total_votes = attributes.get("total_votes", {})

                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0

                is_malicious = malicious_count > 0
                threat_score = 0

                if total_engines > 0:
                    threat_score = min(((malicious_count + suspicious_count * 0.5) / total_engines) * 100, 100)

                result = {
                    "ip": ip_address,
                    "last_analysis_stats": last_analysis_stats,
                    "reputation": reputation,
                    "total_votes": total_votes,
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "total_engines": total_engines,
                    "is_malicious": is_malicious,
                    "threat_score": round(threat_score, 2),
                    "threat_level": _get_virustotal_threat_level(threat_score),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "last_modification_date": attributes.get("last_modification_date"),
                    "country": attributes.get("country"),
                    "as_owner": attributes.get("as_owner"),
                    "asn": attributes.get("asn"),
                    "network": attributes.get("network"),
                    "whois": attributes.get("whois"),
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }

                if malicious_count > 0 or suspicious_count > 0:
                    last_analysis_results = attributes.get("last_analysis_results", {})
                    detected_engines = []
                    for engine, details in last_analysis_results.items():
                        category = details.get("category", "")
                        if category in ["malicious", "suspicious"]:
                            detected_engines.append({
                                "engine": engine,
                                "category": category,
                                "result": details.get("result", ""),
                                "method": details.get("method", "")
                            })
                    result["detected_engines"] = detected_engines

                logger.info(f"[-] VirusTotal lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result

            elif response.status_code == 429:
                logger.warning(f"[x] VirusTotal rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)

            elif response.status_code == 404:
                logger.warning(f"[x] VirusTotal: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No analysis data found for this IP address",
                    "is_malicious": False,
                    "threat_score": 0,
                    "threat_level": "unknown",
                    "source": service_name,
                    "status": "no_data"
                }

            elif response.status_code == 401:
                logger.error(f"[x] VirusTotal: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "VirusTotal API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }

            else:
                logger.error(f"[x] VirusTotal HTTP Error {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"VirusTotal API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }

        except requests.exceptions.Timeout:
            logger.error(f"[-] VirusTotal timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"VirusTotal API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }

        except requests.exceptions.ConnectionError:
            logger.error(f"[-] VirusTotal connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"VirusTotal API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }

        except Exception as e:
            logger.error(f"[x] Unexpected VirusTotal error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during VirusTotal lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }

        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying VirusTotal in {wait_time} seconds...")
            time.sleep(wait_time)

    logger.error(f"[x] VirusTotal lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"VirusTotal lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }

def _get_shodan_risk_level(risk_score: float) -> str:
    """Helper function to determine risk level based on Shodan score."""
    if risk_score == 0:
        return "minimal"
    elif risk_score < 20:
        return "low"
    elif risk_score < 40:
        return "medium"
    elif risk_score < 70:
        return "high"
    else:
        return "critical"

def get_shodan_data(ip_address: str,
                   timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP information from Shodan API with retry logic (no caching).
    (Adapted from provided shodan_tool.py)

    Args:
        ip_address: The IP address to lookup (e.g., "8.8.8.8")
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        dict: Shodan information including ports, services, and vulnerabilities
    """
    service_name = "shodan"
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.error("Shodan API key not configured.")
        return {
            "status": "error",
            "service": service_name,
            "ip_address": ip_address,
            "error_message": "Shodan API key not configured",
            "error_type": "configuration_error",
            "data_source": service_name
        }

    base_url = "https://api.shodan.io/shodan/host"
    url = f"{base_url}/{ip_address}?key={api_key}"

    for attempt in range(max_retries):
        try:
            logger.debug(f"[-] Shodan REST API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            response = requests.get(url, timeout=timeout)
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                host_info = response.json()

                ports = host_info.get("ports", [])
                hostnames = host_info.get("hostnames", [])
                vulnerabilities = host_info.get("vulns", [])
                tags = host_info.get("tags", [])

                suspicious_tags = ["malware", "botnet", "spam", "phishing", "tor", "proxy"]
                has_suspicious_tags = any(tag.lower() in suspicious_tags for tag in tags)
                has_vulnerabilities = len(vulnerabilities) > 0

                risk_score = 0
                if vulnerabilities:
                    risk_score += min(len(vulnerabilities) * 10, 40)
                if has_suspicious_tags:
                    risk_score += 30
                if len(ports) > 10:
                    risk_score += 20
                high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
                open_high_risk_ports = [port for port in ports if port in high_risk_ports]
                if open_high_risk_ports:
                    risk_score += len(open_high_risk_ports) * 5
                risk_score = min(risk_score, 100)

                result = {
                    "ip": ip_address,
                    "ports": sorted(ports),
                    "port_count": len(ports),
                    "hostnames": hostnames,
                    "country": host_info.get("country_name", "Unknown"),
                    "country_code": host_info.get("country_code", "Unknown"),
                    "city": host_info.get("city", "Unknown"),
                    "region": host_info.get("region_code", "Unknown"),
                    "organization": host_info.get("org", "Unknown"),
                    "isp": host_info.get("isp", "Unknown"),
                    "asn": host_info.get("asn", "Unknown"),
                    "last_update": host_info.get("last_update", "Unknown"),
                    "vulnerabilities": vulnerabilities,
                    "vulnerability_count": len(vulnerabilities),
                    "tags": tags,
                    "os": host_info.get("os"),
                    "risk_score": risk_score,
                    "risk_level": _get_shodan_risk_level(risk_score),
                    "is_suspicious": has_suspicious_tags or has_vulnerabilities or risk_score > 30,
                    "high_risk_ports": open_high_risk_ports,
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }

                data_services = host_info.get("data", [])
                if data_services:
                    services = []
                    for service in data_services[:10]:
                        service_info = {
                            "port": service.get("port"),
                            "protocol": service.get("transport", "tcp"),
                            "service": service.get("product", "unknown"),
                            "version": service.get("version", ""),
                            "banner": service.get("data", "")[:200] + "..." if len(service.get("data", "")) > 200 else service.get("data", ""),
                            "timestamp": service.get("timestamp")
                        }
                        services.append(service_info)
                    result["services"] = services

                logger.info(f"[-] Shodan REST lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result

            elif response.status_code == 401:
                logger.error(f"[x] Shodan: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "Shodan API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }

            elif response.status_code == 404:
                logger.warning(f"[!] Shodan: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No information available for this IP address in Shodan",
                    "ports": [],
                    "port_count": 0,
                    "vulnerability_count": 0,
                    "risk_score": 0,
                    "risk_level": "unknown",
                    "is_suspicious": False,
                    "source": service_name,
                    "status": "no_data"
                }

            elif response.status_code == 429:
                logger.warning(f"[!] Shodan rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    continue
                else:
                    return {
                        "ip": ip_address,
                        "error": "Shodan rate limit exceeded",
                        "error_code": 429,
                        "source": service_name,
                        "status": "rate_limit"
                    }

            else:
                logger.error(f"[x] Shodan API HTTP {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"Shodan API HTTP error: {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }

        except requests.exceptions.Timeout:
            logger.error(f"[!] Shodan request timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": "Request timeout",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout"
                }

        except requests.exceptions.ConnectionError:
            logger.error(f"[!] Shodan connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": "Connection error",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"[x] Shodan request error: {e}")
            return {
                "ip": ip_address,
                "error": f"Request error: {str(e)}",
                "error_type": "request_error",
                "source": service_name,
                "status": "request_error"
            }

        except json.JSONDecodeError as e:
            logger.error(f"[x] Shodan JSON decode error: {e}")
            return {
                "ip": ip_address,
                "error": f"Invalid JSON response: {str(e)}",
                "error_type": "json_error",
                "source": service_name,
                "status": "json_error"
            }

        except Exception as e:
            logger.error(f"[x] Unexpected Shodan error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during Shodan lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }

        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying Shodan REST in {wait_time} seconds...")
            time.sleep(wait_time)

    logger.error(f"[x] Shodan lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"Shodan lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }


def get_abuseipdb_data(ip_address: str,
                       timeout: int = 10, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetches IP reputation data from AbuseIPDB API with retry logic (no caching).
    (Adapted from provided abuseipdb_tool.py)

    Args:
        ip_address: The IP address to check (e.g., "8.8.8.8")
        timeout: Request timeout in seconds (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        dict: AbuseIPDB analysis results including abuse confidence score and reports
              Returns error information if lookup fails
    """
    service_name = "abuseipdb"
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.error("AbuseIPDB API key not configured.")
        return {
            "status": "error",
            "service": service_name,
            "ip_address": ip_address,
            "error_message": "AbuseIPDB API key not configured",
            "error_type": "configuration_error",
            "data_source": service_name
        }

    base_url = "https://api.abuseipdb.com/api/v2/check"

    for attempt in range(max_retries):
        try:
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90
            }
            headers = {
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "google-adk-ip-enricher/1.0"
            }
            logger.debug(f"[-] AbuseIPDB API call attempt {attempt + 1} for {ip_address}")
            start_time = time.time()
            response = requests.get(base_url, headers=headers, params=params, timeout=timeout)
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "ip": ip_address,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "last_reported_at": data.get("lastReportedAt"),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "source": service_name,
                    "api_response_time": round(elapsed_time, 3),
                    "status": "success"
                }

                logger.info(f"[-] AbuseIPDB lookup successful for {ip_address} ({elapsed_time:.3f}s)")
                return result

            elif response.status_code == 429:
                logger.warning(f"[x] AbuseIPDB rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"[-] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)

            elif response.status_code == 404:
                logger.warning(f"[x] AbuseIPDB: No data found for IP {ip_address}")
                return {
                    "ip": ip_address,
                    "message": "No abuse data found for this IP address",
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "source": service_name,
                    "status": "no_data"
                }

            elif response.status_code == 401:
                logger.error(f"[x] AbuseIPDB: Authentication failed")
                return {
                    "ip": ip_address,
                    "error": "AbuseIPDB API authentication failed. Check your API key.",
                    "error_code": 401,
                    "source": service_name,
                    "status": "auth_error"
                }

            else:
                logger.error(f"[x] AbuseIPDB HTTP Error {response.status_code}: {response.text}")
                if attempt == max_retries - 1:
                    return {
                        "ip": ip_address,
                        "error": f"AbuseIPDB API error: HTTP {response.status_code}",
                        "error_code": response.status_code,
                        "source": service_name,
                        "status": "api_error"
                    }

        except requests.exceptions.Timeout:
            logger.error(f"[-] AbuseIPDB timeout on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"AbuseIPDB API timeout after {max_retries} attempts",
                    "error_type": "timeout",
                    "source": service_name,
                    "status": "timeout_error"
                }

        except requests.exceptions.ConnectionError:
            logger.error(f"[-] AbuseIPDB connection error on attempt {attempt + 1}/{max_retries}")
            if attempt == max_retries - 1:
                return {
                    "ip": ip_address,
                    "error": f"AbuseIPDB API connection error after {max_retries} attempts",
                    "error_type": "connection_error",
                    "source": service_name,
                    "status": "connection_error"
                }

        except Exception as e:
            logger.error(f"[x] Unexpected AbuseIPDB error: {e}")
            return {
                "ip": ip_address,
                "error": f"Unexpected error during AbuseIPDB lookup: {str(e)}",
                "error_type": "unexpected_error",
                "source": service_name,
                "status": "unexpected_error"
            }

        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"[-] Retrying AbuseIPDB in {wait_time} seconds...")
            time.sleep(wait_time)

    logger.error(f"[x] AbuseIPDB lookup failed for {ip_address} after {max_retries} attempts")
    return {
        "ip": ip_address,
        "error": f"AbuseIPDB lookup failed after {max_retries} attempts",
        "source": service_name,
        "status": "max_retries_exceeded"
    }

