# my_agent/utils/ip_validator.py
import re
import ipaddress
import logging
from typing import List, Tuple, Dict, Any
# Removed: from langchain.tools import tool # No longer needed here

logger = logging.getLogger(__name__)

"""
IP Address Validation Utilities.
This module provides functions to validate and classify IP addresses.
The tool wrapper will be defined in agent.py
"""

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format (IPv4 and IPv6).
    """
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass
    ipv4_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))


def get_ip_classification(ip: str) -> Dict[str, Any]:
    """
    Get comprehensive classification of an IP address.
    """
    if not validate_ip_address(ip):
        return {
            'ip': ip,
            'valid': False,
            'type': 'invalid',
            'classification': 'invalid'
        }
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback:
            classification = 'loopback'
        elif ip_obj.is_private:
            classification = 'private'
        elif ip_obj.is_multicast:
            classification = 'multicast'
        elif ip_obj.is_link_local:
            classification = 'link_local'
        elif ip_obj.is_reserved:
            classification = 'reserved'
        else:
            classification = 'public'
        return {
            'ip': ip,
            'valid': True,
            'type': 'ipv4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'ipv6',
            'classification': classification,
            'is_public': classification == 'public',
            'is_private': ip_obj.is_private,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_link_local': ip_obj.is_link_local
        }
    except ValueError as e:
        logger.error(f"Error classifying IP {ip}: {e}")
        return {
            'ip': ip,
            'valid': False,
            'type': 'invalid',
            'classification': 'invalid',
            'error': str(e)
        }

# The actual tool definition will be in agent.py
def check_ip_for_analysis_func(ip_address: str) -> Dict[str, Any]:
    """
    Determines if an IP address is suitable for external threat intelligence analysis.
    Returns a dictionary with 'should_analyze' (bool) and 'reason' (str).
    """
    classification = get_ip_classification(ip_address)

    if not classification['valid']:
        return {"should_analyze": False, "reason": f"Invalid IP address format: {ip_address}"}

    if not classification['is_public']:
        return {"should_analyze": False, "reason": f"{classification['classification'].capitalize()} IP address ({ip_address}) - not suitable for external analysis"}

    return {"should_analyze": True, "reason": f"Public IP address ({ip_address}) - suitable for analysis"}

