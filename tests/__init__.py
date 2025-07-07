"""
Test Suite for LangChain IP Intelligence Agent

This module contains comprehensive tests for all components of the IP intelligence system.
Tests are organized by functionality and include unit tests, integration tests, and 
workflow tests to ensure system reliability and correctness.

Test Categories:
- Unit Tests: Individual tool and component testing
- Integration Tests: API integration and end-to-end workflows  
- Workflow Tests: LangGraph state machine and node testing
- Mock Tests: Isolated testing with API mocking
- Performance Tests: Load testing and performance validation

Test Structure:
- test_tools.py: Tool-specific unit tests
- test_workflow.py: LangGraph workflow and state testing
- test_integration.py: End-to-end system testing
- conftest.py: Shared fixtures and test configuration

Running Tests:
    # Run all tests
    pytest
    
    # Run specific test file
    pytest tests/test_tools.py
    
    # Run with coverage
    pytest --cov=src tests/
    
    # Run integration tests only
    pytest -m integration tests/
"""

import pytest
import asyncio
from typing import Dict, Any, List
from unittest.mock import Mock, patch

# Test configuration and shared fixtures
@pytest.fixture
def sample_ip_addresses():
    """Sample IP addresses for testing."""
    return {
        "valid_public": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
        "valid_private": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        "invalid": ["invalid.ip", "999.999.999.999", "not-an-ip"]
    }

@pytest.fixture
def mock_api_responses():
    """Mock API responses for testing."""
    return {
        "ipinfo": {
            "status": "success",
            "location": {"city": "Mountain View", "country": "US"},
            "network": {"organization": "Google LLC"}
        },
        "virustotal": {
            "status": "success", 
            "threat_analysis": {"is_malicious": False, "threat_score": 0}
        },
        "shodan": {
            "status": "success",
            "network_analysis": {"port_count": 3, "is_suspicious": False}
        },
        "abuseipdb": {
            "status": "success",
            "reputation_analysis": {"abuse_confidence_score": 0, "is_malicious": False}
        }
    }

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

# Test utilities
def create_mock_tool_response(service: str, success: bool = True) -> Dict[str, Any]:
    """Create mock tool response for testing."""
    if success:
        return {
            "status": "success",
            "service": service,
            "ip_address": "8.8.8.8"
        }
    else:
        return {
            "status": "error", 
            "service": service,
            "ip_address": "8.8.8.8",
            "error_message": f"{service} API error"
        }
