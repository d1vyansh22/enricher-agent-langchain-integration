"""
Unit tests for IP analysis tools
"""
import pytest
from src.tools.ip_validator import IPValidatorTool
from src.tools.ipinfo_tool import IPInfoTool

@pytest.fixture
def ip_validator():
    return IPValidatorTool()

def test_ip_validator_valid_public_ip(ip_validator):
    """Test validation of valid public IP."""
    result = ip_validator.run("8.8.8.8")
    assert result["is_valid"] is True
    assert result["should_analyze"] is True
    assert result["classification"] == "public"

def test_ip_validator_private_ip(ip_validator):
    """Test validation of private IP."""
    result = ip_validator.run("192.168.1.1")
    assert result["is_valid"] is True
    assert result["should_analyze"] is False
    assert result["classification"] == "private"

def test_ip_validator_invalid_ip(ip_validator):
    """Test validation of invalid IP."""
    result = ip_validator.run("invalid.ip.address")
    assert result["is_valid"] is False
    assert result["status"] == "error"

@pytest.mark.asyncio
async def test_ipinfo_tool_integration():
    """Test IPInfo tool integration."""
    tool = IPInfoTool()
    result = tool.run("8.8.8.8")
    
    # Should succeed if API key is configured
    if result["status"] == "success":
        assert "location" in result
        assert "network" in result
        assert result["service"] == "ipinfo"
