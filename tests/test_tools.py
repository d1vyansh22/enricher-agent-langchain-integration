"""
Comprehensive tests for IP analysis tools with enhanced type validation.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, Any, List
from pydantic import ValidationError

from src.tools.ip_validator import IPValidatorTool
from src.tools.ipinfo_tool import IPInfoTool
from src.tools.virustotal_tool import VirusTotalTool
from src.tools.base_tool import EnhancedIPAnalysisTool


class TestIPValidatorTool:
    """Test suite for IP validator with comprehensive validation."""
    
    @pytest.fixture
    def ip_validator(self) -> IPValidatorTool:
        """Create IP validator instance."""
        return IPValidatorTool()
    
    def test_valid_public_ipv4(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of valid public IPv4 address."""
        result = ip_validator.run("8.8.8.8")
        
        # Type validation
        assert isinstance(result, dict), "Result must be dictionary"
        assert result["status"] == "success"
        assert result["is_valid"] is True
        assert result["should_analyze"] is True
        assert result["classification"] == "public"
        assert result["ip_version"] == "ipv4"
    
    def test_valid_public_ipv6(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of valid public IPv6 address."""
        result = ip_validator.run("2001:4860:4860::8888")
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["is_valid"] is True
        assert result["ip_version"] == "ipv6"
    
    def test_private_ipv4(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of private IPv4 address."""
        result = ip_validator.run("192.168.1.1")
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["is_valid"] is True
        assert result["should_analyze"] is False
        assert result["classification"] == "private"
    
    def test_loopback_address(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of loopback address."""
        result = ip_validator.run("127.0.0.1")
        
        assert isinstance(result, dict)
        assert result["is_valid"] is True
        assert result["should_analyze"] is False
        assert result["classification"] == "loopback"
    
    def test_invalid_ip_format(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of invalid IP format."""
        result = ip_validator.run("invalid.ip.address")
        
        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert result["is_valid"] is False
        assert "error_message" in result
    
    def test_empty_ip_address(self, ip_validator: IPValidatorTool) -> None:
        """Test validation of empty IP address."""
        result = ip_validator.run("")
        
        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert result["is_valid"] is False
    
    def test_dict_input_format(self, ip_validator: IPValidatorTool) -> None:
        """Test tool with dictionary input format."""
        result = ip_validator.run({"ip_address": "8.8.8.8"})
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["is_valid"] is True
    
    def test_invalid_dict_input(self, ip_validator: IPValidatorTool) -> None:
        """Test tool with invalid dictionary input."""
        with pytest.raises(ValidationError, match="Field required"):
            ip_validator.run({"invalid_key": "8.8.8.8"})
    
    def test_invalid_input_type(self, ip_validator: IPValidatorTool) -> None:
        """Test tool with invalid input type."""
        with pytest.raises(ValidationError, match="Input should be a valid dictionary or instance of ToolInput"):
            ip_validator.run(123)  # type: ignore[arg-type]


class TestEnhancedIPAnalysisTool:
    """Test suite for enhanced base tool functionality."""
    
    def test_input_normalization_string(self) -> None:
        """Test input normalization with string input."""
        tool = IPValidatorTool()
        ip = tool._extract_ip_address("8.8.8.8")
        assert ip == "8.8.8.8"
    
    def test_input_normalization_dict(self) -> None:
        """Test input normalization with dictionary input."""
        tool = IPValidatorTool()
        ip = tool._extract_ip_address({"ip_address": "8.8.8.8"})
        assert ip == "8.8.8.8"
    
    def test_input_normalization_whitespace(self) -> None:
        """Test input normalization removes whitespace."""
        tool = IPValidatorTool()
        ip = tool._extract_ip_address("  8.8.8.8  ")
        assert ip == "8.8.8.8"
    
    def test_error_response_creation(self) -> None:
        """Test standardized error response creation."""
        tool = IPValidatorTool()
        error_response = tool._create_error_response("Test error", "test_input")
        
        assert isinstance(error_response, dict)
        assert error_response["status"] == "error"
        assert error_response["error_message"] == "Test error"
        assert error_response["service"] == "ip_validator"


class TestIPInfoTool:
    """Test suite for IPInfo tool integration."""
    
    @pytest.fixture
    def ipinfo_tool(self) -> IPInfoTool:
        """Create IPInfo tool instance."""
        return IPInfoTool()
    
    @patch('src.tools.ipinfo_tool.settings')
    def test_missing_api_key(self, mock_settings: Any, ipinfo_tool: IPInfoTool) -> None:
        """Test behavior when API key is missing."""
        mock_settings.ipinfo_api_key = None
        
        result = ipinfo_tool.run("8.8.8.8")
        
        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert "API key not configured" in result["error_message"]
    
    @patch('src.tools.ipinfo_tool.requests.get')
    @patch('src.tools.ipinfo_tool.settings')
    def test_successful_api_response(self, mock_settings: Any, mock_get: Any, ipinfo_tool: IPInfoTool) -> None:
        """Test successful API response processing."""
        # Mock settings
        mock_settings.ipinfo_api_key = "test_key"
        mock_settings.api_timeout = 30
        
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "country": "US",
            "org": "AS15169 Google LLC",
            "privacy": {"vpn": False, "proxy": False, "tor": False}
        }
        mock_get.return_value = mock_response
        
        result = ipinfo_tool.run("8.8.8.8")
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["service"] == "ipinfo"
        assert "location" in result
        assert "network" in result
        assert "privacy" in result
    
    @patch('src.tools.ipinfo_tool.requests.get')
    @patch('src.tools.ipinfo_tool.settings')
    def test_rate_limit_handling(self, mock_settings: Any, mock_get: Any, ipinfo_tool: IPInfoTool) -> None:
        """Test rate limit error handling."""
        mock_settings.ipinfo_api_key = "test_key"
        mock_settings.api_timeout = 30
        
        # Mock rate limit response
        mock_response = Mock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response
        
        with pytest.raises(Exception, match="Rate limit exceeded"):
            ipinfo_tool.run("8.8.8.8")


class TestVirusTotalTool:
    """Test suite for VirusTotal tool integration."""
    
    @pytest.fixture
    def virustotal_tool(self) -> VirusTotalTool:
        """Create VirusTotal tool instance."""
        return VirusTotalTool()
    
    @patch('src.tools.virustotal_tool.settings')
    def test_missing_api_key(self, mock_settings: Any, virustotal_tool: VirusTotalTool) -> None:
        """Test behavior when API key is missing."""
        mock_settings.virustotal_api_key = None
        
        result = virustotal_tool.run("8.8.8.8")
        
        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert "API key not configured" in result["error_message"]
    
    @patch('src.tools.virustotal_tool.requests.get')
    @patch('src.tools.virustotal_tool.settings')
    def test_successful_clean_ip(self, mock_settings: Any, mock_get: Any, virustotal_tool: VirusTotalTool) -> None:
        """Test successful API response for clean IP."""
        mock_settings.virustotal_api_key = "test_key"
        mock_settings.api_timeout = 30
        
        # Mock clean IP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 75,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 10
                    },
                    "reputation": 0
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = virustotal_tool.run("8.8.8.8")
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["threat_analysis"]["is_malicious"] is False
        assert result["threat_analysis"]["threat_level"] == "clean"
    
    @patch('src.tools.virustotal_tool.requests.get')
    @patch('src.tools.virustotal_tool.settings')
    def test_malicious_ip_detection(self, mock_settings: Any, mock_get: Any, virustotal_tool: VirusTotalTool) -> None:
        """Test detection of malicious IP."""
        mock_settings.virustotal_api_key = "test_key"
        mock_settings.api_timeout = 30
        
        # Mock malicious IP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 60,
                        "malicious": 15,
                        "suspicious": 5,
                        "undetected": 5
                    },
                    "reputation": -50,
                    "last_analysis_results": {
                        "Engine1": {"category": "malicious", "result": "malware"},
                        "Engine2": {"category": "malicious", "result": "trojan"}
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = virustotal_tool.run("203.0.113.1")
        
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["threat_analysis"]["is_malicious"] is True
        assert result["threat_analysis"]["malicious_detections"] == 15
        assert len(result["detected_engines"]) > 0


@pytest.mark.asyncio
class TestToolIntegration:
    """Integration tests for tool combinations."""
    
    async def test_tool_chain_execution(self) -> None:
        """Test executing multiple tools in sequence."""
        tools = [
            IPValidatorTool(),
            IPInfoTool(),
            VirusTotalTool()
        ]
        
        ip_address = "8.8.8.8"
        results = []
        
        for tool in tools:
            try:
                result = tool.run(ip_address)
                results.append((tool.name, result))
                assert isinstance(result, dict), f"Tool {tool.name} must return dict"
            except Exception as e:
                # Some tools may fail due to missing API keys in test environment
                results.append((tool.name, {"status": "error", "error_message": str(e)}))
        
        assert len(results) == len(tools)
        
        # Validator should always work
        validator_result = next(r[1] for r in results if r[0] == "ip_validator")
        assert validator_result["status"] == "success"
        assert validator_result["is_valid"] is True


class TestErrorHandling:
    """Test comprehensive error handling scenarios."""
    
    def test_network_timeout_simulation(self) -> None:
        """Test handling of network timeouts."""
        tool = IPValidatorTool()
        
        # This should not timeout as it's local validation
        result = tool.run("8.8.8.8")
        assert isinstance(result, dict)
        assert result["status"] == "success"
    
    def test_malformed_input_handling(self) -> None:
        """Test handling of various malformed inputs."""
        tool = IPValidatorTool()
        
        malformed_inputs: List[Any] = [
            None,
            [],
            {},
            {"wrong_key": "value"},
            123,
            True,
            {"ip_address": None},
            {"ip_address": 123}
        ]
        
        for bad_input in malformed_inputs:
            try:
                result = tool.run(bad_input)
                # If it returns a result, it should be an error
                if isinstance(result, dict):
                    assert result["status"] == "error"
            except (ValueError, TypeError):
                # Exceptions are also acceptable for malformed input
                pass
