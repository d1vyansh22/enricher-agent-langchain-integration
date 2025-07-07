"""
Comprehensive tests for LangGraph workflow with enhanced type validation.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from src.graph.state import IPAnalysisState, create_initial_state, StateUpdate
from src.graph.workflow import ip_analysis_app, create_ip_analysis_workflow, should_continue
from src.graph.nodes import (
    validate_ip_node,
    gather_intelligence_node,
    analyze_threats_node,
    generate_report_node
)


class TestStateManagement:
    """Test state management and type safety."""
    
    def test_create_initial_state(self) -> None:
        """Test initial state creation with proper typing."""
        state = create_initial_state("8.8.8.8", "Test query")
        
        # Type validation
        assert isinstance(state, dict)
        assert state.get("ip_address") == "8.8.8.8"
        assert state.get("user_query") == "Test query"
        assert state.get("completed") is False
        assert state.get("messages") == []
        assert state.get("ip_validation") is None
    
    def test_state_partial_updates(self) -> None:
        """Test that partial state updates work correctly."""
        initial_state = create_initial_state("8.8.8.8", "Test")
        
        # Simulate node update
        update: StateUpdate = {
            "ip_validation": {"status": "success", "is_valid": True},
            "next_action": "gather_intelligence"
        }
        
        # Merge update (simulating LangGraph behavior)
        updated_state = {**initial_state, **update}
        
        assert updated_state["ip_validation"]["status"] == "success"
        assert updated_state["next_action"] == "gather_intelligence"
        assert updated_state["ip_address"] == "8.8.8.8"  # Original field preserved


class TestWorkflowNodes:
    """Test individual workflow nodes with type validation."""
    
    def test_validate_ip_node_return_type(self) -> None:
        """Test that validate_ip_node returns proper Dict[str, Any]."""
        initial_state = create_initial_state("8.8.8.8", "Test query")
        
        result = validate_ip_node(initial_state)
        
        # Critical: Must return Dict[str, Any], not IPAnalysisState
        assert type(result) is dict
        
        # Should contain validation results
        assert "ip_validation" in result
        assert "next_action" in result
    
    def test_validate_ip_node_valid_public_ip(self) -> None:
        """Test IP validation node with valid public IP."""
        initial_state = create_initial_state("8.8.8.8", "Test query")
        
        result: StateUpdate = validate_ip_node(initial_state)
        
        # Type validation
        assert type(result) is dict
        assert all(isinstance(k, str) for k in result.keys())
        
        # Business logic validation
        validation = result.get("ip_validation", {})
        assert validation.get("is_valid") is True
        assert validation.get("should_analyze") is True
        assert result["next_action"] == "gather_intelligence"
        assert result.get("error_message") is None
    
    def test_validate_ip_node_private_ip(self) -> None:
        """Test IP validation node with private IP."""
        initial_state = create_initial_state("192.168.1.1", "Test query")
        
        result: StateUpdate = validate_ip_node(initial_state)
        
        assert type(result) is dict
        validation = result.get("ip_validation", {})
        assert validation.get("is_valid") is True
        assert validation.get("should_analyze") is False
        assert result["next_action"] == "complete"
    
    def test_validate_ip_node_invalid_ip(self) -> None:
        """Test IP validation node with invalid IP."""
        initial_state = create_initial_state("invalid.ip.address", "Test query")
        
        result: StateUpdate = validate_ip_node(initial_state)
        
        assert type(result) is dict
        assert result["next_action"] == "complete"
        assert result.get("error_message") is not None
    
    def test_validate_ip_node_missing_ip(self) -> None:
        """Test IP validation node with missing IP address."""
        # Create state without IP address
        invalid_state: Dict[Any, Any] = {
            "user_query": "Test query",
            "messages": [],
            "completed": False,
        }
        
        # mypy: ignore[arg-type]
        result: StateUpdate = validate_ip_node(invalid_state)  # type: ignore
        
        assert type(result) is dict
        assert "error_message" in result
        assert result["next_action"] == "complete"
        assert not result["completed"]
        assert "ip_validation" in result
    
    @patch('src.graph.nodes.ipinfo_tool')
    @patch('src.graph.nodes.virustotal_tool')
    @patch('src.graph.nodes.shodan_tool')
    @patch('src.graph.nodes.abuseipdb_tool')
    def test_gather_intelligence_node_return_type(self, mock_abuse: Any, mock_shodan: Any, 
                                                  mock_vt, mock_ipinfo) -> None:
        """Test that gather_intelligence_node returns proper Dict[str, Any]."""
        # Setup mocks
        for mock_tool in [mock_ipinfo, mock_vt, mock_shodan, mock_abuse]:
            mock_tool.run.return_value = {"status": "success", "service": mock_tool.name}
        
        initial_state = create_initial_state("8.8.8.8", "Test query")
        
        result = gather_intelligence_node(initial_state)
        
        # Critical type validation
        assert type(result) is dict
        
        # Should contain tool results
        assert "ipinfo_result" in result
        assert "virustotal_result" in result
        assert "shodan_result" in result
        assert "abuseipdb_result" in result
        assert result["next_action"] == "analyze_threats"
    
    @patch('src.graph.nodes.ipinfo_tool')
    @patch('src.graph.nodes.virustotal_tool')
    @patch('src.graph.nodes.shodan_tool')
    @patch('src.graph.nodes.abuseipdb_tool')
    def test_gather_intelligence_node_tool_failures(self, mock_abuse: Any, mock_shodan: Any,
                                                    mock_vt, mock_ipinfo) -> None:
        """Test intelligence gathering with some tool failures."""
        # Setup mixed success/failure
        mock_ipinfo.run.return_value = {"status": "success", "service": "ipinfo"}
        mock_vt.run.side_effect = Exception("API Error")
        mock_shodan.run.return_value = {"status": "success", "service": "shodan"}
        mock_abuse.run.side_effect = Exception("Rate Limited")
        
        initial_state = create_initial_state("8.8.8.8", "Test query")
        
        result = gather_intelligence_node(initial_state)
        
        assert type(result) is dict
        assert result["ipinfo_result"]["status"] == "success"
        assert result["virustotal_result"]["status"] == "error"
        assert result["shodan_result"]["status"] == "success"
        assert result["abuseipdb_result"]["status"] == "error"
        assert result["next_action"] == "analyze_threats"
    
    def test_analyze_threats_node_return_type(self) -> None:
        """Test that analyze_threats_node returns proper Dict[str, Any]."""
        # Create state with mock intelligence results
        state = create_initial_state("8.8.8.8", "Test query")
        state.update({
            "virustotal_result": {
                "status": "success",
                "threat_analysis": {"is_malicious": False, "malicious_detections": 0}
            },
            "abuseipdb_result": {
                "status": "success",
                "reputation_analysis": {"abuse_confidence_score": 0}
            },
            "shodan_result": {
                "status": "success",
                "network_analysis": {"is_suspicious": False}
            },
            "ipinfo_result": {
                "status": "success",
                "risk_indicators": {"risk_score": 0}
            }
        })
        
        result = analyze_threats_node(state)
        
        # Critical type validation
        assert type(result) is dict
        
        # Should contain threat analysis
        assert "threat_analysis" in result
        assert "next_action" in result
        assert result["next_action"] == "generate_report"
    
    def test_analyze_threats_node_high_risk(self) -> None:
        """Test threat analysis with high-risk indicators."""
        state = create_initial_state("203.0.113.42", "Test query")
        state.update({
            "virustotal_result": {
                "status": "success",
                "threat_analysis": {"is_malicious": True, "malicious_detections": 10}
            },
            "abuseipdb_result": {
                "status": "success",
                "reputation_analysis": {"abuse_confidence_score": 85}
            },
            "shodan_result": {
                "status": "success",
                "network_analysis": {"is_suspicious": True}
            },
            "ipinfo_result": {
                "status": "success",
                "risk_indicators": {"risk_score": 60}
            }
        })
        
        result = analyze_threats_node(state)
        
        assert type(result) is dict
        threat_analysis = result["threat_analysis"]
        assert threat_analysis["risk_level"] in ["HIGH", "CRITICAL"]
        assert threat_analysis["threat_score"] >= 70
    
    @patch('src.graph.nodes.gemini_llm')
    def test_generate_report_node_return_type(self, mock_llm: Any) -> None:
        """Test that generate_report_node returns proper Dict[str, Any]."""
        mock_response = Mock()
        mock_response.content = "Test security analysis report"
        mock_llm.invoke.return_value = mock_response
        
        state = create_initial_state("8.8.8.8", "Test query")
        state.update({
            "threat_analysis": {"risk_level": "LOW", "threat_score": 5}
        })
        
        result = generate_report_node(state)
        
        # Critical type validation
        assert type(result) is dict
        
        # Should contain final report
        assert "final_report" in result
        assert result["final_report"] == "Test security analysis report"
        assert result["next_action"] == "complete"
        assert result["completed"] is True
    
    @patch('src.graph.nodes.gemini_llm')
    def test_generate_report_node_llm_failure(self, mock_llm: Any) -> None:
        """Test report generation with LLM failure."""
        mock_llm.invoke.side_effect = Exception("LLM API Error")
        
        state = create_initial_state("8.8.8.8", "Test query")
        
        result = generate_report_node(state)
        
        assert type(result) is dict
        assert "error_message" in result
        assert "final_report" in result  # Should have fallback report
        assert result["completed"] is True


class TestConditionalRouting:
    """Test conditional routing logic."""
    
    def test_should_continue_gather_intelligence(self) -> None:
        """Test routing to gather_intelligence."""
        state = create_initial_state("8.8.8.8", "Test")
        state.update({
            "next_action": "gather_intelligence",
            "ip_validation": {"should_analyze": True}
        })
        
        result = should_continue(state)
        assert result == "gather_intelligence"
    
    def test_should_continue_analyze_threats(self) -> None:
        """Test routing to analyze_threats."""
        state = create_initial_state("8.8.8.8", "Test")
        state.update({
            "next_action": "analyze_threats",
            "ipinfo_result": {"status": "success"}
        })
        
        result = should_continue(state)
        assert result == "analyze_threats"
    
    def test_should_continue_generate_report(self) -> None:
        """Test routing to generate_report."""
        state = create_initial_state("8.8.8.8", "Test")
        state.update({
            "next_action": "generate_report"
        })
        
        result = should_continue(state)
        assert result == "generate_report"
    
    def test_should_continue_complete(self) -> None:
        """Test routing to complete."""
        state = create_initial_state("8.8.8.8", "Test")
        state.update({
            "completed": True
        })
        
        result = should_continue(state)
        assert result == "complete"
    
    def test_should_continue_error_state(self) -> None:
        """Test routing with error state."""
        state = create_initial_state("8.8.8.8", "Test")
        state.update({
            "error_message": "Some error occurred"
        })
        
        result = should_continue(state)
        assert result == "complete"
    
    def test_should_continue_invalid_validation(self) -> None:
        """Test routing when IP validation fails."""
        state = create_initial_state("192.168.1.1", "Test")
        state.update({
            "next_action": "gather_intelligence",
            "ip_validation": {"should_analyze": False}
        })
        
        result = should_continue(state)
        assert result == "complete"


class TestWorkflowIntegration:
    """Test complete workflow integration."""
    
    def test_create_ip_analysis_workflow(self) -> None:
        """Test workflow creation and compilation."""
        workflow = create_ip_analysis_workflow()
        
        # Verify workflow is compiled and ready
        assert workflow is not None
        assert hasattr(workflow, 'invoke')
        assert hasattr(workflow, 'ainvoke')
    
    @pytest.mark.asyncio
    @patch('src.graph.nodes.ipinfo_tool')
    @patch('src.graph.nodes.virustotal_tool')
    @patch('src.graph.nodes.shodan_tool')
    @patch('src.graph.nodes.abuseipdb_tool')
    @patch('src.graph.nodes.gemini_llm')
    async def test_complete_workflow_success(self, mock_llm: Any, mock_abuse: Any, 
                                           mock_shodan: Any, mock_vt, mock_ipinfo) -> None:
        """Test complete workflow execution with mocked tools."""
        # Setup all mocks
        mock_ipinfo.run.return_value = {"status": "success", "service": "ipinfo"}
        mock_vt.run.return_value = {
            "status": "success",
            "threat_analysis": {"is_malicious": False, "malicious_detections": 0}
        }
        mock_shodan.run.return_value = {
            "status": "success", 
            "network_analysis": {"is_suspicious": False}
        }
        mock_abuse.run.return_value = {
            "status": "success",
            "reputation_analysis": {"abuse_confidence_score": 0}
        }
        
        mock_response = Mock()
        mock_response.content = "Complete analysis report"
        mock_llm.invoke.return_value = mock_response
        
        initial_state = create_initial_state("8.8.8.8", "Analyze this IP for threats")
        
        # Execute workflow
        result = await ip_analysis_app.ainvoke(initial_state)  # type: ignore[attr-defined]
        
        # Verify final state
        assert result["completed"] is True
        assert result["final_report"] is not None
        assert result["threat_analysis"] is not None
        assert result["ip_validation"]["is_valid"] is True
    
    @pytest.mark.asyncio
    async def test_workflow_invalid_ip(self) -> None:
        """Test workflow with invalid IP address."""
        initial_state = create_initial_state("invalid.ip", "Analyze this IP")
        
        result = await ip_analysis_app.ainvoke(initial_state)  # type: ignore[attr-defined]
        
        # Should complete early due to validation failure
        assert result.get("error_message") is not None or result.get("completed") is True
        assert result["ip_validation"]["is_valid"] is False
    
    @pytest.mark.asyncio
    async def test_workflow_private_ip(self) -> None:
        """Test workflow with private IP address."""
        initial_state = create_initial_state("192.168.1.1", "Analyze this IP")
        
        result = await ip_analysis_app.ainvoke(initial_state)  # type: ignore[attr-defined]
        
        # Should skip intelligence gathering for private IPs
        assert result.get("completed") is True
        assert result["ip_validation"]["should_analyze"] is False


class TestErrorBoundaries:
    """Test error boundary behavior."""
    
    def test_node_error_handling(self) -> None:
        """Test that nodes handle errors gracefully."""
        # Test with completely invalid state
        from types import SimpleNamespace

        # Provide a minimal object with the required attributes to avoid type errors
        # Provide a minimal valid IPAnalysisState-like object to avoid type errors
        class DummyState:
            pass

        # Provide a minimal valid IPAnalysisState-like object to avoid type errors
        class DummyIPAnalysisState:
            ip_address = None
            prompt = None
            completed = False
            ip_validation = {}
            threat_analysis = None
            final_report = None

        # Use a valid IPAnalysisState instance with intentionally broken data to avoid type errors
        state = create_initial_state(None, None)  # type: ignore
        result = validate_ip_node(state)
        # Should return error state, not raise exception
        assert isinstance(result, dict)
        assert "error_message" in result
        assert result.get("completed") is True
    
    @patch('src.graph.nodes.ip_validator')
    def test_tool_failure_handling(self, mock_validator: Any) -> None:
        """Test handling of tool failures."""
        mock_validator.run.side_effect = Exception("Tool failed")
        
        state = create_initial_state("8.8.8.8", "Test")
        
        result = validate_ip_node(state)
        
        # Should handle exception and return error state
        assert type(result) is dict
        assert "error_message" in result
        assert "Tool failed" in result["error_message"]


@pytest.mark.asyncio
class TestPerformance:
    """Test performance characteristics."""
    
    async def test_workflow_timeout_protection(self) -> None:
        """Test that workflow doesn't run indefinitely."""
        import asyncio
        
        initial_state = create_initial_state("8.8.8.8", "Test")
        
        try:
            # Set a reasonable timeout
            # Use getattr to avoid attribute error if 'invoke' does not exist
            invoke_fn = getattr(ip_analysis_app, "invoke", None)
            assert invoke_fn is not None, "ip_analysis_app does not have an 'invoke' method"
            result = await asyncio.wait_for(
                invoke_fn(initial_state),
                timeout=60.0  # 60 second timeout
            )
            # Should complete within timeout
            assert type(result) is dict
            
        except asyncio.TimeoutError:
            pytest.fail("Workflow exceeded timeout - possible infinite loop")
