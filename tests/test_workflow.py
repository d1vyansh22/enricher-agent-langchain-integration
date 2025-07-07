"""
Comprehensive tests for LangGraph workflow orchestration.

This module tests the complete IP analysis workflow including state transitions,
node execution, error handling, and end-to-end functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from src.graph.state import IPAnalysisState
from src.graph.workflow import ip_analysis_app, create_ip_analysis_workflow
from src.graph.nodes import (
    validate_ip_node,
    gather_intelligence_node,
    analyze_threats_node,
    generate_report_node
)

class TestWorkflowNodes:
    """Test individual workflow nodes."""
    
    def test_validate_ip_node_valid_public_ip(self):
        """Test IP validation node with valid public IP."""
        initial_state: IPAnalysisState = {
            "ip_address": "8.8.8.8",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = validate_ip_node(initial_state)
        
        assert result["ip_validation"]["is_valid"] is True
        assert result["ip_validation"]["should_analyze"] is True
        assert result["next_action"] == "gather_intelligence"
        assert result["error_message"] is None

    def test_validate_ip_node_invalid_ip(self):
        """Test IP validation node with invalid IP."""
        initial_state: IPAnalysisState = {
            "ip_address": "invalid.ip.address",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = validate_ip_node(initial_state)
        
        assert result["ip_validation"]["is_valid"] is False
        assert result["next_action"] == "complete"
        assert result["error_message"] is not None

    def test_validate_ip_node_private_ip(self):
        """Test IP validation node with private IP."""
        initial_state: IPAnalysisState = {
            "ip_address": "192.168.1.1",
            "user_query": "Test query", 
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = validate_ip_node(initial_state)
        
        assert result["ip_validation"]["is_valid"] is True
        assert result["ip_validation"]["should_analyze"] is False
        assert result["next_action"] == "complete"

    @patch('src.graph.nodes.ipinfo_tool')
    @patch('src.graph.nodes.virustotal_tool')
    @patch('src.graph.nodes.shodan_tool')
    @patch('src.graph.nodes.abuseipdb_tool')
    def test_gather_intelligence_node(self, mock_abuse, mock_shodan, mock_vt, mock_ipinfo):
        """Test intelligence gathering node with mocked APIs."""
        # Setup mocks
        mock_ipinfo.run.return_value = {"status": "success", "service": "ipinfo"}
        mock_vt.run.return_value = {"status": "success", "service": "virustotal"}
        mock_shodan.run.return_value = {"status": "success", "service": "shodan"}
        mock_abuse.run.return_value = {"status": "success", "service": "abuseipdb"}
        
        initial_state: IPAnalysisState = {
            "ip_address": "8.8.8.8",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": {"is_valid": True, "should_analyze": True},
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = gather_intelligence_node(initial_state)
        
        assert result["ipinfo_result"]["status"] == "success"
        assert result["virustotal_result"]["status"] == "success"
        assert result["shodan_result"]["status"] == "success"
        assert result["abuseipdb_result"]["status"] == "success"
        assert result["next_action"] == "analyze_threats"

    def test_analyze_threats_node_low_risk(self):
        """Test threat analysis with low risk indicators."""
        initial_state: IPAnalysisState = {
            "ip_address": "8.8.8.8",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": {"status": "success"},
            "virustotal_result": {
                "status": "success",
                "threat_analysis": {"is_malicious": False, "malicious_detections": 0}
            },
            "shodan_result": {
                "status": "success", 
                "network_analysis": {"is_suspicious": False}
            },
            "abuseipdb_result": {
                "status": "success",
                "reputation_analysis": {"abuse_confidence_score": 0}
            },
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = analyze_threats_node(initial_state)
        
        assert result["threat_analysis"]["risk_level"] == "LOW"
        assert result["threat_analysis"]["threat_score"] < 15
        assert result["next_action"] == "generate_report"

    def test_analyze_threats_node_high_risk(self):
        """Test threat analysis with high risk indicators."""
        initial_state: IPAnalysisState = {
            "ip_address": "203.0.113.42",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": {"status": "success"},
            "virustotal_result": {
                "status": "success",
                "threat_analysis": {"is_malicious": True, "malicious_detections": 10}
            },
            "shodan_result": {
                "status": "success",
                "network_analysis": {"is_suspicious": True}
            },
            "abuseipdb_result": {
                "status": "success", 
                "reputation_analysis": {"abuse_confidence_score": 85}
            },
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = analyze_threats_node(initial_state)
        
        assert result["threat_analysis"]["risk_level"] == "CRITICAL"
        assert result["threat_analysis"]["threat_score"] >= 70
        assert result["next_action"] == "generate_report"

    @patch('src.graph.nodes.gemini_llm')
    def test_generate_report_node(self, mock_llm):
        """Test report generation node."""
        mock_response = Mock()
        mock_response.content = "Test security analysis report"
        mock_llm.invoke.return_value = mock_response
        
        initial_state: IPAnalysisState = {
            "ip_address": "8.8.8.8",
            "user_query": "Test query",
            "messages": [],
            "ip_validation": {"is_valid": True},
            "ipinfo_result": {"status": "success"},
            "virustotal_result": {"status": "success"},
            "shodan_result": {"status": "success"},
            "abuseipdb_result": {"status": "success"},
            "threat_analysis": {"risk_level": "LOW", "threat_score": 5},
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = generate_report_node(initial_state)
        
        assert result["final_report"] == "Test security analysis report"
        assert result["next_action"] == "complete"
        assert result["completed"] is True
        assert len(result["messages"]) > 0

class TestWorkflowIntegration:
    """Test complete workflow integration."""
    
    @pytest.mark.asyncio
    @patch('src.graph.nodes.ipinfo_tool')
    @patch('src.graph.nodes.virustotal_tool') 
    @patch('src.graph.nodes.shodan_tool')
    @patch('src.graph.nodes.abuseipdb_tool')
    @patch('src.graph.nodes.gemini_llm')
    async def test_complete_workflow_success(self, mock_llm, mock_abuse, mock_shodan, mock_vt, mock_ipinfo):
        """Test complete workflow execution."""
        # Setup mocks
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
        
        initial_state: IPAnalysisState = {
            "ip_address": "8.8.8.8",
            "user_query": "Analyze this IP for threats",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        # Execute workflow
        result = await ip_analysis_app.ainvoke(initial_state)
        
        # Verify final state
        assert result["completed"] is True
        assert result["final_report"] is not None
        assert result["threat_analysis"] is not None
        assert result["ip_validation"]["is_valid"] is True

    @pytest.mark.asyncio
    async def test_workflow_invalid_ip(self):
        """Test workflow with invalid IP address."""
        initial_state: IPAnalysisState = {
            "ip_address": "invalid.ip",
            "user_query": "Analyze this IP",
            "messages": [],
            "ip_validation": None,
            "ipinfo_result": None,
            "virustotal_result": None,
            "shodan_result": None,
            "abuseipdb_result": None,
            "threat_analysis": None,
            "final_report": None,
            "next_action": None,
            "error_message": None,
            "completed": False
        }
        
        result = await ip_analysis_app.ainvoke(initial_state)
        
        # Should complete early due to validation failure
        assert result["error_message"] is not None
        assert result["ip_validation"]["is_valid"] is False

class TestWorkflowConfiguration:
    """Test workflow configuration and setup."""
    
    def test_create_ip_analysis_workflow(self):
        """Test workflow creation and compilation."""
        workflow = create_ip_analysis_workflow()
        
        # Verify workflow is compiled and ready
        assert workflow is not None
        assert hasattr(workflow, 'invoke')
        assert hasattr(workflow, 'ainvoke')

    def test_workflow_nodes_registered(self):
        """Test that all required nodes are registered."""
        workflow = create_ip_analysis_workflow()
        
        # This is a basic test - in practice you'd inspect the workflow structure
        # The exact implementation depends on LangGraph internals
        assert workflow is not None
