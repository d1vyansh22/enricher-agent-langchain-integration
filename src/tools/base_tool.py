"""
Enhanced base tool class with comprehensive input validation and error handling.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Union, Dict, Any, Optional, Callable
from langchain.tools import BaseTool
from langchain_core.tools import ToolException
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)


class ToolInput(BaseModel):
    """Base input schema for IP analysis tools."""
    ip_address: str = Field(description="IP address to analyze")


class EnhancedIPAnalysisTool(BaseTool, ABC):
    """
    Enhanced base class for all IP analysis tools with comprehensive
    input validation, error handling, and retry logic.
    """
    
    # Base configuration
    return_direct: bool = False
    handle_tool_error: Union[bool, str, Callable[[ToolException], str], None] = True
    
    def __init__(self, **kwargs: Any) -> None:
        """Initialize the enhanced tool with proper configuration."""
        super().__init__(**kwargs)
        self.args_schema = ToolInput
    
    @abstractmethod
    def _run_implementation(self, ip_address: str) -> Dict[str, Any]:
        """
        Tool-specific implementation to be overridden by subclasses.
        
        Args:
            ip_address: Validated IP address string
            
        Returns:
            Tool-specific response dictionary
        """
        pass

    def _run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Accepts both positional and keyword arguments to match LangChain's tool interface.
        Extracts ip_address from args or kwargs and delegates to _run_implementation.
        """
        ip_address = None
        if args and isinstance(args[0], str):
            ip_address = args[0]
        elif 'ip_address' in kwargs:
            ip_address = kwargs['ip_address']
        else:
            raise ValueError("ip_address must be provided as a positional argument or keyword argument.")
        return self._run_implementation(ip_address)

    def _extract_ip_address(self, tool_input: Union[str, Dict[str, Any]]) -> str:
        """Extract IP address from various input formats."""
        if isinstance(tool_input, str):
            return tool_input.strip()
        elif isinstance(tool_input, dict):
            ip_address = tool_input.get("ip_address")
            if not ip_address:
                raise ValueError("Dictionary input must contain 'ip_address' key")
            if not isinstance(ip_address, str):
                raise ValueError(f"IP address must be string, got {type(ip_address)}")
            return ip_address.strip()
        else:
            raise ValueError(f"Invalid input type: {type(tool_input)}. Expected str or dict.")
    
    def _validate_ip_format(self, ip_address: str) -> None:
        """Basic IP address format validation."""
        if not ip_address:
            raise ValueError("IP address cannot be empty")
        
        # Basic format check - more detailed validation in IP validator tool
        if not ip_address.replace(".", "").replace(":", "").replace("/", "").isalnum():
            raise ValueError(f"Invalid IP address format: {ip_address}")
    
    def _execute_with_retry(self, ip_address: str) -> Dict[str, Any]:
        """Execute tool with retry logic and error classification."""
        max_retries = getattr(self, 'max_retries', 3)
        
        for attempt in range(max_retries + 1):
            try:
                start_time = time.time()
                result = self._run_implementation(ip_address)
                execution_time = time.time() - start_time
                
                # Add execution metadata
                if isinstance(result, dict):
                    result["execution_time"] = round(execution_time, 3)
                    result["attempt_number"] = attempt + 1
                
                return result
                
            except Exception as e:
                if attempt == max_retries:
                    # Final attempt failed
                    logger.error(f"Tool {self.name} failed after {max_retries + 1} attempts: {str(e)}")
                    raise
                
                # Check if error is retryable
                if not self._is_retryable_error(e):
                    logger.error(f"Non-retryable error in {self.name}: {str(e)}")
                    raise
                
                # Wait before retry with exponential backoff
                wait_time = 2 ** attempt
                logger.warning(f"Tool {self.name} attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
        
        # Should never reach here
        raise RuntimeError("Unexpected retry loop exit")
    
    def _is_retryable_error(self, error: Exception) -> bool:
        """Determine if an error is retryable based on type and message."""
        error_str = str(error).lower()
        
        # Network-related errors are generally retryable
        retryable_indicators = [
            "timeout", "connection", "network", "rate limit", 
            "502", "503", "504", "429"
        ]
        
        return any(indicator in error_str for indicator in retryable_indicators)
    
    def _create_error_response(self, error_message: str, original_input: Any) -> Dict[str, Any]:
        """Create standardized error response."""
        return {
            "status": "error",
            "service": self.name,
            "error_message": error_message,
            "error_type": "tool_execution_error",
            "original_input": str(original_input)
        }
