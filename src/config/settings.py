"""
Enhanced configuration management with proper type safety and validation.
"""

import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from pydantic.config import ConfigDict


class Settings(BaseSettings):
    """Application settings with comprehensive environment variable support."""
    
    # Core LLM Configuration
    google_api_key: str = Field(default=..., validation_alias="GOOGLE_API_KEY")
    gemini_model: str = Field(default="gemini-2.0-flash", validation_alias="GEMINI_MODEL")
    
    # Threat Intelligence APIs
    ipinfo_api_key: Optional[str] = Field(default=None, validation_alias="IPINFO_API_KEY")
    virustotal_api_key: Optional[str] = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, validation_alias="SHODAN_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")
    
    # LangSmith Configuration
    langchain_tracing_v2: bool = Field(default=True, validation_alias="LANGCHAIN_TRACING_V2")
    langchain_api_key: Optional[str] = Field(default=None, validation_alias="LANGCHAIN_API_KEY")
    langchain_project: str = Field(default="ip-intelligence-agent", validation_alias="LANGCHAIN_PROJECT")
    
    # API Configuration
    api_timeout: int = Field(default=30, validation_alias="API_TIMEOUT")
    max_retries: int = Field(default=3, validation_alias="MAX_RETRIES")
    
    # Advanced Configuration
    enable_debug_logging: bool = Field(default=False, validation_alias="ENABLE_DEBUG_LOGGING")
    workflow_timeout: int = Field(default=300, validation_alias="WORKFLOW_TIMEOUT")
    
    @validator("api_timeout")
    def validate_timeout(cls, v: int) -> int:
        """Ensure timeout is reasonable."""
        if v < 5 or v > 300:
            raise ValueError("API timeout must be between 5 and 300 seconds")
        return v
    
    @validator("max_retries")
    def validate_retries(cls, v: int) -> int:
        """Ensure retry count is reasonable."""
        if v < 0 or v > 10:
            raise ValueError("Max retries must be between 0 and 10")
        return v
    
    def get_api_key_status(self) -> Dict[str, bool]:
        """Get status of all API keys for validation."""
        return {
            "google_api_key": bool(self.google_api_key),
            "ipinfo_api_key": bool(self.ipinfo_api_key),
            "virustotal_api_key": bool(self.virustotal_api_key),
            "shodan_api_key": bool(self.shodan_api_key),
            "abuseipdb_api_key": bool(self.abuseipdb_api_key),
            "langchain_api_key": bool(self.langchain_api_key)
        }
    
    def validate_required_keys(self) -> None:
        """Validate that required API keys are present."""
        if not self.google_api_key:
            raise ValueError("GOOGLE_API_KEY is required but not configured")


# Global settings instance
settings = Settings()
