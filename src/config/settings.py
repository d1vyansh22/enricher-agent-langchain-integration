"""
Configuration management for LangChain IP Intelligence Agent
"""
import os
from typing import Optional
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Gemini API Configuration
    google_api_key: str = Field(..., env="GOOGLE_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-pro", env="GEMINI_MODEL")
    
    # Threat Intelligence APIs
    ipinfo_api_key: Optional[str] = Field(None, env="IPINFO_API_KEY")
    virustotal_api_key: Optional[str] = Field(None, env="VIRUSTOTAL_API_KEY")
    shodan_api_key: Optional[str] = Field(None, env="SHODAN_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(None, env="ABUSEIPDB_API_KEY")
    
    # LangSmith Configuration
    langchain_tracing_v2: bool = Field(default=True, env="LANGCHAIN_TRACING_V2")
    langchain_api_key: Optional[str] = Field(None, env="LANGCHAIN_API_KEY")
    langchain_project: str = Field(default="ip-intelligence-agent", env="LANGCHAIN_PROJECT")
    
    # API Configuration
    api_timeout: int = Field(default=30, env="API_TIMEOUT")
    max_retries: int = Field(default=3, env="MAX_RETRIES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    def validate_api_keys(self) -> dict:
        """Validate which API keys are configured."""
        return {
            "google_api_key": bool(self.google_api_key),
            "ipinfo_api_key": bool(self.ipinfo_api_key),
            "virustotal_api_key": bool(self.virustotal_api_key),
            "shodan_api_key": bool(self.shodan_api_key),
            "abuseipdb_api_key": bool(self.abuseipdb_api_key),
            "langchain_api_key": bool(self.langchain_api_key)
        }

# Global settings instance
settings = Settings()
