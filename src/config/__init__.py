"""
Configuration Management Module

This module handles all configuration management for the LangChain IP Intelligence Agent.
It provides centralized settings management using Pydantic for validation and 
environment variable integration.

Key Components:
- Settings: Main configuration class with API keys and system settings
- Environment variable validation and loading
- Configuration validation and error reporting

Usage:
    from src.config import settings
    
    # Access configuration
    api_key = settings.google_api_key
    timeout = settings.api_timeout
    
    # Validate configuration
    validation_result = settings.validate_api_keys()
"""

from .settings import settings, Settings
from typing import List

# Export main configuration objects
__all__: List[str] = [
    "settings",
    "Settings"
]
