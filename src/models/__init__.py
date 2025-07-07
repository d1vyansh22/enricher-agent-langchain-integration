"""
Language Model Integration Module

This module handles integration with various language models for the IP intelligence system.
Currently focused on Google Gemini integration with LangChain, but designed to be extensible
for other LLM providers.

Key Components:
- Gemini Client: Google Gemini API integration via LangChain
- LLM Configuration: Model settings and parameters
- Chat Interface: Conversational AI capabilities for IP analysis

Features:
- Configurable temperature and model parameters
- Error handling and retry logic
- Cost optimization through model selection
- Integration with LangSmith for monitoring

Usage:
    from src.models import gemini_llm, create_gemini_llm
    
    # Use default configured LLM
    response = gemini_llm.invoke("Analyze this IP: 8.8.8.8")
    
    # Create custom LLM instance
    custom_llm = create_gemini_llm(temperature=0.5)
"""

from .gemini_client import gemini_llm, create_gemini_llm

# Export LLM components
__all__ = [
    "gemini_llm",
    "create_gemini_llm"
]
