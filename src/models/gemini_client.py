"""
Enhanced Gemini API client configuration with proper error handling.
"""

import logging
from typing import Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models.chat_models import BaseChatModel
from ..config.settings import settings

logger = logging.getLogger(__name__)


def create_gemini_llm(
    temperature: float = 0.1,
    model_name: Optional[str] = None,
    max_retries: int = 3
) -> ChatGoogleGenerativeAI:
    """
    Create and configure Gemini LLM instance with enhanced error handling.
    
    Args:
        temperature: Sampling temperature (0.0 to 1.0)
        model_name: Override default model name
        max_retries: Maximum retry attempts for API calls
        
    Returns:
        Configured Gemini LLM instance
        
    Raises:
        ValueError: If API key is not configured
    """
    if not settings.google_api_key:
        raise ValueError("Google API key is required but not configured")
    
    model = model_name or settings.gemini_model
    
    try:
        llm = ChatGoogleGenerativeAI(
            model=model,
            google_api_key=settings.google_api_key,
            temperature=temperature,
            convert_system_message_to_human=True,
            max_retries=max_retries,
            request_timeout=settings.api_timeout
        )
        
        logger.info(f"Initialized Gemini LLM with model: {model}")
        return llm
        
    except Exception as e:
        logger.error(f"Failed to initialize Gemini LLM: {e}")
        raise


# Default LLM instance with error handling
try:
    gemini_llm = create_gemini_llm()
except Exception as e:
    logger.error(f"Failed to create default Gemini LLM instance: {e}")
    # Create a placeholder that will raise an error when used
    class PlaceholderLLM:
        def invoke(self, *args, **kwargs):
            raise RuntimeError("Gemini LLM not properly configured")
    
    gemini_llm = PlaceholderLLM()
