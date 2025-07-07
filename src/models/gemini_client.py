"""
Gemini API client configuration for LangChain
"""
from langchain_google_genai import ChatGoogleGenerativeAI
from ..config.settings import settings

def create_gemini_llm(temperature: float = 0.0) -> ChatGoogleGenerativeAI:
    """Create and configure Gemini LLM instance."""
    return ChatGoogleGenerativeAI(
        model=settings.gemini_model,
        google_api_key=settings.google_api_key,
        temperature=temperature,
        convert_system_message_to_human=True
    )

# Default LLM instance
gemini_llm = create_gemini_llm()
