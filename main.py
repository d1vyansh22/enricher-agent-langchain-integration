# main.py
import os
from dotenv import load_dotenv
from graph import build_graph
from state import IPAnalysisState
from typing import Dict, Any
import logging # Import logging module

"""
Main application file to run the multi-agentic threat intelligence system.
Loads environment variables, initializes the graph, and handles user interaction.
"""

# Configure logging at the very beginning to ensure all logs are visible
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main():
    # Load environment variables from .env file
    load_dotenv()

    # --- Ensure LangSmith environment variables are set early ---
    # These must be set BEFORE any LangChain/LangGraph components are initialized
    # for tracing to work correctly.
    os.environ["LANGCHAIN_TRACING_V2"] = os.getenv("LANGCHAIN_TRACING_V2", "false")
    os.environ["LANGCHAIN_API_KEY"] = os.getenv("LANGCHAIN_API_KEY", "")
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT", "Threat Intelligence System")
    # Optionally, you can also set the endpoint if you're not using the default
    # os.environ["LANGCHAIN_ENDPOINT"] = os.getenv("LANGCHAIN_ENDPOINT", "https://api.smith.langchain.com")

    # Confirmation prints for debugging
    logger.info(f"LANGCHAIN_TRACING_V2: {os.environ.get('LANGCHAIN_TRACING_V2')}")
    logger.info(f"LANGCHAIN_PROJECT: {os.environ.get('LANGCHAIN_PROJECT')}")
    # Be careful not to print the full API key in production logs
    if os.environ.get('LANGCHAIN_API_KEY'):
        logger.info("LANGCHAIN_API_KEY is set (value hidden for security).")
    else:
        logger.warning("LANGCHAIN_API_KEY is NOT set. LangSmith tracing will not work.")


    # Ensure Google API Key is set
    if not os.getenv("GOOGLE_API_KEY"):
        logger.error("Error: GOOGLE_API_KEY environment variable not set.")
        logger.error("Please set it in your .env file or system environment.")
        return

    logger.info("Initializing Threat Intelligence System...")
    app = build_graph() # Graph initialization happens AFTER env vars are set
    logger.info("System ready. Type 'exit' to quit.")

    while True:
        user_input = input("\nEnter your query (e.g., 'Analyze IP 8.8.8.8 for threats'): ")
        if user_input.lower() == 'exit':
            break

        # Initial state for the graph
        initial_state: IPAnalysisState = {
            "user_query": user_input,
            "ip_address": None,
            "ipinfo_data": None,
            "virustotal_data": None,
            "shodan_data": None,
            "abuseipdb_data": None,
            "analysis_report": None,
            "error_message": None
        }

        logger.info("\n--- Running Analysis ---")
        try:
            # Invoke the graph with the initial state
            final_result = app.invoke(initial_state)

            logger.info("\n--- Analysis Complete ---")
            if final_result.get("error_message"):
                logger.error(f"Error: {final_result['error_message']}")
            elif final_result.get("analysis_report"):
                logger.info("\n--- Threat Intelligence Report ---")
                print(final_result["analysis_report"]) # Use print for the final report to avoid logger prefixes
            else:
                logger.warning("No report generated. Check for errors or if an IP was extracted.")
                logger.info(f"Final State (for debugging): {final_result}")

        except Exception as e:
            logger.exception(f"\nAn unexpected error occurred during analysis: {e}") # Use logger.exception for full traceback

if __name__ == "__main__":
    main()

