# main.py
import os
from dotenv import load_dotenv
from graph import build_graph
from state import IPAnalysisState
from typing import Dict, Any

"""
Main application file to run the multi-agentic threat intelligence system.
Loads environment variables, initializes the graph, and handles user interaction.
"""

def main():
    # Load environment variables
    load_dotenv()

    # Set LangSmith environment variables if tracing is enabled
    os.environ["LANGCHAIN_TRACING_V2"] = os.getenv("LANGCHAIN_TRACING_V2", "false")
    os.environ["LANGCHAIN_API_KEY"] = os.getenv("LANGCHAIN_API_KEY", "")
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT", "Threat Intelligence System")

    # Ensure Google API Key is set
    if not os.getenv("GOOGLE_API_KEY"):
        print("Error: GOOGLE_API_KEY environment variable not set.")
        print("Please set it in your .env file or system environment.")
        return

    print("Initializing Threat Intelligence System...")
    app = build_graph()
    print("System ready. Type 'exit' to quit.")

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

        print("\n--- Running Analysis ---")
        try:
            # Invoke the graph with the initial state to get the final result
            final_result = app.invoke(initial_state)

            print("\n--- Analysis Complete ---")
            if final_result.get("error_message"):
                print(f"Error: {final_result['error_message']}")
            elif final_result.get("analysis_report"):
                print("\n--- Threat Intelligence Report ---")
                print(final_result["analysis_report"])
            else:
                print("No report generated. Check for errors or if an IP was extracted.")
                print(f"Final State (for debugging): {final_result}")

        except Exception as e:
            print(f"\nAn unexpected error occurred during analysis: {e}")
            import traceback
            traceback.print_exc() # Print full traceback for debugging

if __name__ == "__main__":
    main()

