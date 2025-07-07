"""
Enhanced single IP analysis example with comprehensive error handling.
"""

import asyncio
import logging
from typing import Optional, Any, cast
from src.graph.workflow import ip_analysis_app
from src.graph.state import create_initial_state
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def analyze_ip(ip_address: str, user_query: Optional[str] = None) -> str:
    """
    Analyze a single IP address with enhanced error handling.
    
    Args:
        ip_address: IP address to analyze
        user_query: Optional custom query
        
    Returns:
        Analysis report or error message
    """
    if not user_query:
        user_query = f"Perform comprehensive threat intelligence analysis on {ip_address}"
    
    try:
        # Create initial state
        initial_state = create_initial_state(ip_address, user_query)
        
        # Execute the workflow
        logger.info(f"Starting analysis for {ip_address}")
        result = await cast(Any, ip_analysis_app).ainvoke(initial_state)
        
        # Check for successful completion
        if result is None:
            return "Analysis failed: Workflow returned None"
        
        if result.get("completed"):
            if result.get("error_message"):
                return f"Analysis completed with warnings:\n{result['error_message']}"
            else:
                return result.get("final_report", "Analysis completed but no report generated")
        else:
            return f"Analysis failed: {result.get('error_message', 'Unknown error')}"
            
    except Exception as e:
        logger.error(f"Analysis failed for {ip_address}: {e}")
        return f"Analysis failed due to system error: {str(e)}"


async def main():
    """Example usage of the IP analysis system."""
    test_ips = [
        "8.8.8.8",           # Google DNS - should be clean
        "1.1.1.1",           # Cloudflare DNS - should be clean  
        "192.168.1.1",       # Private IP - should be skipped
        "203.0.113.42"       # Test IP - results may vary
    ]
    
    print("IP Intelligence Agent - Analysis Examples")
    print("=" * 50)
    
    for ip in test_ips:
        print(f"\n🔍 Analyzing {ip}...")
        print("-" * 30)
        
        try:
            report = await analyze_ip(ip)
            print(report)
        except Exception as e:
            print(f"❌ Error analyzing {ip}: {e}")
        
        print("\n" + "=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
