"""
Enhanced batch IP analysis with parallel processing and comprehensive reporting.
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from src.graph.workflow import ip_analysis_app
from src.graph.state import create_initial_state


@dataclass
class BatchAnalysisResult:
    """Result container for batch analysis."""
    ip_address: str
    status: str
    threat_level: Optional[str] = None
    risk_score: Optional[int] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    full_report: Optional[str] = None


async def analyze_single_ip_batch(ip_address: str, semaphore: asyncio.Semaphore) -> BatchAnalysisResult:
    """
    Analyze a single IP as part of batch processing.
    
    Args:
        ip_address: IP to analyze
        semaphore: Semaphore for controlling concurrency
        
    Returns:
        Analysis result
    """
    async with semaphore:
        start_time = time.time()
        
        try:
            initial_state = create_initial_state(
                ip_address, 
                f"Batch analysis for {ip_address}"
            )

            # ip_analysis_app is a StateGraph, which does not have an 'arun' method.
            # The correct way to execute a StateGraph is to use the 'run' method for synchronous execution,
            # or 'arun' if it exists for async. Here, we use 'run' in an executor to avoid blocking.
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, ip_analysis_app.invoke, initial_state)  # type: ignore[attr-defined]
            execution_time = time.time() - start_time
            if result is None:
                return BatchAnalysisResult(
                    ip_address=ip_address,
                    status="failed",
                    execution_time=execution_time,
                    error_message="Workflow returned None"
                )
            if result.get("completed"):
                threat_analysis = result.get("threat_analysis", {})
                return BatchAnalysisResult(
                    ip_address=ip_address,
                    status="success",
                    threat_level=threat_analysis.get("risk_level"),
                    risk_score=threat_analysis.get("threat_score"),
                    execution_time=execution_time,
                    full_report=result.get("final_report"),
                    error_message=result.get("error_message")
                )
            else:
                return BatchAnalysisResult(
                    ip_address=ip_address,
                    status="failed",
                    execution_time=execution_time,
                    error_message=result.get("error_message", "Analysis incomplete")
                )
                
        except Exception as e:
            execution_time = time.time() - start_time
            return BatchAnalysisResult(
                ip_address=ip_address,
                status="error",
                execution_time=execution_time,
                error_message=str(e)
            )


async def analyze_multiple_ips(
    ip_addresses: List[str], 
    max_concurrent: int = 5
) -> Dict[str, BatchAnalysisResult]:
    """
    Analyze multiple IP addresses with controlled concurrency.
    
    Args:
        ip_addresses: List of IP addresses to analyze
        max_concurrent: Maximum concurrent analyses
        
    Returns:
        Dictionary mapping IP addresses to results
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    # Create tasks for all IPs
    tasks = [
        analyze_single_ip_batch(ip, semaphore)
        for ip in ip_addresses
    ]
    
    # Execute all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    analysis_results = {}
    for result in results:
        if isinstance(result, BatchAnalysisResult):
            analysis_results[result.ip_address] = result
        else:
            # Handle unexpected exceptions
            print(f"Unexpected error: {result}")
    
    return analysis_results


def generate_batch_summary(results: Dict[str, BatchAnalysisResult]) -> str:
    """Generate comprehensive summary of batch analysis results."""
    total_ips = len(results)
    successful = sum(1 for r in results.values() if r.status == "success")
    failed = sum(1 for r in results.values() if r.status in ["failed", "error"])
    
    # Categorize by threat level
    threat_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    total_execution_time = 0
    
    for result in results.values():
        if result.threat_level:
            threat_summary[result.threat_level] = threat_summary.get(result.threat_level, 0) + 1
        else:
            threat_summary["UNKNOWN"] += 1
        
        if result.execution_time:
            total_execution_time += result.execution_time
    
    avg_execution_time = total_execution_time / total_ips if total_ips > 0 else 0
    
    summary = f"""
# Batch IP Analysis Summary

## Overview
- **Total IPs Analyzed**: {total_ips}
- **Successful Analyses**: {successful}
- **Failed Analyses**: {failed}
- **Success Rate**: {(successful/total_ips)*100:.1f}%
- **Average Execution Time**: {avg_execution_time:.2f} seconds

## Threat Level Distribution
- **CRITICAL**: {threat_summary['CRITICAL']} IPs
- **HIGH**: {threat_summary['HIGH']} IPs  
- **MEDIUM**: {threat_summary['MEDIUM']} IPs
- **LOW**: {threat_summary['LOW']} IPs
- **UNKNOWN**: {threat_summary['UNKNOWN']} IPs

## High-Risk IPs Detected
"""
    
    # Add high-risk IPs
    high_risk_ips = [
        ip for ip, result in results.items()
        if result.threat_level in ["CRITICAL", "HIGH"]
    ]
    
    if high_risk_ips:
        summary += "\n".join(f"- {ip}" for ip in high_risk_ips)
    else:
        summary += "None detected"
    
    summary += "\n\n## Failed Analyses\n"
    failed_ips = [
        f"- {ip}: {result.error_message}"
        for ip, result in results.items()
        if result.status in ["failed", "error"]
    ]
    
    if failed_ips:
        summary += "\n".join(failed_ips)
    else:
        summary += "None"
    
    return summary


async def main():
    """Example batch analysis execution."""
    # Example IP list for testing
    test_ips = [
        "8.8.8.8",           # Google DNS
        "1.1.1.1",           # Cloudflare DNS
        "9.9.9.9",           # Quad9 DNS
        "208.67.222.222",    # OpenDNS
        "192.168.1.1",       # Private IP
        "10.0.0.1",          # Private IP
        "203.0.113.42",      # Test IP
        "198.51.100.42"      # Test IP
    ]
    
    print("🚀 Starting Batch IP Analysis")
    print(f"Analyzing {len(test_ips)} IP addresses...")
    print("=" * 60)
    
    start_time = time.time()
    
    # Run batch analysis
    results = await analyze_multiple_ips(test_ips, max_concurrent=3)
    
    total_time = time.time() - start_time
    
    # Generate and display summary
    summary = generate_batch_summary(results)
    print(summary)
    
    print(f"\n⏱️  Total batch execution time: {total_time:.2f} seconds")
    print("=" * 60)
    
    # Optionally display detailed results for high-risk IPs
    print("\n📋 Detailed Reports for High-Risk IPs:")
    for ip, result in results.items():
        if result.threat_level in ["CRITICAL", "HIGH"] and result.full_report:
            print(f"\n🚨 {ip} - {result.threat_level} RISK")
            print("-" * 40)
            print(result.full_report[:500] + "..." if len(result.full_report) > 500 else result.full_report)


if __name__ == "__main__":
    asyncio.run(main())
