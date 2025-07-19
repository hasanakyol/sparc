#!/usr/bin/env python3
"""
Security Gates Checker
Evaluates security scan results against configured thresholds and determines if the build should pass or fail.
"""

import argparse
import json
import sys
from typing import Dict, Any, Tuple


def load_json_file(filepath: str) -> Dict[str, Any]:
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return {}


def check_severity_thresholds(report: Dict[str, Any], config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Check if vulnerability counts exceed configured thresholds.
    Returns (passed, message)
    """
    summary = report.get('summary', {})
    thresholds = config.get('thresholds', {})
    
    messages = []
    should_block = False
    
    # Check each severity level
    for severity in ['critical', 'high', 'medium', 'low']:
        count = summary.get(severity, 0)
        threshold_config = thresholds.get(severity, {})
        action = threshold_config.get('action', 'info')
        
        if count > 0:
            if severity == 'critical':
                # Critical vulnerabilities always fail
                should_block = True
                messages.append(f"❌ Found {count} CRITICAL vulnerabilities - BUILD BLOCKED")
            elif severity == 'high' and action == 'block':
                # High vulnerabilities block if configured
                max_allowed = threshold_config.get('max_allowed', 0)
                if count > max_allowed:
                    should_block = True
                    messages.append(f"❌ Found {count} HIGH vulnerabilities (max allowed: {max_allowed}) - BUILD BLOCKED")
                else:
                    messages.append(f"⚠️  Found {count} HIGH vulnerabilities (within threshold)")
            elif severity == 'medium':
                messages.append(f"⚠️  Found {count} MEDIUM vulnerabilities")
            elif severity == 'low':
                messages.append(f"ℹ️  Found {count} LOW vulnerabilities")
    
    if not messages:
        messages.append("✅ No vulnerabilities found")
    
    return not should_block, '\n'.join(messages)


def check_scan_failures(report: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if any security scans failed to complete."""
    scan_results = report.get('scan_results', {})
    failed_scans = []
    
    for scan_type, result in scan_results.items():
        if result.get('status') == 'failed':
            failed_scans.append(scan_type)
    
    if failed_scans:
        return False, f"❌ The following scans failed to complete: {', '.join(failed_scans)}"
    
    return True, "✅ All security scans completed successfully"


def check_specific_vulnerability_types(report: Dict[str, Any], config: Dict[str, Any]) -> Tuple[bool, str]:
    """Check for specific types of vulnerabilities that should always fail the build."""
    vulnerabilities = report.get('vulnerabilities', [])
    blocked_types = config.get('blocked_vulnerability_types', [
        'SQL Injection',
        'Remote Code Execution',
        'Authentication Bypass',
        'Hardcoded Credentials',
        'Private Key Exposure'
    ])
    
    found_blocked = []
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', '')
        if any(blocked in vuln_type for blocked in blocked_types):
            found_blocked.append(f"{vuln_type} in {vuln.get('file', 'unknown')}")
    
    if found_blocked:
        return False, f"❌ Found critical vulnerability types:\n" + '\n'.join(f"  - {v}" for v in found_blocked[:5])
    
    return True, "✅ No critical vulnerability types found"


def generate_summary_report(report: Dict[str, Any], passed: bool) -> str:
    """Generate a summary report of the security scan results."""
    summary = report.get('summary', {})
    total_vulns = sum(summary.get(sev, 0) for sev in ['critical', 'high', 'medium', 'low'])
    
    report_lines = [
        "=" * 60,
        "SECURITY SCAN SUMMARY",
        "=" * 60,
        f"Total Vulnerabilities: {total_vulns}",
        f"  Critical: {summary.get('critical', 0)}",
        f"  High:     {summary.get('high', 0)}",
        f"  Medium:   {summary.get('medium', 0)}",
        f"  Low:      {summary.get('low', 0)}",
        "",
        f"Security Gate Status: {'✅ PASSED' if passed else '❌ FAILED'}",
        "=" * 60
    ]
    
    return '\n'.join(report_lines)


def main():
    parser = argparse.ArgumentParser(description='Check security gates based on scan results')
    parser.add_argument('--report', required=True, help='Path to the security report JSON file')
    parser.add_argument('--config', required=True, help='Path to the security configuration file')
    parser.add_argument('--output-format', choices=['text', 'json'], default='text', help='Output format')
    args = parser.parse_args()
    
    # Load report and configuration
    report = load_json_file(args.report)
    config = load_json_file(args.config)
    
    if not report:
        print("❌ Failed to load security report")
        sys.exit(1)
    
    # Run all checks
    checks = []
    overall_passed = True
    
    # Check severity thresholds
    passed, message = check_severity_thresholds(report, config)
    checks.append(('Severity Thresholds', passed, message))
    overall_passed = overall_passed and passed
    
    # Check scan failures
    passed, message = check_scan_failures(report)
    checks.append(('Scan Completion', passed, message))
    overall_passed = overall_passed and passed
    
    # Check specific vulnerability types
    passed, message = check_specific_vulnerability_types(report, config)
    checks.append(('Vulnerability Types', passed, message))
    overall_passed = overall_passed and passed
    
    # Output results
    if args.output_format == 'json':
        result = {
            'passed': overall_passed,
            'checks': [
                {'name': name, 'passed': passed, 'message': message}
                for name, passed, message in checks
            ]
        }
        print(json.dumps(result, indent=2))
    else:
        # Text output
        print("\nSECURITY GATE CHECKS")
        print("=" * 60)
        for name, passed, message in checks:
            print(f"\n{name}:")
            print(message)
        
        print("\n" + generate_summary_report(report, overall_passed))
    
    # Set GitHub Actions output if running in CI
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"status={'passed' if overall_passed else 'failed'}\n")
    
    # Exit with appropriate code
    sys.exit(0 if overall_passed else 1)


if __name__ == '__main__':
    import os
    main()