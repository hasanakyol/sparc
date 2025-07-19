#!/usr/bin/env python3
"""
Security Report Generator
Consolidates vulnerability scan results into a comprehensive report
"""

import json
import argparse
import os
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Dict, List, Any
import html
import glob

class SecurityReportGenerator:
    def __init__(self):
        self.vulnerabilities = []
        self.summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        self.by_scanner = {}
        self.by_type = {}
        self.scan_results = {}
        
    def parse_npm_audit(self, filepath: str):
        """Parse npm audit JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            if 'vulnerabilities' in data:
                for vuln_name, vuln_data in data['vulnerabilities'].items():
                    severity = vuln_data.get('severity', 'unknown')
                    self.add_vulnerability({
                        'scanner': 'npm-audit',
                        'type': 'dependency',
                        'severity': severity,
                        'title': f"{vuln_name} - {vuln_data.get('title', 'Unknown vulnerability')}",
                        'description': vuln_data.get('overview', ''),
                        'package': vuln_name,
                        'version': vuln_data.get('range', ''),
                        'fix': vuln_data.get('fixAvailable', {}).get('name', 'No fix available'),
                        'cve': vuln_data.get('cves', []),
                        'url': vuln_data.get('url', '')
                    })
        except Exception as e:
            print(f"Error parsing npm audit report: {e}")
    
    def parse_snyk_report(self, filepath: str):
        """Parse Snyk JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            for vuln in data.get('vulnerabilities', []):
                self.add_vulnerability({
                    'scanner': 'snyk',
                    'type': 'dependency',
                    'severity': vuln.get('severity', 'unknown'),
                    'title': vuln.get('title', 'Unknown vulnerability'),
                    'description': vuln.get('description', ''),
                    'package': vuln.get('packageName', ''),
                    'version': vuln.get('version', ''),
                    'fix': vuln.get('fixedIn', ['No fix available'])[0] if vuln.get('fixedIn') else 'No fix available',
                    'cve': vuln.get('identifiers', {}).get('CVE', []),
                    'cvss_score': vuln.get('cvssScore', 0),
                    'exploit_maturity': vuln.get('exploitMaturity', 'unknown')
                })
        except Exception as e:
            print(f"Error parsing Snyk report: {e}")
    
    def parse_trivy_sarif(self, filepath: str):
        """Parse Trivy SARIF report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    rule = next((r for r in run.get('tool', {}).get('driver', {}).get('rules', []) 
                               if r['id'] == result['ruleId']), {})
                    
                    severity_map = {
                        'error': 'critical',
                        'warning': 'high',
                        'note': 'medium',
                        'none': 'low'
                    }
                    
                    severity = severity_map.get(result.get('level', 'none'), 'unknown')
                    
                    self.add_vulnerability({
                        'scanner': 'trivy',
                        'type': 'container',
                        'severity': severity,
                        'title': rule.get('shortDescription', {}).get('text', result.get('message', {}).get('text', '')),
                        'description': rule.get('fullDescription', {}).get('text', ''),
                        'package': result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', ''),
                        'cve': result.get('ruleId', ''),
                        'fix': rule.get('help', {}).get('text', 'No fix available')
                    })
        except Exception as e:
            print(f"Error parsing Trivy SARIF report: {e}")
    
    def parse_dependency_check_xml(self, filepath: str):
        """Parse OWASP Dependency Check XML report"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            ns = {'dc': 'https://jeremylong.github.io/DependencyCheck/dependency-check.xsd'}
            
            for dependency in root.findall('.//dc:dependency', ns):
                for vulnerability in dependency.findall('.//dc:vulnerability', ns):
                    severity = vulnerability.find('dc:severity', ns).text if vulnerability.find('dc:severity', ns) is not None else 'unknown'
                    
                    self.add_vulnerability({
                        'scanner': 'dependency-check',
                        'type': 'dependency',
                        'severity': severity.lower(),
                        'title': vulnerability.find('dc:name', ns).text if vulnerability.find('dc:name', ns) is not None else 'Unknown',
                        'description': vulnerability.find('dc:description', ns).text if vulnerability.find('dc:description', ns) is not None else '',
                        'package': dependency.find('dc:fileName', ns).text if dependency.find('dc:fileName', ns) is not None else '',
                        'cve': vulnerability.find('dc:name', ns).text if vulnerability.find('dc:name', ns) is not None else '',
                        'cvss_score': float(vulnerability.find('dc:cvssV3/dc:baseScore', ns).text) if vulnerability.find('dc:cvssV3/dc:baseScore', ns) is not None else 0,
                        'cwe': vulnerability.find('dc:cwe', ns).text if vulnerability.find('dc:cwe', ns) is not None else ''
                    })
        except Exception as e:
            print(f"Error parsing Dependency Check XML report: {e}")
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add vulnerability to the report"""
        self.vulnerabilities.append(vuln)
        
        # Update summary
        severity = vuln.get('severity', 'unknown').lower()
        if severity in self.summary:
            self.summary[severity] += 1
        
        # Update by scanner
        scanner = vuln.get('scanner', 'unknown')
        if scanner not in self.by_scanner:
            self.by_scanner[scanner] = 0
        self.by_scanner[scanner] += 1
        
        # Update by type
        vuln_type = vuln.get('type', 'unknown')
        if vuln_type not in self.by_type:
            self.by_type[vuln_type] = 0
        self.by_type[vuln_type] += 1
    
    def generate_html_report(self, output_path: str, include_recommendations: bool = True):
        """Generate HTML security report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SPARC Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .summary-item {{ text-align: center; padding: 20px; border-radius: 5px; }}
        .critical {{ background-color: #f8d7da; color: #721c24; }}
        .high {{ background-color: #fff3cd; color: #856404; }}
        .medium {{ background-color: #cce5ff; color: #004085; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
        .info {{ background-color: #d4edda; color: #155724; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .vulnerability h3 {{ margin-top: 0; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .chart {{ margin: 20px 0; }}
        .recommendations {{ background-color: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .recommendations ul {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SPARC Security Scan Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {len(self.vulnerabilities)}</p>
        
        <h2>📊 Summary</h2>
        <div class="summary">
            <div class="summary-item critical">
                <h3>{self.summary['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-item high">
                <h3>{self.summary['high']}</h3>
                <p>High</p>
            </div>
            <div class="summary-item medium">
                <h3>{self.summary['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-item low">
                <h3>{self.summary['low']}</h3>
                <p>Low</p>
            </div>
            <div class="summary-item info">
                <h3>{self.summary['info']}</h3>
                <p>Info</p>
            </div>
        </div>
        
        <h2>📈 Statistics</h2>
        <table>
            <tr>
                <th>Scanner</th>
                <th>Vulnerabilities Found</th>
            </tr>
            {''.join(f'<tr><td>{scanner}</td><td>{count}</td></tr>' for scanner, count in self.by_scanner.items())}
        </table>
        
        <table>
            <tr>
                <th>Type</th>
                <th>Count</th>
            </tr>
            {''.join(f'<tr><td>{vuln_type}</td><td>{count}</td></tr>' for vuln_type, count in self.by_type.items())}
        </table>
        """
        
        if include_recommendations:
            html_content += self.generate_recommendations()
        
        # Add vulnerability details
        html_content += """
        <h2>🔍 Vulnerability Details</h2>
        """
        
        # Sort vulnerabilities by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x.get('severity', '').lower(), 5))
        
        for vuln in sorted_vulns:
            severity_class = vuln.get('severity', 'unknown').lower()
            html_content += f"""
            <div class="vulnerability {severity_class}">
                <h3>{html.escape(vuln.get('title', 'Unknown'))}</h3>
                <div class="meta">
                    <strong>Scanner:</strong> {vuln.get('scanner', 'unknown')} | 
                    <strong>Type:</strong> {vuln.get('type', 'unknown')} | 
                    <strong>Severity:</strong> {vuln.get('severity', 'unknown')}
                    {f" | <strong>CVSS:</strong> {vuln.get('cvss_score', 'N/A')}" if vuln.get('cvss_score') else ''}
                    {f" | <strong>CVE:</strong> {vuln.get('cve', 'N/A')}" if vuln.get('cve') else ''}
                </div>
                <p><strong>Package/Component:</strong> {html.escape(str(vuln.get('package', 'Unknown')))}</p>
                <p><strong>Description:</strong> {html.escape(vuln.get('description', 'No description available'))}</p>
                <p><strong>Fix/Mitigation:</strong> {html.escape(str(vuln.get('fix', 'No fix available')))}</p>
            </div>
            """
        
        html_content += """
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def generate_recommendations(self) -> str:
        """Generate security recommendations based on findings"""
        recommendations = """
        <div class="recommendations">
            <h2>🚀 Recommendations</h2>
        """
        
        if self.summary['critical'] > 0:
            recommendations += """
            <h3>⚠️ Critical Actions Required</h3>
            <ul>
                <li>Immediately address all critical vulnerabilities</li>
                <li>Consider rolling back recent deployments if critical vulnerabilities were introduced</li>
                <li>Implement emergency patching procedures</li>
                <li>Notify security team and management</li>
            </ul>
            """
        
        if self.summary['high'] > 0:
            recommendations += """
            <h3>🔴 High Priority Actions</h3>
            <ul>
                <li>Schedule immediate fixes for high severity vulnerabilities</li>
                <li>Update all vulnerable dependencies to patched versions</li>
                <li>Review and update security policies</li>
                <li>Implement additional security controls where needed</li>
            </ul>
            """
        
        # General recommendations
        recommendations += """
            <h3>📋 General Security Improvements</h3>
            <ul>
                <li>Implement automated dependency updates using Dependabot or Renovate</li>
                <li>Add security scanning to CI/CD pipeline as a blocking step</li>
                <li>Conduct regular security training for development team</li>
                <li>Implement a vulnerability disclosure program</li>
                <li>Regularly review and update security dependencies</li>
                <li>Consider implementing a Software Bill of Materials (SBOM)</li>
                <li>Enable GitHub Advanced Security features</li>
            </ul>
            
            <h3>🛡️ Defense in Depth</h3>
            <ul>
                <li>Implement Web Application Firewall (WAF) rules</li>
                <li>Enable runtime application self-protection (RASP)</li>
                <li>Use container image signing and verification</li>
                <li>Implement least privilege access controls</li>
                <li>Enable comprehensive logging and monitoring</li>
            </ul>
        </div>
        """
        
        return recommendations
    
    def generate_json_report(self, output_path: str):
        """Generate JSON security report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.summary,
            'by_scanner': self.by_scanner,
            'by_type': self.by_type,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'scan_results': self.scan_results
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def generate_markdown_report(self, output_path: str, include_recommendations: bool = True):
        """Generate Markdown security report"""
        md_content = f"""# 🛡️ SPARC Security Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Total Vulnerabilities Found:** {len(self.vulnerabilities)}

## 📊 Summary

| Severity | Count |
|----------|-------|
| Critical | {self.summary['critical']} |
| High     | {self.summary['high']} |
| Medium   | {self.summary['medium']} |
| Low      | {self.summary['low']} |
| Info     | {self.summary['info']} |

## 📈 Vulnerabilities by Scanner

| Scanner | Count |
|---------|-------|
"""
        for scanner, count in self.by_scanner.items():
            md_content += f"| {scanner} | {count} |\n"
        
        md_content += """
## 🔍 Vulnerabilities by Type

| Type | Count |
|------|-------|
"""
        for vuln_type, count in self.by_type.items():
            md_content += f"| {vuln_type} | {count} |\n"
        
        if include_recommendations and (self.summary['critical'] > 0 or self.summary['high'] > 0):
            md_content += """
## 🚀 Recommendations

"""
            if self.summary['critical'] > 0:
                md_content += """### ⚠️ Critical Actions Required

- Immediately address all critical vulnerabilities
- Consider rolling back recent deployments if critical vulnerabilities were introduced
- Implement emergency patching procedures
- Notify security team and management

"""
            
            if self.summary['high'] > 0:
                md_content += """### 🔴 High Priority Actions

- Schedule immediate fixes for high severity vulnerabilities
- Update all vulnerable dependencies to patched versions
- Review and update security policies
- Implement additional security controls where needed

"""
        
        # Add top vulnerabilities
        if self.vulnerabilities:
            md_content += """## 🎯 Top Vulnerabilities

"""
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
            sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x.get('severity', '').lower(), 5))
            
            # Show top 10
            for i, vuln in enumerate(sorted_vulns[:10], 1):
                severity = vuln.get('severity', 'unknown').upper()
                md_content += f"""### {i}. {severity} - {vuln.get('title', 'Unknown')}

- **Scanner:** {vuln.get('scanner', 'unknown')}
- **Type:** {vuln.get('type', 'unknown')}
- **Package:** {vuln.get('package', 'Unknown')}
- **Description:** {vuln.get('description', 'No description available')}
- **Fix:** {vuln.get('fix', 'No fix available')}

---

"""
        
        with open(output_path, 'w') as f:
            f.write(md_content)
    
    def parse_sarif_generic(self, filepath: str, scanner_name: str = None):
        """Parse generic SARIF format files"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if not scanner_name:
                # Try to detect scanner from tool name
                scanner_name = 'unknown'
                if 'runs' in data and len(data['runs']) > 0:
                    tool_name = data['runs'][0].get('tool', {}).get('driver', {}).get('name', '').lower()
                    scanner_name = tool_name if tool_name else 'unknown'
            
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    rule = next((r for r in run.get('tool', {}).get('driver', {}).get('rules', []) 
                               if r['id'] == result.get('ruleId', '')), {})
                    
                    severity_map = {
                        'error': 'critical',
                        'warning': 'high',
                        'note': 'medium',
                        'none': 'low'
                    }
                    
                    level = result.get('level', 'none')
                    severity = severity_map.get(level, 'medium')
                    
                    # Get location information
                    location = 'Unknown'
                    line = 'Unknown'
                    if result.get('locations'):
                        loc = result['locations'][0]
                        if 'physicalLocation' in loc:
                            phys_loc = loc['physicalLocation']
                            if 'artifactLocation' in phys_loc:
                                location = phys_loc['artifactLocation'].get('uri', 'Unknown')
                            if 'region' in phys_loc:
                                line = phys_loc['region'].get('startLine', 'Unknown')
                    
                    self.add_vulnerability({
                        'scanner': scanner_name,
                        'type': 'code' if 'semgrep' in scanner_name or 'codeql' in scanner_name else 'unknown',
                        'severity': severity,
                        'title': result.get('message', {}).get('text', rule.get('shortDescription', {}).get('text', 'Unknown')),
                        'description': rule.get('fullDescription', {}).get('text', result.get('message', {}).get('text', '')),
                        'file': location,
                        'line': line,
                        'rule_id': result.get('ruleId', 'Unknown'),
                        'recommendation': rule.get('help', {}).get('text', 'Review and fix the issue')
                    })
                    
            self.scan_results[scanner_name] = {'status': 'completed', 'vulnerabilities_found': self.by_scanner.get(scanner_name, 0)}
                    
        except Exception as e:
            print(f"Error parsing SARIF file {filepath}: {e}")
            self.scan_results[scanner_name] = {'status': 'failed', 'error': str(e)}

def main():
    parser = argparse.ArgumentParser(description='Generate consolidated security report')
    parser.add_argument('--input-dir', help='Input directory containing scan results')
    parser.add_argument('--output-dir', help='Output directory for reports')
    parser.add_argument('--output', help='Output file path (deprecated, use --output-dir)')
    parser.add_argument('--format', action='append', choices=['html', 'json', 'markdown'], 
                        help='Output format(s), can be specified multiple times')
    parser.add_argument('--include-recommendations', action='store_true', help='Include recommendations')
    
    args = parser.parse_args()
    
    # Handle backward compatibility
    if args.output and not args.output_dir:
        args.output_dir = os.path.dirname(args.output) or '.'
        if not args.format:
            # Guess format from extension
            ext = os.path.splitext(args.output)[1].lower()
            if ext == '.html':
                args.format = ['html']
            elif ext == '.json':
                args.format = ['json']
            elif ext == '.md':
                args.format = ['markdown']
            else:
                args.format = ['html']
    
    # Default values
    if not args.format:
        args.format = ['html']
    if not args.output_dir:
        args.output_dir = '.'
    if not args.input_dir:
        args.input_dir = '.'
    
    # Create output directory if needed
    os.makedirs(args.output_dir, exist_ok=True)
    
    generator = SecurityReportGenerator()
    
    # Parse all available reports from input directory
    input_path = Path(args.input_dir)
    
    # Parse npm audit reports
    for npm_audit in input_path.rglob('npm-audit*.json'):
        print(f"Parsing {npm_audit}")
        generator.parse_npm_audit(str(npm_audit))
    
    # Parse Snyk reports
    for snyk_report in input_path.rglob('snyk*.json'):
        if 'sarif' not in str(snyk_report):
            print(f"Parsing {snyk_report}")
            generator.parse_snyk_report(str(snyk_report))
    
    # Parse Dependency Check reports
    for dep_check in input_path.rglob('dependency-check-report.xml'):
        print(f"Parsing {dep_check}")
        generator.parse_dependency_check_xml(str(dep_check))
    
    # Parse SARIF files
    sarif_files = list(input_path.rglob('*.sarif'))
    for sarif_file in sarif_files:
        filename = os.path.basename(str(sarif_file)).lower()
        print(f"Parsing SARIF: {sarif_file}")
        
        if 'trivy' in filename:
            generator.parse_trivy_sarif(str(sarif_file))
        elif 'semgrep' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'semgrep')
        elif 'eslint' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'eslint-security')
        elif 'codeql' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'codeql')
        elif 'snyk' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'snyk')
        elif 'npm-audit' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'npm-audit')
        elif 'checkov' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'checkov')
        elif 'hadolint' in filename:
            generator.parse_sarif_generic(str(sarif_file), 'hadolint')
        else:
            # Try to parse as generic SARIF
            generator.parse_sarif_generic(str(sarif_file))
    
    # Generate reports in all requested formats
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    generated_files = []
    
    for fmt in args.format:
        if fmt == 'html':
            output_file = os.path.join(args.output_dir, f'report.html')
            generator.generate_html_report(output_file, args.include_recommendations)
            generated_files.append(output_file)
        elif fmt == 'json':
            output_file = os.path.join(args.output_dir, f'report.json')
            generator.generate_json_report(output_file)
            generated_files.append(output_file)
        elif fmt == 'markdown':
            output_file = os.path.join(args.output_dir, f'report.md')
            generator.generate_markdown_report(output_file, args.include_recommendations)
            generated_files.append(output_file)
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY SCAN REPORT SUMMARY")
    print("="*60)
    print(f"Generated reports: {', '.join(generated_files)}")
    print(f"Total vulnerabilities found: {len(generator.vulnerabilities)}")
    print(f"Critical: {generator.summary['critical']}")
    print(f"High: {generator.summary['high']}")
    print(f"Medium: {generator.summary['medium']}")
    print(f"Low: {generator.summary['low']}")
    print(f"Info: {generator.summary['info']}")
    print("="*60)

if __name__ == '__main__':
    main()