import os
import json
import datetime
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from jinja2 import Template
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import base64
import io
from vulnerability_assessment import VulnerabilityAssessment

class ScanReport:
    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.console = Console()
        self.start_time = scan_data.get('start_time', datetime.datetime.now())
        self.end_time = scan_data.get('end_time', datetime.datetime.now())
        self.duration = self.end_time - self.start_time
        self.target_url = scan_data.get('target_url', '')
        self.vulnerability_assessor = VulnerabilityAssessment()
        self.vulnerabilities = [self.vulnerability_assessor.assess_vulnerability(v) for v in scan_data.get('vulnerabilities', [])]
        self.endpoints_tested = scan_data.get('endpoints_tested', [])
        self.scan_coverage = scan_data.get('scan_coverage', {})

    def _get_severity_color(self, severity: str) -> str:
        severity_colors = {
            'critical': 'red',
            'high': 'bright_red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        return severity_colors.get(severity.lower(), 'white')

    def _categorize_vulnerabilities(self) -> Dict:
        categories = {
            'injection': [],
            'authentication': [],
            'data_exposure': [],
            'xxe': [],
            'access_control': [],
            'security_misconfig': [],
            'xss': [],
            'deserialization': [],
            'components': [],
            'logging': []
        }
        
        for vuln in self.vulnerabilities:
            category = self._determine_category(vuln['type'])
            categories[category].append(vuln)
            
        return categories
        
    def _determine_category(self, vuln_type: str) -> str:
        type_lower = vuln_type.lower()
        if any(x in type_lower for x in ['sql', 'command', 'ldap']):
            return 'injection'
        elif any(x in type_lower for x in ['auth', 'session', 'credential']):
            return 'authentication'
        elif any(x in type_lower for x in ['exposure', 'disclosure', 'leak']):
            return 'data_exposure'
        elif 'xxe' in type_lower:
            return 'xxe'
        elif any(x in type_lower for x in ['rbac', 'idor', 'access']):
            return 'access_control'
        elif any(x in type_lower for x in ['config', 'setup', 'default']):
            return 'security_misconfig'
        elif 'xss' in type_lower:
            return 'xss'
        elif any(x in type_lower for x in ['deserial', 'serial']):
            return 'deserialization'
        elif any(x in type_lower for x in ['component', 'dependency', 'library']):
            return 'components'
        elif any(x in type_lower for x in ['log', 'monitor', 'audit']):
            return 'logging'
        return 'security_misconfig'  # default category

    def _generate_severity_chart(self) -> str:
        """Generate a base64 encoded chart for vulnerability severity distribution"""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            severity_counts[severity] += 1
            
        plt.figure(figsize=(8, 6))
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        colors = ['#ff0000', '#ff4500', '#ffa500', '#00cc00', '#0000ff']
        explode = (0.1, 0.05, 0, 0, 0)
        
        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')
        plt.title('Vulnerability Severity Distribution')
        
        # Convert plot to base64 string
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close()
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _generate_binary_chart(self) -> str:
        """Generate a base64 encoded chart for binary analysis results""\
        binary_data = self.scan_data.get('binary_analysis', [])
        if not binary_data:
            return ""
            
        # Count risk levels
        risk_counts = {'high': 0, 'medium': 0, 'low': 0, 'safe': 0}
        for binary in binary_data:
            risk_level = binary.get('risk_level', 'safe')
            risk_counts[risk_level] += 1
            
        # Create pie chart
        plt.figure(figsize=(8, 6))
        labels = list(risk_counts.keys())
        sizes = list(risk_counts.values())
        colors = ['#ff4500', '#ffa500', '#ffff00', '#00cc00']
        explode = (0.1, 0, 0, 0)  # explode the 1st slice (high risk)
        
        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=140)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.title('Binary Files Risk Distribution')
        
        # Convert plot to base64 string
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img_str = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        
        return img_str
        
    def _create_html_report(self) -> str:
        # Generate binary chart if data is available
        binary_chart = self._generate_binary_chart()
        
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {{ target_url }}</title>
            <style>
                :root {
                    --primary-color: #2196F3;
                    --critical-color: #ff0000;
                    --high-color: #ff4500;
                    --medium-color: #ffa500;
                    --low-color: #ffff00;
                    --no-vuln-color: #00cc00;
                    --info-color: #2196F3;
                }
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background: #f5f5f5;
                    color: #333;
                    line-height: 1.6;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 40px 20px;
                }
                .header { 
                    background: linear-gradient(135deg, var(--primary-color), #1976D2);
                    color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }
                .header h1 {
                    margin: 0 0 20px 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }
                .header p {
                    margin: 10px 0;
                    font-size: 1.1em;
                    opacity: 0.9;
                }
                .section {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    margin-bottom: 30px;
                }
                .section h2 {
                    color: var(--primary-color);
                    margin-top: 0;
                    font-weight: 500;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }
                .vulnerability { 
                    margin: 20px 0;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 5px solid;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                .critical { 
                    background: rgba(255,0,0,0.1);
                    border-left-color: var(--critical-color);
                }
                .high { 
                    background: rgba(255,69,0,0.1);
                    border-left-color: var(--high-color);
                }
                .medium { 
                    background: rgba(255,165,0,0.1);
                    border-left-color: var(--medium-color);
                }
                .low { 
                    background: rgba(255,255,0,0.1);
                    border-left-color: var(--low-color);
                }
                .no-vulnerabilities {
                    background: rgba(0,204,0,0.1);
                    border-left: 5px solid var(--no-vuln-color);
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    text-align: center;
                    font-weight: bold;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                .vulnerability h3 {
                    margin: 0 0 15px 0;
                    color: #333;
                }
                .vulnerability p {
                    margin: 10px 0;
                }
                .vulnerability strong {
                    color: #555;
                }
                table { 
                    width: 100%;
                    border-collapse: separate;
                    border-spacing: 0;
                    margin: 20px 0;
                    background: white;
                    border-radius: 8px;
                    overflow: hidden;
                }
                th { 
                    background: var(--primary-color);
                    color: white;
                    padding: 15px;
                    text-align: left;
                    font-weight: 500;
                }
                td { 
                    padding: 12px 15px;
                    border-bottom: 1px solid #eee;
                }
                tr:last-child td {
                    border-bottom: none;
                }
                tr:hover td {
                    background: #f8f9fa;
                }
                .binary-file {
                    margin: 15px 0;
                    padding: 15px;
                    border-radius: 8px;
                    border: 1px solid #eee;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                }
                .binary-file h4 {
                    margin: 0 0 10px 0;
                    color: #333;
                }
                .binary-file-high {
                    border-left: 5px solid var(--high-color);
                }
                .binary-file-medium {
                    border-left: 5px solid var(--medium-color);
                }
                .binary-file-low {
                    border-left: 5px solid var(--low-color);
                }
                .binary-file-safe {
                    border-left: 5px solid var(--no-vuln-color);
                }
                .binary-stats {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 15px;
                    margin-bottom: 20px;
                }
                .stat-card {
                    flex: 1;
                    min-width: 200px;
                    padding: 15px;
                    border-radius: 8px;
                    background: #f8f9fa;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                }
                .chart-container {
                    margin: 30px 0;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Scan Report</h1>
                    <p>Target: {{ target_url }}</p>
                    <p>Scan Date: {{ start_time }}</p>
                    <p>Duration: {{ duration }}</p>
                </div>
                
                <div class="section">
                    <h2>Vulnerabilities Summary</h2>
                    {% set vuln_count = vulnerabilities|length %}
                    {% if vuln_count > 0 %}
                        <p>Found {{ vuln_count }} vulnerabilities in this scan.</p>
                        
                        {% for vuln in vulnerabilities %}
                            <div class="vulnerability {{ vuln.severity|lower }}">
                                <h3>{{ vuln.type }}</h3>
                                <p><strong>Severity:</strong> {{ vuln.severity }}</p>
                                <p><strong>URL:</strong> {{ vuln.url }}</p>
                                <p><strong>Details:</strong> {{ vuln.details }}</p>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="no-vulnerabilities">
                            No vulnerabilities were found in this scan.
                        </div>
                    {% endif %}
                </div>
                
                <div class="section">
                    <h2>Scan Coverage</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Test Type</th>
                                <th>Endpoints Tested</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for test, details in scan_coverage.items() %}
                                <tr>
                                    <td>{{ test }}</td>
                                    <td>{{ details.endpoints }}</td>
                                    <td>{{ details.status }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                {% if binary_chart %}
                <div class="section">
                    <h2>Binary Analysis</h2>
                    <div class="chart-container">
                        <img src="data:image/png;base64,{{ binary_chart }}" alt="Binary Risk Distribution" />
                    </div>
                </div>
                {% endif %}
            </div>
        </body>
        </html>
        """)

        return template.render(
            target_url=self.target_url,
            start_time=self.start_time,
            duration=self.duration,
            vulnerabilities=self.vulnerabilities,
            scan_coverage=self.scan_coverage,
            binary_chart=binary_chart
        )

    def _create_json_report(self) -> str:
        report_data = {
            'scan_info': {
                'target_url': self.target_url,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': str(self.duration)
            },
            'vulnerabilities': self.vulnerabilities,
            'scan_coverage': self.scan_coverage,
            'endpoints_tested': self.endpoints_tested
        }
        return json.dumps(report_data, indent=2)

    def _create_markdown_report(self) -> str:
        md_report = f"# Security Scan Report\n\n"
        md_report += f"## Scan Information\n"
        md_report += f"- **Target URL:** {self.target_url}\n"
        md_report += f"- **Scan Date:** {self.start_time}\n"
        md_report += f"- **Duration:** {self.duration}\n\n"

        md_report += f"## Vulnerabilities Found\n\n"
        for vuln in self.vulnerabilities:
            md_report += f"### {vuln['type']}\n"
            md_report += f"- **Severity:** {vuln['severity']}\n"
            md_report += f"- **URL:** {vuln['url']}\n"
            md_report += f"- **Details:** {vuln['details']}\n\n"

        md_report += f"## Scan Coverage\n\n"
        md_report += f"| Test Type | Endpoints Tested | Status |\n"
        md_report += f"|-----------|-----------------|--------|\n"
        for test, details in self.scan_coverage.items():
            md_report += f"| {test} | {details['endpoints']} | {details['status']} |\n"

        return md_report

    def generate_report(self, format: str = 'html') -> str:
        reports_dir = Path('Reports')
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_report_{timestamp}"

        if format.lower() == 'html':
            report_content = self._create_html_report()
            file_path = reports_dir / f"{filename}.html"
        elif format.lower() == 'json':
            report_content = self._create_json_report()
            file_path = reports_dir / f"{filename}.json"
        elif format.lower() == 'md':
            report_content = self._create_markdown_report()
            file_path = reports_dir / f"{filename}.md"
        else:
            raise ValueError(f"Unsupported report format: {format}")

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        self.console.print(f"[green]Report generated successfully: {file_path}[/green]")
        return str(file_path)