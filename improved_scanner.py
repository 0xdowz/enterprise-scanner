import asyncio
import aiohttp
import argparse
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, track
from rich.markdown import Markdown
from rich.panel import Panel
import yaml
import json
import signal
import jwt
import re
import hashlib
import random
import string
import os
import time
from datetime import datetime
from cryptography.fernet import Fernet
from typing import Dict, List, Optional, AsyncGenerator, Set, Tuple, Any
import xml.etree.ElementTree as ET
import dns.resolver
import tldextract
from faker import Faker
from aiohttp_socks import ProxyConnector
import numpy as np
from sklearn.ensemble import IsolationForest

# Import base modules
from base_scanner import BaseScanner
from threat_intelligence import ThreatIntelligence
from ai_anomaly_detector import AIAnomalyDetector

# Import enhanced modules
from enhanced_binary_detection import EnhancedBinaryDetector
from enhanced_ssti_detection import EnhancedSSTIDetector

# Initialize rich console
console = Console()

# Advanced configuration
VERSION = "1.6.0"
BANNER = f"""
[bold gradient(45,red,purple)]

     █████╗ ██╗    ██╗███████╗
    ██╔══██╗██║    ██║██╔════╝
    ███████║██║ █╗ ██║███████╗
    ██╔══██║██║███╗██║╚════██║
    ██║  ██║╚███╔███╔╝███████║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
[/bold gradient(45,red,purple)] Version: {VERSION} | Enterprise Web Security Scanner
[bold blue] BY: 0xdowz | GitHub: https://github.com/0xdowz [/bold blue]
"""

class ImprovedScanner(BaseScanner, ThreatIntelligence, AIAnomalyDetector):
    """Improved scanner with enhanced detection capabilities"""
    
    def __init__(self, config: Dict):
        # Initialize parent classes
        BaseScanner.__init__(self, config)
        ThreatIntelligence.__init__(self)
        AIAnomalyDetector.__init__(self)
        
        # Store configuration
        self.config = config
        self.target = config.get('target', '')
        self.scan_mode = config.get('scan_mode', 'full')
        self.output_format = config.get('output_format', 'html')
        self.evasion = config.get('evasion', False)
        self.use_tor = config.get('tor', False)
        
        # Initialize session and state variables
        self.session = None
        self.lock = asyncio.Lock()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.request_count = 0
        self.start_time = datetime.now()
        self.end_time = None
        
        # Initialize enhanced modules
        self.binary_detector = EnhancedBinaryDetector()
        self.ssti_detector = EnhancedSSTIDetector()
        
        # Initialize encryption for secure data handling
        self.crypto = Fernet(config.get('encryption_key', Fernet.generate_key()))
        
        # Initialize faker for evasion techniques
        self.faker = Faker()
        
        # Load payloads from file
        self.payloads = self.load_payloads()
        
        # Rate limiting semaphore
        self.rate_limit_sem = asyncio.Semaphore(config.get('rate_limit', 50))
        
        # Scan statistics
        self.scan_stats = {
            'total_urls': 0,
            'binary_files': 0,
            'vulnerabilities': 0,
            'scan_duration': 0,
            'start_time': self.start_time.isoformat(),
            'end_time': None
        }
    
    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        if not self.evasion:
            return {
                'User-Agent': 'AWS Enterprise Scanner/{}'.format(VERSION),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        
        # Enhanced evasion with more randomized headers
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'Accept-Encoding': 'gzip, deflate',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url(),
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Pragma': 'no-cache',
            'DNT': '1',
            'Connection': random.choice(['keep-alive', 'close']),
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1'
        }
    
    async def init_session(self):
        """Initialize HTTP session with advanced configuration"""
        # Configure connector based on Tor usage
        if self.use_tor:
            try:
                connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
                console.print("[green]Using Tor network for anonymous scanning[/green]")
            except Exception as e:
                console.print(f"[red]Error connecting to Tor: {str(e)}[/red]")
                console.print("[yellow]Falling back to direct connection[/yellow]")
                connector = aiohttp.TCPConnector(limit=100, ssl=False)
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        # Create session with configured headers and timeout
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
    
    def load_payloads(self):
        """Load payloads from YAML file"""
        try:
            payloads_file = self.config.get('payloads_file', 'advanced_payloads.yaml')
            with open(payloads_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            console.print(f"[red]Error loading payloads: {str(e)}[/red]")
            console.print("[yellow]Using default payloads[/yellow]")
            return {}
    
    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints with enhanced detection"""
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

            # Check if URL points to an image or other binary file
            skip_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', 
                              '.pdf', '.zip', '.rar', '.gz', '.tar', '.7z', '.exe', '.dll')
            if url.lower().endswith(skip_extensions):
                console.print(f"[yellow]Skipping binary file: {url}[/yellow]")
                return

            console.print(f"[cyan]Starting crawl of {url}...[/cyan]")
            
            # Use rate limiting semaphore
            async with self.rate_limit_sem:
                async with self.session.get(url, allow_redirects=True) as resp:
                    self.request_count += 1
                    
                    # Handle different response status codes
                    if resp.status == 404:
                        console.print(f"[red]Error: Page not found (404) at {url}[/red]")
                        return
                    elif resp.status == 403:
                        console.print(f"[red]Error: Access forbidden (403) at {url}[/red]")
                        return
                    elif resp.status == 429:
                        console.print(f"[red]Error: Rate limited (429) at {url}[/red]")
                        console.print("[yellow]Waiting before continuing...[/yellow]")
                        await asyncio.sleep(5)  # Wait before continuing
                        return
                    elif resp.status == 200:
                        # Check content type for binary files
                        content_type = resp.headers.get('content-type', '').lower()
                        
                        # Skip images and other binary content
                        if content_type.startswith(('image/', 'application/pdf', 'application/zip', 'application/x-rar')):
                            console.print(f"[yellow]Skipping binary content: {url}[/yellow]")
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
                                    'payload': 'N/A',
                                    'details': f"Binary file detected with risks: {', '.join(r['description'] for r in analysis['risks'])}"
                                })
                            return

                        # Process HTML content
                        text = await resp.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        
                        # Extract all links
                        for link in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe', 'frame', 'area']):
                            href = link.get('href') or link.get('src') or link.get('action') or link.get('data-url')
                            if href:
                                try:
                                    full_url = urljoin(url, href)
                                    # Skip if the URL is a binary file
                                    if full_url.lower().endswith(skip_extensions):
                                        continue
                                    
                                    # Only process URLs from the same domain
                                    parsed = urlparse(full_url)
                                    if parsed.netloc == parsed_url.netloc:  # Better domain matching
                                        if full_url not in self.discovered_urls:
                                            self.discovered_urls.add(full_url)
                                            self.scan_stats['total_urls'] += 1
                                            console.print(f"[green]Found endpoint: {full_url}[/green]")
                                except Exception as e:
                                    console.print(f"[yellow]Error processing URL {href}: {str(e)}[/yellow]")
                        
                        # Also look for URLs in JavaScript code
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if script.string:
                                # Find URLs in JavaScript using regex
                                js_urls = re.findall(r'["\']((https?://|/)\S+)["\']', script.string)
                                for js_url in js_urls:
                                    try:
                                        full_url = urljoin(url, js_url[0])
                                        parsed = urlparse(full_url)
                                        if parsed.netloc == parsed_url.netloc and full_url not in self.discovered_urls:
                                            self.discovered_urls.add(full_url)
                                            self.scan_stats['total_urls'] += 1
                                            console.print(f"[green]Found endpoint in JavaScript: {full_url}[/green]")
                                    except Exception as e:
                                        pass
                        
                        # Check for potential API endpoints
                        api_patterns = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '/query', '/service']
                        for pattern in api_patterns:
                            if pattern in url:
                                console.print(f"[blue]Potential API endpoint detected: {url}[/blue]")
                        
                        if not self.discovered_urls:
                            console.print("[yellow]Warning: No endpoints discovered. The target might be blocking crawling attempts.[/yellow]")
                        
                    else:
                        console.print(f"[red]Error: Received status code {resp.status} from {url}[/red]")
        except aiohttp.ClientError as e:
            console.print(f"[red]Network error while crawling {url}: {str(e)}[/red]")
        except Exception as e:
            console.print(f"[red]Unexpected error crawling {url}: {str(e)}[/red]")
    
    async def _analyze_binary_response(self, url: str, content: bytes) -> Dict:
        """Analyze binary content from response using enhanced binary detection"""
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
            
        # Record end time and duration
        self.end_time = datetime.now()
        self.scan_stats['end_time'] = self.end_time.isoformat()
        self.scan_stats['scan_duration'] = (self.end_time - self.start_time).total_seconds()
        
        console.print(f"[green]Scan completed in {self.scan_stats['scan_duration']:.2f} seconds[/green]")
    
    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection using enhanced detection"""
        console.print(f"[cyan]Testing SSTI vulnerabilities on {url}...[/cyan]")
        
        try:
            # Use the enhanced SSTI detector
            result = await self.ssti_detector.scan_url(self.session, url)
            
            if result['vulnerable']:
                severity = result['severity']
                details = result['details']
                
                # Get the first payload from results for reporting
                payload = "Multiple payloads"
                if result.get('results') and len(result['results']) > 0:
                    first_result = result['results'][0]
                    if 'payload' in first_result:
                        payload = first_result['payload']
                
                await self.report_vulnerability(
                    'Server-Side Template Injection',
                    url,
                    payload,
                    details
                )
                
                # If critical severity, log additional warning
                if severity == 'critical':
                    console.print(f"[bold red]CRITICAL: Remote Code Execution possible via SSTI at {url}[/bold red]")
        
        except Exception as e:
            console.print(f"[yellow]Error during SSTI testing on {url}: {str(e)}[/yellow]")
    
    async def check_deserialization(self, url: str):
        """Check for insecure deserialization vulnerabilities"""
        console.print(f"[cyan]Testing deserialization vulnerabilities on {url}...[/cyan]")
        
        # Common serialization formats and their markers
        serialization_tests = [
            # Java
            {
                'name': 'Java Serialization',
                'payload': b'\xac\xed\x00\x05',  # Java serialization header
                'content_type': 'application/x-java-serialized-object',
                'markers': ['java.io.', 'ClassNotFoundException', 'SerialVersionUID']
            },
            # PHP
            {
                'name': 'PHP Serialization',
                'payload': 'O:8:"stdClass":0:{}',  # Simple PHP serialized object
                'content_type': 'application/x-www-form-urlencoded',
                'markers': ['unserialize', '__wakeup', '__destruct']
            },
            # .NET
            {
                'name': '.NET Deserialization',
                'payload': '<root type="System.Object" />',  # Simple XML serialized object
                'content_type': 'application/xml',
                'markers': ['System.Runtime.Serialization', 'SerializationException', 'BinaryFormatter']
            },
            # Node.js
            {
                'name': 'Node.js Deserialization',
                'payload': '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'echo DESERIALIZATION_TEST\')}()"}',
                'content_type': 'application/json',
                'markers': ['DESERIALIZATION_TEST', 'child_process', 'exec']
            },
            # Python Pickle
            {
                'name': 'Python Pickle',
                'payload': b'\x80\x04\x95',  # Pickle protocol 4 header
                'content_type': 'application/octet-stream',
                'markers': ['pickle.', 'unpickle', 'CodeType']
            },
        ]
        
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Test each serialization format
            for test in serialization_tests:
                # Try POST request with the payload
                headers = {'Content-Type': test['content_type']}
                try:
                    async with self.session.post(url, data=test['payload'], headers=headers) as resp:
                        response_text = await resp.text()
                        
                        # Check for markers indicating vulnerability
                        for marker in test['markers']:
                            if marker in response_text:
                                await self.report_vulnerability(
                                    'Insecure Deserialization',
                                    url,
                                    str(test['payload']),
                                    f"Potential {test['name']} vulnerability detected. Response contains marker: {marker}"
                                )
                                break
                except Exception:
                    pass
                
                # Try with each parameter in GET request
                for param, values in params.items():
                    param_url = url.split('?')[0] + f"?{param}={quote(str(test['payload']))}"
                    try:
                        async with self.session.get(param_url) as resp:
                            response_text = await resp.text()
                            
                            # Check for markers indicating vulnerability
                            for marker in test['markers']:
                                if marker in response_text:
                                    await self.report_vulnerability(
                                        'Insecure Deserialization',
                                        url,
                                        str(test['payload']),
                                        f"Potential {test['name']} vulnerability detected in parameter {param}. Response contains marker: {marker}"
                                    )
                                    break
                    except Exception:
                        pass
        
        except Exception as e:
            console.print(f"[yellow]Error during deserialization testing on {url}: {str(e)}[/yellow]")
    
    async def check_graphql(self, url: str):
        """Check for GraphQL endpoint vulnerabilities"""
        # Common GraphQL endpoints
        graphql_paths = [
            '/graphql', '/api/graphql', '/query', '/api/query', '/graphiql',
            '/api', '/gql', '/api/gql', '/v1/graphql', '/v2/graphql'
        ]
        
        # Introspection query to detect GraphQL
        introspection_query = """{
            __schema {
                queryType { name }
                mutationType { name }
                types { name kind description }
            }
        }"""
        
        # Check if the URL itself is a GraphQL endpoint
        is_graphql = False
        base_url = url.split('?')[0]
        
        # First check the provided URL
        try:
            headers = {'Content-Type': 'application/json'}
            payload = json.dumps({'query': introspection_query})
            
            async with self.session.post(url, data=payload, headers=headers) as resp:
                response_text = await resp.text()
                
                if ('"data"' in response_text and '"__schema"' in response_text) or \
                   ('"errors"' in response_text and '"locations"' in response_text):
                    is_graphql = True
                    console.print(f"[blue]GraphQL endpoint detected: {url}[/blue]")
                    
                    # Check if introspection is enabled (security issue)
                    if '"queryType"' in response_text and '"types"' in response_text:
                        await self.report_vulnerability(
                            'GraphQL Introspection Enabled',
                            url,
                            introspection_query,
                            "GraphQL introspection is enabled, exposing schema information"
                        )
        except Exception:
            pass
        
        # If not a GraphQL endpoint, check common paths
        if not is_graphql:
            parsed_url = urlparse(url)
            base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for path in graphql_paths:
                graphql_url = urljoin(base_domain, path)
                
                try:
                    headers = {'Content-Type': 'application/json'}
                    payload = json.dumps({'query': introspection_query})
                    
                    async with self.session.post(graphql_url, data=payload, headers=headers) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            
                            if ('"data"' in response_text and '"__schema"' in response_text) or \
                               ('"errors"' in response_text and '"locations"' in response_text):
                                console.print(f"[blue]GraphQL endpoint detected: {graphql_url}[/blue]")
                                self.discovered_urls.add(graphql_url)
                                
                                # Check if introspection is enabled (security issue)
                                if '"queryType"' in response_text and '"types"' in response_text:
                                    await self.report_vulnerability(
                                        'GraphQL Introspection Enabled',
                                        graphql_url,
                                        introspection_query,
                                        "GraphQL introspection is enabled, exposing schema information"
                                    )
                except Exception:
                    pass
    
    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        self.scan_stats['vulnerabilities'] += 1
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")
    
    async def generate_report(self, format: str):
        """Generate scan report in specified format"""
        if not hasattr(self, 'vulnerabilities'):
            self.vulnerabilities = []

        # Ensure end time is set
        if not self.end_time:
            self.end_time = datetime.now()
            self.scan_stats['end_time'] = self.end_time.isoformat()
            self.scan_stats['scan_duration'] = (self.end_time - self.start_time).total_seconds()

        # Create reports directory if it doesn't exist
        os.makedirs('Reports', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Reports/scan_report_{timestamp}"

        if format == 'html':
            report = self._generate_html_report()
            with open(f"{filename}.html", 'w') as f:
                f.write(report)
            report_path = f"{filename}.html"
        elif format == 'json':
            report = self._generate_json_report()
            with open(f"{filename}.json", 'w') as f:
                json.dump(report, f, indent=2)
            report_path = f"{filename}.json"
        elif format == 'md':
            report = self._generate_markdown_report()
            with open(f"{filename}.md", 'w') as f:
                f.write(report)
            report_path = f"{filename}.md"
        elif format == 'sarif':
            report = self._generate_sarif_report()
            with open(f"{filename}.sarif", 'w') as f:
                json.dump(report, f, indent=2)
            report_path = f"{filename}.sarif"
        else:
            console.print(f"[red]Unsupported report format: {format}[/red]")
            return

        console.print(f"\n[green]Report generated successfully: {report_path}[/green]")
        return report_path

    def _generate_html_report(self) -> str:
        """Generate HTML format report with improved styling and visualization"""
        html = """<!DOCTYPE html>"""
<html>
<head>
    <title>Enterprise Security Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        h1 {{ margin: 0; font-size: 24px; }}
        .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; min-width: 200px; }}
        .stat-card h3 {{ margin-top: 0; color: #2c3e50; }}
        .stat-value {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
        .vulnerabilities {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .vulnerability {{ border-left: 5px solid #ddd; padding: 15px; margin: 15px 0; }}
        .critical {{ border-left-color: #7b0000; background-color: #ffebee; }}
        .high {{ border-left-color: #c62828