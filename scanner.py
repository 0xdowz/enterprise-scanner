import asyncio
import aiohttp
import argparse
from urllib.parse import urljoin, quote
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

# Initialize rich console
console = Console()

# Advanced configuration
VERSION = "4.0.0"
BANNER = f"""
[bold gradient(45,red,purple)]

     █████╗ ██╗    ██╗███████╗
    ██╔══██╗██║    ██║██╔════╝
    ███████║██║ █╗ ██║███████╗
    ██╔══██║██║███╗██║╚════██║
    ██║  ██║╚███╔███╔╝███████║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
[/bold gradient(45,red,purple)] Version: {VERSION} | Web Security Scanner
[bold blue] BY: 0xdowz[/bold blue]
"""

class ThreatIntelligence:
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_domains = set()
        
    async def load_threat_feeds(self):
        """Load threat intelligence from public feeds"""
        feeds = [
            "https://feeds.talosintelligence.com/blocklist",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ]
        try:
            timeout = aiohttp.ClientTimeout(total=10)  # Set a reasonable timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for feed in feeds:
                    try:
                        async with session.get(feed) as resp:
                            if resp.status == 200:
                                data = await resp.text()
                                self._parse_feed_data(data)
                            else:
                                console.print(f"[yellow]Warning: Feed {feed} returned status {resp.status}[/yellow]")
                    except aiohttp.ClientError as e:
                        console.print(f"[yellow]Warning: Could not load threat feed {feed}: {str(e)}[/yellow]")
                    except asyncio.TimeoutError:
                        console.print(f"[yellow]Warning: Timeout while loading threat feed {feed}[/yellow]")
        except Exception as e:
            console.print("[yellow]Warning: Could not initialize threat intelligence feeds. Continuing without them.[/yellow]")
            return

    def _parse_feed_data(self, data: str):
        """Parse threat feed data"""
        for line in data.split('\n'):
            if not line.startswith('#'):
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                    self.malicious_ips.add(line.strip())
                else:
                    self.suspicious_domains.add(line.strip())

class AIAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.01)
        self.features = []

class AdvancedScanner(ThreatIntelligence, AIAnomalyDetector):
    def __init__(self, config: Dict):
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
        
    async def init_session(self):
        """Initialize aiohttp session with optional Tor proxy"""
        if self.config.get('tor'):
            connector = ProxyConnector.from_url('socks5://localhost:9050')
            self.session = aiohttp.ClientSession(connector=connector)
        else:
            self.session = aiohttp.ClientSession()
        
    def load_payloads(self):
        """Load payloads from YAML file"""
        try:
            with open(self.config['payloads_file'], 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            console.print(f"[red]Error loading payloads: {str(e)}[/red]")
            return {}

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

[bold]Scanning Modes:[/bold]
1. Full Vulnerability Scan
   - Complete security assessment
   - Includes all available tests

2. Payload Testing Only
   - Focused testing with predefined payloads
   - SSTI and deserialization checks

3. Reconnaissance Only
   - DNS enumeration
   - URL discovery and mapping

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
    parser.add_argument('-o', '--output', choices=['html', 'json', 'md', 'sarif'], help='Report output format')
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

        if args.output:
            await scanner.generate_report(args.output)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    finally:
        await scanner.close()

if __name__ == '__main__':
    asyncio.run(main())
        
    def extract_features(self, response):
        """Extract features from HTTP response for anomaly detection"""
        features = [
            len(response.text),
            len(response.headers),
            response.status,
            sum(1 for c in response.text if c.isupper()),
            response.text.count('error'),
            response.text.count('warning')
        ]
        self.features.append(features)
        return features
    
    def train_model(self):
        """Train anomaly detection model"""
        X = np.array(self.features)
        self.model.fit(X)
        
    def detect_anomaly(self, features):
        """Detect anomalous responses"""
        return self.model.predict([features])[0] == -1

class AdvancedScanner(ThreatIntelligence, AIAnomalyDetector):
    def __init__(self, config: Dict):
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
        
    async def init_session(self):
        """Initialize aiohttp session with optional Tor proxy"""
        if self.config.get('tor'):
            connector = ProxyConnector.from_url('socks5://localhost:9050')
            self.session = aiohttp.ClientSession(connector=connector)
        else:
            self.session = aiohttp.ClientSession()
        
    def load_payloads(self):
        """Load payloads from YAML file"""
        try:
            with open(self.config['payloads_file'], 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            console.print(f"[red]Error loading payloads: {str(e)}[/red]")
            return {}

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints"""
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img']):
                        href = link.get('href') or link.get('src')
                        if href:
                            full_url = urljoin(url, href)
                            if url in full_url:  # Only add URLs from same domain
                                self.discovered_urls.add(full_url)
                    
                    console.print(f"[green]Discovered {len(self.discovered_urls)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {str(e)}[/red]")
            return

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

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
        """Check for CORS misconfigurations"""
        malicious_origin = "https://attacker.com"
        headers = {"Origin": malicious_origin}
        
        try:
            async with self.session.options(url, headers=headers) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or (acao == malicious_origin and acac == 'true'):
                    await self.report_vulnerability(
                        'CORS Misconfiguration',
                        url,
                        malicious_origin,
                        f"Exposed headers: {resp.headers}"
                    )
        except Exception as e:
            console.print(f"[!] CORS check error: {str(e)}", style="bold red")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection"""
        payloads = {
            'python': '{{ 7 * 7 }}',
            'java': '${{ 7 * 7 }}',
            'ruby': '<%= 7 * 7 %>',
            'smarty': '{7 * 7}'
        }
        
        for lang, payload in payloads.items():
            try:
                async with self.session.post(url, data={'input': payload}) as resp:
                    if '49' in await resp.text():
                        await self.report_vulnerability(
                            'SSTI',
                            url,
                            payload,
                            f"Detected {lang} template injection"
                        )
            except Exception as e:
                console.print(f"[!] SSTI test error: {str(e)}", style="bold red")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QABmF0dGFja3QAAi9idAAHd3d3LmNvbXQAA2h0dHB4"
        )
        
        headers = {'Content-Type': 'application/java-serialized-object'}
        try:
            async with self.session.post(url, data=java_payload, headers=headers) as resp:
                if 'java.io.Serializable' in await resp.text():
                    await self.report_vulnerability(
                        'Insecure Deserialization',
                        url,
                        java_payload,
                        "Java deserialization detected"
                    )
        except Exception as e:
            console.print(f"[!] Deserialization check error: {str(e)}", style="bold red")

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

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints"""
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img']):
                        href = link.get('href') or link.get('src')
                        if href:
                            full_url = urljoin(url, href)
                            if url in full_url:  # Only add URLs from same domain
                                self.discovered_urls.add(full_url)
                    
                    console.print(f"[green]Discovered {len(self.discovered_urls)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {str(e)}[/red]")
            return

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

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
        """Check for CORS misconfigurations"""
        malicious_origin = "https://attacker.com"
        headers = {"Origin": malicious_origin}
        
        try:
            async with self.session.options(url, headers=headers) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or (acao == malicious_origin and acac == 'true'):
                    await self.report_vulnerability(
                        'CORS Misconfiguration',
                        url,
                        malicious_origin,
                        f"Exposed headers: {resp.headers}"
                    )
        except Exception as e:
            console.print(f"[!] CORS check error: {str(e)}", style="bold red")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection"""
        payloads = {
            'python': '{{ 7 * 7 }}',
            'java': '${{ 7 * 7 }}',
            'ruby': '<%= 7 * 7 %>',
            'smarty': '{7 * 7}'
        }
        
        for lang, payload in payloads.items():
            try:
                async with self.session.post(url, data={'input': payload}) as resp:
                    if '49' in await resp.text():
                        await self.report_vulnerability(
                            'SSTI',
                            url,
                            payload,
                            f"Detected {lang} template injection"
                        )
            except Exception as e:
                console.print(f"[!] SSTI test error: {str(e)}", style="bold red")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QABmF0dGFja3QAAi9idAAHd3d3LmNvbXQAA2h0dHB4"
        )
        
        headers = {'Content-Type': 'application/java-serialized-object'}
        try:
            async with self.session.post(url, data=java_payload, headers=headers) as resp:
                if 'java.io.Serializable' in await resp.text():
                    await self.report_vulnerability(
                        'Insecure Deserialization',
                        url,
                        java_payload,
                        "Java deserialization detected"
                    )
        except Exception as e:
            console.print(f"[!] Deserialization check error: {str(e)}", style="bold red")

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

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints"""
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img']):
                        href = link.get('href') or link.get('src')
                        if href:
                            full_url = urljoin(url, href)
                            if url in full_url:  # Only add URLs from same domain
                                self.discovered_urls.add(full_url)
                    
                    console.print(f"[green]Discovered {len(self.discovered_urls)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {str(e)}[/red]")
            return

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

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
        """Check for CORS misconfigurations"""
        malicious_origin = "https://attacker.com"
        headers = {"Origin": malicious_origin}
        
        try:
            async with self.session.options(url, headers=headers) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or (acao == malicious_origin and acac == 'true'):
                    await self.report_vulnerability(
                        'CORS Misconfiguration',
                        url,
                        malicious_origin,
                        f"Exposed headers: {resp.headers}"
                    )
        except Exception as e:
            console.print(f"[!] CORS check error: {str(e)}", style="bold red")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection"""
        payloads = {
            'python': '{{ 7 * 7 }}',
            'java': '${{ 7 * 7 }}',
            'ruby': '<%= 7 * 7 %>',
            'smarty': '{7 * 7}'
        }
        
        for lang, payload in payloads.items():
            try:
                async with self.session.post(url, data={'input': payload}) as resp:
                    if '49' in await resp.text():
                        await self.report_vulnerability(
                            'SSTI',
                            url,
                            payload,
                            f"Detected {lang} template injection"
                        )
            except Exception as e:
                console.print(f"[!] SSTI test error: {str(e)}", style="bold red")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QABmF0dGFja3QAAi9idAAHd3d3LmNvbXQAA2h0dHB4"
        )
        
        headers = {'Content-Type': 'application/java-serialized-object'}
        try:
            async with self.session.post(url, data=java_payload, headers=headers) as resp:
                if 'java.io.Serializable' in await resp.text():
                    await self.report_vulnerability(
                        'Insecure Deserialization',
                        url,
                        java_payload,
                        "Java deserialization detected"
                    )
        except Exception as e:
            console.print(f"[!] Deserialization check error: {str(e)}", style="bold red")

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

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints"""
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img']):
                        href = link.get('href') or link.get('src')
                        if href:
                            full_url = urljoin(url, href)
                            if url in full_url:  # Only add URLs from same domain
                                self.discovered_urls.add(full_url)
                    
                    console.print(f"[green]Discovered {len(self.discovered_urls)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {str(e)}[/red]")
            return

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

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
        """Check for CORS misconfigurations"""
        malicious_origin = "https://attacker.com"
        headers = {"Origin": malicious_origin}
        
        try:
            async with self.session.options(url, headers=headers) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or (acao == malicious_origin and acac == 'true'):
                    await self.report_vulnerability(
                        'CORS Misconfiguration',
                        url,
                        malicious_origin,
                        f"Exposed headers: {resp.headers}"
                    )
        except Exception as e:
            console.print(f"[!] CORS check error: {str(e)}", style="bold red")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection"""
        payloads = {
            'python': '{{ 7 * 7 }}',
            'java': '${{ 7 * 7 }}',
            'ruby': '<%= 7 * 7 %>',
            'smarty': '{7 * 7}'
        }
        
        for lang, payload in payloads.items():
            try:
                async with self.session.post(url, data={'input': payload}) as resp:
                    if '49' in await resp.text():
                        await self.report_vulnerability(
                            'SSTI',
                            url,
                            payload,
                            f"Detected {lang} template injection"
                        )
            except Exception as e:
                console.print(f"[!] SSTI test error: {str(e)}", style="bold red")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QABmF0dGFja3QAAi9idAAHd3d3LmNvbXQAA2h0dHB4"
        )
        
        headers = {'Content-Type': 'application/java-serialized-object'}
        try:
            async with self.session.post(url, data=java_payload, headers=headers) as resp:
                if 'java.io.Serializable' in await resp.text():
                    await self.report_vulnerability(
                        'Insecure Deserialization',
                        url,
                        java_payload,
                        "Java deserialization detected"
                    )
        except Exception as e:
            console.print(f"[!] Deserialization check error: {str(e)}", style="bold red")

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

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30),
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

    async def crawl(self, url: str):
        """Crawl the target URL and discover endpoints"""
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img']):
                        href = link.get('href') or link.get('src')
                        if href:
                            full_url = urljoin(url, href)
                            if url in full_url:  # Only add URLs from same domain
                                self.discovered_urls.add(full_url)
                    
                    console.print(f"[green]Discovered {len(self.discovered_urls)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Error crawling {url}: {str(e)}[/red]")
            return

    def _generate_headers(self):
        """Generate randomized headers for stealth"""
        return {
            'User-Agent': self.faker.user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': f'en-US,en;q=0.{random.randint(5,9)}',
            'X-Forwarded-For': self.faker.ipv4(),
            'Referer': self.faker.url()
        }

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
        """Check for CORS misconfigurations"""
        malicious_origin = "https://attacker.com"
        headers = {"Origin": malicious_origin}
        
        try:
            async with self.session.options(url, headers=headers) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or (acao == malicious_origin and acac == 'true'):
                    await self.report_vulnerability(
                        'CORS Misconfiguration',
                        url,
                        malicious_origin,
                        f"Exposed headers: {resp.headers}"
                    )
        except Exception as e:
            console.print(f"[!] CORS check error: {str(e)}", style="bold red")

    async def test_ssti(self, url: str):
        """Test for Server-Side Template Injection"""
        payloads = {
            'python': '{{ 7 * 7 }}',
            'java': '${{ 7 * 7 }}',
            'ruby': '<%= 7 * 7 %>',
            'smarty': '{7 * 7}'
        }
        
        for lang, payload in payloads.items():
            try:
                async with self.session.post(url, data={'input': payload}) as resp:
                    if '49' in await resp.text():
                        await self.report_vulnerability(
                            'SSTI',
                            url,
                            payload,
                            f"Detected {lang} template injection"
                        )
            except Exception as e:
                console.print(f"[!] SSTI test error: {str(e)}", style="bold red")

    async def check_deserialization(self, url: str):
        """Test for insecure deserialization vulnerabilities"""
        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QABmF0dGFja3QAAi9idAAHd3d3LmNvbXQAA2h0dHB4"
        )
        
        headers = {'Content-Type': 'application/java-serialized-object'}
        try:
            async with self.session.post(url, data=java_payload, headers=headers) as resp:
                if 'java.io.Serializable' in await resp.text():
                    await self.report_vulnerability(
                        'Insecure Deserialization',
                        url,
                        java_payload,
                        "Java deserialization detected"
                    )
        except Exception as e:
            console.print(f"[!] Deserialization check error: {str(e)}", style="bold red")

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

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details
        })
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")

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
        if self.config['tor']:
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(limit=100, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self._generate_headers(),
            timeout=aiohttp.ClientTimeout(total=30)
        )
