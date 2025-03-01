from typing import Dict, List
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import random
from faker import Faker
from rich.console import Console
from datetime import datetime

class BaseScanner:
    """Base scanner class containing common functionality for web scanning"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.lock = asyncio.Lock()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.faker = Faker()
        self.request_count = 0
        self.rate_limit_sem = asyncio.Semaphore(config.get('rate_limit', 50))
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

    async def init_session(self):
        """Initialize HTTP session with advanced configuration"""
        if self.config.get('tor'):
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')
        else:
            connector = aiohttp.TCPConnector(ssl=False)

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
        """Base crawl method for discovering endpoints"""
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

            console.print(f"[cyan]Starting crawl of {url}...[/cyan]")
            async with self.session.get(url, allow_redirects=True) as resp:
                if resp.status == 404:
                    console.print(f"[red]Error: Page not found (404) at {url}[/red]")
                    return
                elif resp.status == 403:
                    console.print(f"[red]Error: Access forbidden (403) at {url}[/red]")
                    return
                elif resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                        href = link.get('href') or link.get('src') or link.get('action')
                        if href:
                            try:
                                full_url = urljoin(url, href)
                                parsed = urlparse(full_url)
                                if parsed.netloc == parsed_url.netloc:
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

        except aiohttp.ClientError as e:
            console.print(f"[red]Network error while crawling {url}: {str(e)}[/red]")
        except Exception as e:
            console.print(f"[red]Unexpected error crawling {url}: {str(e)}[/red]")

    async def report_vulnerability(self, vuln_type: str, url: str, payload: str, details: str):
        """Report a discovered vulnerability with enhanced tracking"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        if hasattr(self, 'scan_stats'):
            self.scan_stats['vulnerabilities'] += 1
        console.print(f"[red][!] Found {vuln_type} vulnerability at {url}[/red]")