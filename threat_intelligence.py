import aiohttp
from typing import Set, Dict
from rich.console import Console

class ThreatIntelligence:
    """Class for handling threat intelligence data and malicious IP detection"""
    
    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.threat_feeds = [
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt',
            'https://raw.githubusercontent.com/pallebone/StrictBlockPro/master/blacklists/ips.txt'
        ]
        self.console = Console()
    
    async def load_threat_feeds(self):
        """Load and parse threat intelligence feeds"""
        async with aiohttp.ClientSession() as session:
            for feed_url in self.threat_feeds:
                try:
                    async with session.get(feed_url) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Parse IPs from feed and add to set
                            self.malicious_ips.update(
                                ip.strip() for ip in text.splitlines()
                                if ip.strip() and not ip.startswith('#')
                            )
                except Exception as e:
                    self.console.print(f"[yellow]Warning: Could not load threat feed {feed_url}: {str(e)}[/yellow]")
    
    def is_ip_malicious(self, ip: str) -> bool:
        """Check if an IP is in the known malicious IPs list"""
        return ip in self.malicious_ips
    
    def get_threat_stats(self) -> Dict:
        """Get statistics about loaded threat intelligence"""
        return {
            'total_malicious_ips': len(self.malicious_ips),
            'feeds_loaded': len(self.threat_feeds)
        }