"""
VEIL IP Intelligence Module
WHOIS lookups, IP reputation checks, and threat intelligence.
"""

import threading
import time
import json
import logging
from typing import Optional, Dict
from dataclasses import dataclass

logger = logging.getLogger("veil.ipintel")


@dataclass
class IPReputation:
    ip: str = ""
    hostname: str = ""
    org: str = ""
    isp: str = ""
    asn: str = ""
    country: str = ""
    city: str = ""
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_known_attacker: bool = False
    risk_score: int = 0   # 0-100
    risk_level: str = "unknown"  # low, medium, high, critical
    abuse_reports: int = 0
    whois_org: str = ""
    whois_netname: str = ""
    whois_descr: str = ""
    last_checked: float = 0.0


class IPIntelligence:
    """IP address reputation and intelligence lookups."""

    def __init__(self):
        self._cache: Dict[str, IPReputation] = {}
        self._lock = threading.Lock()
        self._pending = set()

        # Known datacenter/cloud ASN prefixes (for heuristic detection)
        self._datacenter_orgs = {
            "amazon", "aws", "google", "microsoft", "azure", "cloudflare",
            "digitalocean", "linode", "vultr", "ovh", "hetzner", "oracle cloud",
            "alibaba", "tencent", "rackspace", "ibm cloud", "fastly", "akamai",
        }

        # Known suspicious TLDs
        self._suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".click"}

    def lookup(self, ip: str, hostname: str = "") -> IPReputation:
        """Look up IP reputation. Returns cached or triggers async lookup."""
        if ip in self._cache:
            return self._cache[ip]

        # Private IP — no lookup needed
        if self._is_private(ip):
            rep = IPReputation(
                ip=ip, hostname=hostname or "local",
                org="Private Network", risk_level="none", risk_score=0,
            )
            self._cache[ip] = rep
            return rep

        # Start async lookup
        if ip not in self._pending:
            self._pending.add(ip)
            threading.Thread(target=self._async_lookup, args=(ip, hostname), daemon=True).start()

        return IPReputation(ip=ip, hostname=hostname)

    def _async_lookup(self, ip: str, hostname: str = ""):
        """Perform async IP reputation lookup."""
        rep = IPReputation(ip=ip, hostname=hostname, last_checked=time.time())

        # Try ip-api.com for basic geo + org
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,org,isp,as,proxy,hosting,country,city"
            req = urllib.request.Request(url, headers={"User-Agent": "VEIL/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                rep.org = data.get("org", "")
                rep.isp = data.get("isp", "")
                rep.asn = data.get("as", "")
                rep.country = data.get("country", "")
                rep.city = data.get("city", "")
                rep.is_proxy = data.get("proxy", False)
                rep.is_datacenter = data.get("hosting", False)
        except Exception as e:
            logger.debug(f"ip-api lookup failed for {ip}: {e}")

        # Heuristic scoring
        rep.risk_score = self._calculate_risk(rep, hostname)
        if rep.risk_score < 20:
            rep.risk_level = "low"
        elif rep.risk_score < 50:
            rep.risk_level = "medium"
        elif rep.risk_score < 75:
            rep.risk_level = "high"
        else:
            rep.risk_level = "critical"

        with self._lock:
            self._cache[ip] = rep
            self._pending.discard(ip)

    def _calculate_risk(self, rep: IPReputation, hostname: str = "") -> int:
        """Calculate heuristic risk score for an IP/host."""
        score = 0

        if rep.is_proxy: score += 30
        if rep.is_vpn: score += 20
        if rep.is_tor: score += 40
        if rep.is_datacenter: score += 5
        if rep.is_known_attacker: score += 50

        # Suspicious TLD
        if hostname:
            for tld in self._suspicious_tlds:
                if hostname.endswith(tld):
                    score += 25
                    break

        # Unknown org
        if not rep.org or rep.org == "Unknown":
            score += 10

        # IP-only (no hostname resolves)
        if not hostname or hostname == rep.ip:
            score += 5

        return min(100, score)

    def get_cached(self, ip: str) -> Optional[IPReputation]:
        return self._cache.get(ip)

    @staticmethod
    def _is_private(ip: str) -> bool:
        return (ip.startswith("10.") or ip.startswith("192.168.") or
                ip.startswith("172.16.") or ip.startswith("172.17.") or
                ip.startswith("127.") or ip.startswith("169.254.") or
                ip == "::1" or ip.startswith("fe80"))

    @property
    def cache_size(self) -> int:
        return len(self._cache)
