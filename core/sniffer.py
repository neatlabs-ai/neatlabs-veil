"""
VEIL Core Packet Sniffer Engine
Captures network traffic using scapy and resolves connections to processes.

NEATLABS™ Intelligence Technology
Open Source — github.com/neatlabs-ai
"""

import threading
import time
import socket
import struct
import json
import os
import logging
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Callable

logger = logging.getLogger("veil.sniffer")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GeoInfo:
    ip: str = ""
    city: str = "Unknown"
    region: str = ""
    country: str = "??"
    country_code: str = "??"
    lat: float = 0.0
    lng: float = 0.0
    org: str = "Unknown"
    isp: str = ""
    asn: str = ""


@dataclass
class ConnectionInfo:
    """Represents a single captured connection/packet."""
    timestamp: float = 0.0
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "TCP"
    length: int = 0
    app_name: str = "Unknown"
    app_pid: int = 0
    dst_host: str = ""
    geo: Optional[GeoInfo] = None
    is_tracker: bool = False
    tracker_name: str = ""
    tracker_company: str = ""
    tracker_category: str = ""
    tracker_severity: str = ""
    is_outbound: bool = True
    dns_query: str = ""
    flags: str = ""
    payload_preview: str = ""

    @property
    def direction(self) -> str:
        return "OUT" if self.is_outbound else "IN"

    @property
    def proto_display(self) -> str:
        if self.dst_port == 443 or self.src_port == 443:
            return "HTTPS"
        elif self.dst_port == 80 or self.src_port == 80:
            return "HTTP"
        elif self.dst_port == 53 or self.src_port == 53:
            return "DNS"
        elif self.protocol == "UDP" and self.dst_port == 443:
            return "QUIC"
        return self.protocol


@dataclass
class AppTrafficStats:
    """Per-application traffic statistics."""
    name: str = ""
    pid: int = 0
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    packet_count: int = 0
    connections: Set[str] = field(default_factory=set)
    tracker_hits: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    destinations: Set[str] = field(default_factory=set)


@dataclass
class SessionStats:
    """Overall session statistics."""
    start_time: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    total_sessions: int = 0
    total_dns_queries: int = 0
    unique_endpoints: Set[str] = field(default_factory=set)
    unique_destinations: Set[str] = field(default_factory=set)
    trackers_found: Set[str] = field(default_factory=set)
    tracker_bytes: int = 0
    protocols: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    countries: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bandwidth_history: List[tuple] = field(default_factory=list)
    privacy_score: float = 0.0
    alerts: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tracker Detection
# ---------------------------------------------------------------------------

class TrackerDetector:
    """Detects known trackers, ad networks, and telemetry endpoints."""

    def __init__(self, db_path: str = None):
        self.trackers = {}
        self.telemetry_keywords = []
        self.ad_keywords = []
        self._load_database(db_path)

    def _load_database(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "trackers.json")
        try:
            with open(db_path, "r") as f:
                data = json.load(f)
            self.trackers = data.get("trackers", {})
            self.telemetry_keywords = data.get("telemetry_domains", [])
            self.ad_keywords = data.get("ad_domains", [])
            logger.info(f"Loaded {len(self.trackers)} tracker signatures")
        except Exception as e:
            logger.error(f"Failed to load tracker DB: {e}")

    def check(self, hostname: str) -> Optional[dict]:
        """Check if a hostname is a known tracker. Returns tracker info or None."""
        if not hostname:
            return None
        hostname_lower = hostname.lower()

        # Direct match
        for domain, info in self.trackers.items():
            if domain in hostname_lower:
                return info

        # Heuristic: telemetry keywords in subdomain
        parts = hostname_lower.split(".")
        for part in parts:
            for kw in self.telemetry_keywords:
                if kw in part:
                    return {
                        "name": f"Telemetry ({part})",
                        "company": "Unknown",
                        "category": "Telemetry",
                        "severity": "medium"
                    }
            for kw in self.ad_keywords:
                if kw in part and len(part) > len(kw):
                    return {
                        "name": f"Ad Network ({part})",
                        "company": "Unknown",
                        "category": "Advertising",
                        "severity": "high"
                    }
        return None


# ---------------------------------------------------------------------------
# GeoIP Resolver
# ---------------------------------------------------------------------------

class GeoIPResolver:
    """Resolves IP addresses to geographic locations."""

    def __init__(self):
        self._cache: Dict[str, GeoInfo] = {}
        self._lock = threading.Lock()
        self._pending: Set[str] = set()
        self._use_api = True
        self._private_ranges = [
            ("10.", ),
            ("172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
             "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
             "172.28.", "172.29.", "172.30.", "172.31."),
            ("192.168.",),
            ("127.",),
            ("169.254.",),
        ]

    def is_private(self, ip: str) -> bool:
        for group in self._private_ranges:
            for prefix in group:
                if ip.startswith(prefix):
                    return True
        return False

    def resolve(self, ip: str) -> GeoInfo:
        """Get geo info for an IP. Returns cached result or triggers async lookup."""
        if ip in self._cache:
            return self._cache[ip]

        if self.is_private(ip):
            geo = GeoInfo(ip=ip, city="Local Network", country="LOCAL",
                         country_code="LO", org="Private Network")
            self._cache[ip] = geo
            return geo

        # Start async lookup
        if ip not in self._pending:
            self._pending.add(ip)
            threading.Thread(target=self._lookup, args=(ip,), daemon=True).start()

        return GeoInfo(ip=ip)

    def _lookup(self, ip: str):
        """Perform GeoIP lookup via ip-api.com (free, no key needed)."""
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,org,isp,as"
            req = urllib.request.Request(url, headers={"User-Agent": "VEIL/3.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                geo = GeoInfo(
                    ip=ip,
                    city=data.get("city", "Unknown"),
                    region=data.get("region", ""),
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "??"),
                    lat=data.get("lat", 0),
                    lng=data.get("lon", 0),
                    org=data.get("org", "Unknown"),
                    isp=data.get("isp", ""),
                    asn=data.get("as", ""),
                )
            else:
                geo = GeoInfo(ip=ip)
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            geo = GeoInfo(ip=ip)

        with self._lock:
            self._cache[ip] = geo
            self._pending.discard(ip)

    def get_cached(self, ip: str) -> Optional[GeoInfo]:
        return self._cache.get(ip)

    @property
    def cache_size(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# Process Resolver
# ---------------------------------------------------------------------------

class ProcessResolver:
    """Maps network connections to running processes using psutil."""

    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._pid_cache: Dict[str, int] = {}
        self._psutil_available = False
        try:
            import psutil
            self._psutil_available = True
        except ImportError:
            logger.warning("psutil not available — process resolution disabled")

    def resolve(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                protocol: str = "tcp") -> tuple:
        """Returns (app_name, pid) for a connection."""
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        if key in self._cache:
            return self._cache[key], self._pid_cache.get(key, 0)

        if not self._psutil_available:
            return "Unknown", 0

        try:
            import psutil
            kind = "inet"
            for conn in psutil.net_connections(kind=kind):
                if conn.status == "NONE":
                    continue
                laddr = conn.laddr
                raddr = conn.raddr
                if not raddr:
                    continue
                if ((laddr.port == src_port and raddr.port == dst_port) or
                    (laddr.port == dst_port and raddr.port == src_port)):
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name()
                        self._cache[key] = name
                        self._pid_cache[key] = conn.pid
                        return name, conn.pid
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            logger.debug(f"Process resolution failed: {e}")

        return "Unknown", 0

    def refresh_connections(self) -> Dict[str, dict]:
        """Get all current network connections with process info."""
        if not self._psutil_available:
            return {}

        import psutil
        result = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    name = proc.name() if proc else "System"
                    result[f"{conn.laddr.ip}:{conn.laddr.port}"] = {
                        "pid": conn.pid,
                        "name": name,
                        "status": conn.status,
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except psutil.AccessDenied:
            logger.warning("Need elevated privileges for full process resolution")
        return result


# ---------------------------------------------------------------------------
# DNS Resolver / Cache
# ---------------------------------------------------------------------------

class DNSCache:
    """Caches DNS resolutions and captures DNS queries from traffic."""

    def __init__(self):
        self._ip_to_host: Dict[str, str] = {}
        self._host_to_ip: Dict[str, str] = {}
        self._queries: List[dict] = []
        self._lock = threading.Lock()

    def add(self, hostname: str, ip: str):
        with self._lock:
            self._ip_to_host[ip] = hostname
            self._host_to_ip[hostname] = ip

    def add_query(self, query: str, response_ip: str = "", qtype: str = "A"):
        with self._lock:
            self._queries.append({
                "time": time.time(),
                "query": query,
                "response": response_ip,
                "type": qtype
            })
            if response_ip:
                self._ip_to_host[response_ip] = query

    def get_hostname(self, ip: str) -> str:
        hostname = self._ip_to_host.get(ip, "")
        if not hostname:
            try:
                hostname = socket.getfqdn(ip)
                if hostname != ip:
                    self._ip_to_host[ip] = hostname
            except Exception:
                pass
        return hostname

    @property
    def queries(self):
        return list(self._queries)

    @property
    def query_count(self):
        return len(self._queries)


# ---------------------------------------------------------------------------
# Company Aggregation
# ---------------------------------------------------------------------------

# Domain → parent company mapping for traffic intelligence
COMPANY_DOMAINS = {
    "google": "Google", "googleapis": "Google", "gstatic": "Google",
    "youtube": "Google", "googlevideo": "Google", "doubleclick": "Google",
    "googleusercontent": "Google", "google-analytics": "Google",
    "googleadservices": "Google", "googlesyndication": "Google",
    "gvt1": "Google", "gvt2": "Google", "ggpht": "Google",
    "microsoft": "Microsoft", "msftconnecttest": "Microsoft",
    "msedge": "Microsoft", "office": "Microsoft", "live": "Microsoft",
    "bing": "Microsoft", "azure": "Microsoft", "windows": "Microsoft",
    "msn": "Microsoft", "skype": "Microsoft", "outlook": "Microsoft",
    "linkedin": "Microsoft",
    "facebook": "Meta", "fbcdn": "Meta", "instagram": "Meta",
    "whatsapp": "Meta", "meta": "Meta", "fbsbx": "Meta",
    "amazon": "Amazon", "amazonaws": "Amazon", "cloudfront": "Amazon",
    "aws": "Amazon", "amazonvideo": "Amazon", "alexa": "Amazon",
    "apple": "Apple", "icloud": "Apple", "mzstatic": "Apple",
    "aaplimg": "Apple", "itunes": "Apple", "cdn-apple": "Apple",
    "tiktok": "ByteDance", "bytedance": "ByteDance", "tiktokcdn": "ByteDance",
    "musical": "ByteDance",
    "cloudflare": "Cloudflare", "cfcdn": "Cloudflare",
    "adobe": "Adobe", "adobedtm": "Adobe", "omtrdc": "Adobe",
    "demdex": "Adobe", "typekit": "Adobe",
    "twitter": "X Corp", "twimg": "X Corp",
    "netflix": "Netflix", "nflxvideo": "Netflix",
    "akamai": "Akamai", "akamaized": "Akamai", "akamaihd": "Akamai",
    "fastly": "Fastly",
    "oracle": "Oracle", "eloqua": "Oracle", "bluekai": "Oracle",
    "yahoo": "Yahoo", "yimg": "Yahoo",
    "samsung": "Samsung", "samsungcloud": "Samsung",
    "spotify": "Spotify", "scdn": "Spotify",
    "snap": "Snap", "snapchat": "Snap", "sc-cdn": "Snap",
}


def resolve_company(hostname: str) -> str:
    """Resolve a hostname to its parent company."""
    if not hostname:
        return ""
    hostname_lower = hostname.lower()
    for keyword, company in COMPANY_DOMAINS.items():
        if keyword in hostname_lower:
            return company
    return ""


# ---------------------------------------------------------------------------
# Main Sniffer Engine
# ---------------------------------------------------------------------------

class SnifferEngine:
    """
    Main packet capture engine.
    Uses scapy for live capture, with fallback to socket-based capture.
    """

    def __init__(self, interface: str = None):
        self.interface = interface
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []

        # Sub-systems
        self.tracker_detector = TrackerDetector()
        self.geo_resolver = GeoIPResolver()
        self.process_resolver = ProcessResolver()
        self.dns_cache = DNSCache()

        # Stats
        self.stats = SessionStats(start_time=time.time())
        self.app_stats: Dict[str, AppTrafficStats] = {}
        self.dest_stats: Dict[str, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0, "host": "", "geo": None})
        self.company_stats: Dict[str, dict] = defaultdict(lambda: {"bytes": 0, "apps": set(), "trackers": 0, "connections": 0})
        self.connections: List[ConnectionInfo] = []
        self._conn_lock = threading.Lock()

        # Phone-home tracking
        self.phone_home_apps: Dict[str, dict] = defaultdict(lambda: {
            "silent_connections": 0, "destinations": set(), "first_seen": 0.0,
            "last_seen": 0.0, "total_bytes": 0, "tracker_connections": 0
        })

        # Bandwidth tracking
        self._bytes_window: List[tuple] = []
        self._current_bps = 0.0

        # State
        self._scapy_available = False
        self._capture_mode = "none"
        self._local_ips: Set[str] = set()

        self._detect_capabilities()
        self._get_local_ips()

    def _detect_capabilities(self):
        """Check what capture methods are available."""
        try:
            from scapy.all import sniff as _s, IP as _i
            self._scapy_available = True
            self._capture_mode = "scapy"
            logger.info("Scapy available — full packet capture enabled")
        except ImportError:
            logger.info("Scapy not available — checking alternatives")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.close()
                self._capture_mode = "raw_socket"
                logger.info("Raw socket capture available (needs root)")
            except (PermissionError, OSError):
                try:
                    import psutil
                    self._capture_mode = "psutil_poll"
                    logger.info("Using psutil connection polling (no root required)")
                except ImportError:
                    self._capture_mode = "none"
                    logger.error("No capture method available — install scapy or psutil")

    def _get_local_ips(self):
        """Detect local IP addresses."""
        self._local_ips = {"127.0.0.1", "::1"}
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in (socket.AF_INET, socket.AF_INET6):
                        self._local_ips.add(addr.address)
        except ImportError:
            try:
                hostname = socket.gethostname()
                self._local_ips.add(socket.gethostbyname(hostname))
            except Exception:
                pass
        logger.info(f"Local IPs: {self._local_ips}")

    def on_packet(self, callback: Callable):
        """Register a callback for new packets."""
        self._callbacks.append(callback)

    def on_alert(self, callback: Callable):
        """Register a callback for security alerts."""
        self._alert_callbacks.append(callback)

    def start(self):
        """Start packet capture."""
        if self.running:
            return
        self.running = True
        self.stats = SessionStats(start_time=time.time())
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        # Start bandwidth calculator
        threading.Thread(target=self._bandwidth_loop, daemon=True).start()
        logger.info("Sniffer engine started")

    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Sniffer engine stopped")

    def _capture_loop(self):
        """Main capture loop — dispatches to appropriate method."""
        if self._capture_mode == "scapy":
            self._capture_scapy()
        elif self._capture_mode == "raw_socket":
            self._capture_raw_socket()
        else:
            self._capture_psutil_poll()

    def _capture_scapy(self):
        """Capture using scapy — most feature-rich method."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw

            def process_packet(pkt):
                if not self.running:
                    return
                if not pkt.haslayer(IP):
                    return

                ip_layer = pkt[IP]
                conn = ConnectionInfo(
                    timestamp=time.time(),
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    length=len(pkt),
                    protocol="TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER"),
                )

                if pkt.haslayer(TCP):
                    conn.src_port = pkt[TCP].sport
                    conn.dst_port = pkt[TCP].dport
                    conn.flags = str(pkt[TCP].flags)
                elif pkt.haslayer(UDP):
                    conn.src_port = pkt[UDP].sport
                    conn.dst_port = pkt[UDP].dport

                # DNS capture
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    conn.dns_query = qname
                    self.dns_cache.add_query(qname)
                    self.stats.total_dns_queries += 1

                # Determine direction
                conn.is_outbound = ip_layer.src in self._local_ips

                # Payload preview (first 64 bytes, sanitized)
                if pkt.haslayer(Raw):
                    raw = bytes(pkt[Raw].load[:64])
                    conn.payload_preview = raw.decode("utf-8", errors="replace")[:64]

                self._process_connection(conn)

            sniff(
                iface=self.interface,
                prn=process_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            logger.error("Permission denied — run with sudo/admin for full capture")
            self._capture_mode = "psutil_poll"
            self._capture_psutil_poll()
        except Exception as e:
            logger.error(f"Scapy capture error: {e}")
            self._capture_mode = "psutil_poll"
            self._capture_psutil_poll()

    def _capture_raw_socket(self):
        """Capture using raw sockets (Linux only, needs root)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1.0)
            while self.running:
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    ip_header = raw_data[:20]
                    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    dst_ip = socket.inet_ntoa(iph[9])
                    total_length = iph[2]

                    conn = ConnectionInfo(
                        timestamp=time.time(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        length=total_length,
                        protocol="TCP" if protocol == 6 else ("UDP" if protocol == 17 else "OTHER"),
                        is_outbound=src_ip in self._local_ips,
                    )

                    ihl = (iph[0] & 0x0F) * 4
                    if protocol == 6 and len(raw_data) >= ihl + 4:
                        conn.src_port, conn.dst_port = struct.unpack("!HH", raw_data[ihl:ihl+4])
                    elif protocol == 17 and len(raw_data) >= ihl + 4:
                        conn.src_port, conn.dst_port = struct.unpack("!HH", raw_data[ihl:ihl+4])

                    self._process_connection(conn)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"Raw socket parse error: {e}")
        except PermissionError:
            logger.error("Raw socket needs root — falling back to psutil polling")
            self._capture_psutil_poll()
        except Exception as e:
            logger.error(f"Raw socket error: {e}")
            self._capture_psutil_poll()

    def _capture_psutil_poll(self):
        """Fallback: poll psutil for active connections (no root needed)."""
        logger.info("Using psutil connection polling (no root required)")
        seen_connections = set()
        try:
            import psutil
        except ImportError:
            logger.error("psutil not available — cannot capture")
            return

        while self.running:
            try:
                for conn_info in psutil.net_connections(kind="inet"):
                    if not conn_info.raddr or not self.running:
                        continue

                    key = f"{conn_info.laddr.ip}:{conn_info.laddr.port}-{conn_info.raddr.ip}:{conn_info.raddr.port}"
                    if key in seen_connections:
                        continue
                    seen_connections.add(key)

                    app_name = "Unknown"
                    pid = conn_info.pid or 0
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            app_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    proto = "TCP" if conn_info.type == socket.SOCK_STREAM else "UDP"

                    conn = ConnectionInfo(
                        timestamp=time.time(),
                        src_ip=conn_info.laddr.ip,
                        src_port=conn_info.laddr.port,
                        dst_ip=conn_info.raddr.ip,
                        dst_port=conn_info.raddr.port,
                        protocol=proto,
                        length=0,
                        app_name=app_name,
                        app_pid=pid,
                        is_outbound=True,
                    )
                    self._process_connection(conn)

                if len(seen_connections) > 10000:
                    seen_connections.clear()

                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"psutil poll error: {e}")
                time.sleep(1)

    def _process_connection(self, conn: ConnectionInfo):
        """Process a captured connection — resolve, classify, and notify."""
        # Resolve hostname
        target_ip = conn.dst_ip if conn.is_outbound else conn.src_ip
        hostname = self.dns_cache.get_hostname(target_ip)
        conn.dst_host = hostname or target_ip

        # Resolve process (if not already set)
        if conn.app_name == "Unknown":
            conn.app_name, conn.app_pid = self.process_resolver.resolve(
                conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port
            )

        # Check tracker
        tracker = self.tracker_detector.check(conn.dst_host)
        if tracker:
            conn.is_tracker = True
            conn.tracker_name = tracker["name"]
            conn.tracker_company = tracker.get("company", "Unknown")
            conn.tracker_category = tracker.get("category", "Unknown")
            conn.tracker_severity = tracker.get("severity", "medium")
            self.stats.trackers_found.add(conn.tracker_name)
            self.stats.tracker_bytes += conn.length

        # GeoIP
        conn.geo = self.geo_resolver.resolve(target_ip)

        # Update stats
        self.stats.total_packets += 1
        self.stats.total_bytes += conn.length
        self.stats.unique_endpoints.add(target_ip)
        self.stats.unique_destinations.add(conn.dst_host or target_ip)
        self.stats.protocols[conn.proto_display] += 1

        if conn.geo and conn.geo.country_code != "??":
            self.stats.countries[conn.geo.country] += 1

        # DNS
        if conn.dns_query:
            self.stats.total_dns_queries += 1

        # Bandwidth tracking
        self._bytes_window.append((time.time(), conn.length))

        # App stats
        app_key = conn.app_name
        if app_key not in self.app_stats:
            self.app_stats[app_key] = AppTrafficStats(
                name=app_key, pid=conn.app_pid, first_seen=time.time()
            )
        app = self.app_stats[app_key]
        app.packet_count += 1
        app.last_seen = time.time()
        app.destinations.add(conn.dst_host or target_ip)
        if conn.is_outbound:
            app.total_bytes_sent += conn.length
        else:
            app.total_bytes_recv += conn.length
        if conn.is_tracker:
            app.tracker_hits += 1

        # Dest stats
        dest_key = conn.dst_host or target_ip
        self.dest_stats[dest_key]["bytes"] += conn.length
        self.dest_stats[dest_key]["packets"] += 1
        self.dest_stats[dest_key]["host"] = conn.dst_host
        self.dest_stats[dest_key]["geo"] = conn.geo

        # Company aggregation
        company = resolve_company(conn.dst_host)
        if company:
            self.company_stats[company]["bytes"] += conn.length
            self.company_stats[company]["apps"].add(conn.app_name)
            self.company_stats[company]["connections"] += 1
            if conn.is_tracker:
                self.company_stats[company]["trackers"] += 1

        # Phone-home tracking
        if conn.is_outbound and conn.app_name != "Unknown":
            ph = self.phone_home_apps[conn.app_name]
            ph["silent_connections"] += 1
            ph["destinations"].add(conn.dst_host or target_ip)
            if ph["first_seen"] == 0:
                ph["first_seen"] = time.time()
            ph["last_seen"] = time.time()
            ph["total_bytes"] += conn.length
            if conn.is_tracker:
                ph["tracker_connections"] += 1

        # Store connection
        with self._conn_lock:
            self.connections.append(conn)
            if len(self.connections) > 50000:
                self.connections = self.connections[-25000:]

        # Calculate privacy score
        self._update_privacy_score()

        # Check for alerts
        self._check_alerts(conn)

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(conn)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    def _update_privacy_score(self):
        """Calculate privacy exposure score (0-100)."""
        score = 0
        score += min(30, len(self.stats.trackers_found) * 3)
        score += min(20, len(self.stats.unique_destinations) * 0.3)
        score += min(15, self.stats.tracker_bytes / (1024 * 1024) * 5)
        score += min(15, len(self.stats.countries) * 2)
        score += min(20, sum(1 for a in self.app_stats.values() if a.tracker_hits > 0) * 4)
        self.stats.privacy_score = min(99, score)

    def _check_alerts(self, conn: ConnectionInfo):
        """Generate alerts for suspicious activity."""
        alerts = []

        if conn.is_tracker and conn.tracker_severity == "critical":
            alerts.append({
                "time": time.time(),
                "level": "critical",
                "message": f"Critical tracker active: {conn.tracker_name} ({conn.tracker_company})",
                "app": conn.app_name,
            })

        if conn.dst_port not in (80, 443, 53, 8080, 8443) and conn.is_outbound:
            if not self.geo_resolver.is_private(conn.dst_ip):
                alerts.append({
                    "time": time.time(),
                    "level": "warning",
                    "message": f"Unusual port {conn.dst_port} → {conn.dst_host or conn.dst_ip}",
                    "app": conn.app_name,
                })

        for alert in alerts:
            self.stats.alerts.append(alert)
            if len(self.stats.alerts) > 500:
                self.stats.alerts = self.stats.alerts[-250:]
            for cb in self._alert_callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass

    def _bandwidth_loop(self):
        """Calculate bandwidth every second."""
        while self.running:
            now = time.time()
            self._bytes_window = [(t, b) for t, b in self._bytes_window if now - t < 1.0]
            self._current_bps = sum(b for _, b in self._bytes_window)
            self.stats.bandwidth_history.append((now, self._current_bps))
            if len(self.stats.bandwidth_history) > 3600:
                self.stats.bandwidth_history = self.stats.bandwidth_history[-1800:]
            time.sleep(1)

    @property
    def bandwidth(self) -> float:
        """Current bandwidth in bytes/sec."""
        return self._current_bps

    @property
    def capture_mode(self) -> str:
        return self._capture_mode

    def get_recent_connections(self, n: int = 50) -> List[ConnectionInfo]:
        with self._conn_lock:
            return list(self.connections[-n:])

    def get_top_apps(self, n: int = 20) -> List[AppTrafficStats]:
        return sorted(
            self.app_stats.values(),
            key=lambda a: a.total_bytes_sent + a.total_bytes_recv,
            reverse=True
        )[:n]

    def get_top_destinations(self, n: int = 20) -> List[tuple]:
        return sorted(
            self.dest_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:n]

    def get_company_data(self) -> dict:
        """Get company aggregation data (serializable)."""
        result = {}
        for company, data in sorted(
            self.company_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:12]:
            result[company] = {
                "bytes": data["bytes"],
                "apps": len(data["apps"]),
                "trackers": data["trackers"],
                "connections": data["connections"],
            }
        return result

    def get_phone_home_data(self) -> list:
        """Get phone-home detection data sorted by suspiciousness."""
        results = []
        for app_name, data in self.phone_home_apps.items():
            if data["silent_connections"] < 2:
                continue
            suspicion_score = 0
            suspicion_score += min(30, data["silent_connections"] * 0.5)
            suspicion_score += min(25, len(data["destinations"]) * 3)
            suspicion_score += min(25, data["tracker_connections"] * 5)
            suspicion_score += min(20, data["total_bytes"] / (1024 * 100))
            results.append({
                "app": app_name,
                "connections": data["silent_connections"],
                "destinations": len(data["destinations"]),
                "tracker_connections": data["tracker_connections"],
                "bytes": data["total_bytes"],
                "suspicion": min(100, suspicion_score),
                "duration": data["last_seen"] - data["first_seen"] if data["first_seen"] else 0,
            })
        return sorted(results, key=lambda x: x["suspicion"], reverse=True)[:20]

    def export_json(self, filepath: str):
        """Export captured data to JSON."""
        data = {
            "session": {
                "start": self.stats.start_time,
                "duration": time.time() - self.stats.start_time,
                "total_packets": self.stats.total_packets,
                "total_bytes": self.stats.total_bytes,
                "privacy_score": self.stats.privacy_score,
            },
            "trackers": list(self.stats.trackers_found),
            "endpoints": list(self.stats.unique_endpoints),
            "protocols": dict(self.stats.protocols),
            "countries": dict(self.stats.countries),
            "companies": self.get_company_data(),
            "phone_home": self.get_phone_home_data(),
            "apps": {
                name: {
                    "bytes_sent": app.total_bytes_sent,
                    "bytes_recv": app.total_bytes_recv,
                    "packets": app.packet_count,
                    "tracker_hits": app.tracker_hits,
                    "destinations": list(app.destinations),
                }
                for name, app in self.app_stats.items()
            },
            "connections": [
                {
                    "time": c.timestamp,
                    "app": c.app_name,
                    "src": f"{c.src_ip}:{c.src_port}",
                    "dst": f"{c.dst_ip}:{c.dst_port}",
                    "host": c.dst_host,
                    "protocol": c.proto_display,
                    "bytes": c.length,
                    "tracker": c.tracker_name if c.is_tracker else None,
                }
                for c in self.connections[-5000:]
            ],
            "alerts": self.stats.alerts[-100:],
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def export_csv(self, filepath: str):
        """Export connections to CSV."""
        import csv
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "App", "PID", "Source IP", "Source Port",
                "Dest IP", "Dest Port", "Hostname", "Protocol", "Bytes",
                "Direction", "Is Tracker", "Tracker Name", "Tracker Company",
                "Country", "City", "Org"
            ])
            for c in self.connections:
                writer.writerow([
                    datetime.fromtimestamp(c.timestamp).isoformat(),
                    c.app_name, c.app_pid, c.src_ip, c.src_port,
                    c.dst_ip, c.dst_port, c.dst_host, c.proto_display,
                    c.length, c.direction, c.is_tracker, c.tracker_name,
                    c.tracker_company,
                    c.geo.country if c.geo else "",
                    c.geo.city if c.geo else "",
                    c.geo.org if c.geo else "",
                ])
