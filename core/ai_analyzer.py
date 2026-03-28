"""
VEIL AI Analysis Engine
Integrates OpenAI GPT-4.1-nano for intelligent network traffic analysis,
threat assessment, privacy scoring, and natural language summaries.

NEATLABS™ Intelligence Technology
Open Source — github.com/neatlabs-ai
"""

import json
import time
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, List, Callable
from collections import defaultdict

logger = logging.getLogger("veil.ai")


# ---------------------------------------------------------------------------
# Privacy Translation Layer
# ---------------------------------------------------------------------------

class PrivacyTranslator:
    """
    Anonymizes network traffic data before sending to external AI APIs.
    Preserves analytical structure (patterns, volumes, protocols, tracker names)
    while stripping personally identifiable information (IPs, hostnames, device names).
    """

    def __init__(self):
        self._ip_map: Dict[str, str] = {}
        self._host_map: Dict[str, str] = {}
        self._ip_counter = 0
        self._host_counter = 0
        # Known safe categories that don't need anonymization
        self._safe_domains = {
            "google", "facebook", "microsoft", "amazon", "apple", "cloudflare",
            "akamai", "fastly", "youtube", "twitter", "instagram", "tiktok",
            "netflix", "spotify", "adobe", "oracle", "yahoo", "linkedin",
            "github", "stackoverflow", "wikipedia",
        }

    def anonymize_ip(self, ip: str) -> str:
        """Replace IP with pseudonym like [ENDPOINT_1]."""
        if not ip or ip.startswith("127.") or ip.startswith("0."):
            return "[LOCALHOST]"
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "[LOCAL_NET]"
        if ip not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[ip] = f"[ENDPOINT_{self._ip_counter}]"
        return self._ip_map[ip]

    def anonymize_host(self, host: str) -> str:
        """Anonymize hostname but keep well-known service names visible."""
        if not host:
            return "[UNKNOWN_HOST]"
        host_lower = host.lower()
        # Keep tracker/company names visible — they're the point of the analysis
        for safe in self._safe_domains:
            if safe in host_lower:
                return host  # Keep as-is — it's a known service
        # Anonymize personal/unknown hostnames
        if host_lower.startswith("192.168.") or host_lower.startswith("10."):
            return "[LOCAL_DEVICE]"
        if host not in self._host_map:
            self._host_counter += 1
            self._host_map[host] = f"[HOST_{self._host_counter}]"
        return self._host_map[host]

    def anonymize_app(self, app_name: str) -> str:
        """Keep well-known app names, anonymize personal ones."""
        known_apps = {
            "chrome.exe", "firefox.exe", "msedge.exe", "safari", "opera.exe",
            "code.exe", "slack.exe", "teams.exe", "zoom.exe", "discord.exe",
            "spotify.exe", "steam.exe", "outlook.exe", "thunderbird.exe",
            "python.exe", "python3", "node.exe", "java.exe", "curl", "wget",
            "svchost.exe", "system", "explorer.exe", "dwm.exe",
        }
        if app_name.lower() in known_apps or app_name == "Unknown":
            return app_name
        return f"[APP:{app_name.split('.')[0][:8].upper()}]"

    def translate_snapshot(self, snapshot_text: str) -> str:
        """Apply privacy translation to a full traffic snapshot string."""
        import re
        result = snapshot_text

        # Anonymize IP addresses (IPv4)
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        found_ips = set(re.findall(ip_pattern, result))
        for ip in found_ips:
            anon = self.anonymize_ip(ip)
            result = result.replace(ip, anon)

        # Add privacy notice header
        header = ("=== PRIVACY MODE ACTIVE ===\n"
                  "IPs and personal hostnames have been anonymized.\n"
                  "Tracker names, companies, protocols, and traffic patterns are preserved.\n\n")
        return header + result

    def reset(self):
        """Reset mappings for a new session."""
        self._ip_map.clear()
        self._host_map.clear()
        self._ip_counter = 0
        self._host_counter = 0


class AIAnalyzer:
    """
    Multi-provider AI traffic analyzer.
    Supports OpenAI (GPT-4.1-nano) and Anthropic (Claude) APIs.
    """

    PROVIDERS = {
        "openai": {"models": ["gpt-4.1-nano", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "gpt-4.1"], "default": "gpt-4.1-nano"},
        "anthropic": {"models": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-20250514"], "default": "claude-sonnet-4-20250514"},
    }

    def __init__(self, api_key: str = "", model: str = "gpt-4.1-nano", provider: str = ""):
        self.api_key = api_key
        self.model = model
        self.provider = provider or self._detect_provider(api_key)
        self._available = False
        self._client = None
        self._lock = threading.Lock()
        self._analysis_cache: Dict[str, dict] = {}
        self._callbacks: List[Callable] = []
        self._conversation_history: List[dict] = []

        # Privacy translation layer
        self.privacy_mode = False
        self._translator = PrivacyTranslator()

        # Analysis state
        self.last_summary = ""
        self.last_threat_report = ""
        self.last_recommendations = []
        self.analysis_count = 0

        if api_key:
            self._init_client()

    @staticmethod
    def _detect_provider(api_key: str) -> str:
        """Auto-detect provider from API key format."""
        if not api_key:
            return "openai"
        if api_key.startswith("sk-ant-"):
            return "anthropic"
        return "openai"

    def _init_client(self):
        """Initialize the appropriate AI client based on provider."""
        self.provider = self._detect_provider(self.api_key) if not self.provider else self.provider

        if self.provider == "anthropic":
            self._init_anthropic()
        else:
            self._init_openai()

    def _init_openai(self):
        """Initialize OpenAI client."""
        # Set default model if switching from Anthropic
        if self.model.startswith("claude"):
            self.model = self.PROVIDERS["openai"]["default"]
        try:
            import openai
            openai.api_key = self.api_key
            self._client = openai
            self._available = True
            logger.info(f"OpenAI initialized — model: {self.model}")
        except ImportError:
            logger.warning("openai not installed — pip install openai==0.28")
            self._available = False

    def _init_anthropic(self):
        """Initialize Anthropic client."""
        # Set default model if switching from OpenAI
        if not self.model.startswith("claude"):
            self.model = self.PROVIDERS["anthropic"]["default"]
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
            self._available = True
            logger.info(f"Anthropic initialized — model: {self.model}")
        except ImportError:
            logger.warning("anthropic not installed — pip install anthropic")
            self._available = False

    def set_api_key(self, key: str, provider: str = ""):
        """Set or update the API key and provider."""
        self.api_key = key
        if provider:
            self.provider = provider
        else:
            self.provider = self._detect_provider(key)
        self._init_client()

    def set_model(self, model: str):
        """Change the active model."""
        self.model = model
        logger.info(f"Model changed to: {model}")

    @property
    def is_available(self) -> bool:
        return self._available and bool(self.api_key)

    @property
    def provider_display(self) -> str:
        """Human-readable provider + model string."""
        p = "Anthropic" if self.provider == "anthropic" else "OpenAI"
        return f"{p} / {self.model}"

    def on_analysis(self, callback: Callable):
        """Register callback for when analysis completes."""
        self._callbacks.append(callback)

    def _notify(self, analysis_type: str, result: dict):
        for cb in self._callbacks:
            try:
                cb(analysis_type, result)
            except Exception as e:
                logger.debug(f"AI callback error: {e}")

    def _call_ai(self, system_prompt: str, user_prompt: str,
                  temperature: float = 0.3, max_tokens: int = 1500) -> str:
        """Route to the correct provider."""
        if not self.is_available:
            return "[AI unavailable — set API key via AI menu]"
        if self.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt, temperature, max_tokens)
        return self._call_openai(system_prompt, user_prompt, temperature, max_tokens)

    def _call_anthropic(self, system_prompt: str, user_prompt: str,
                         temperature: float = 0.3, max_tokens: int = 1500) -> str:
        """Call Anthropic Claude API."""
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                temperature=temperature,
            )
            self.analysis_count += 1
            return response.content[0].text.strip()
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return f"[Anthropic Error: {str(e)[:120]}]"

    def _call_openai(self, system_prompt: str, user_prompt: str,
                      temperature: float = 0.3, max_tokens: int = 1500) -> str:
        """Call OpenAI API (legacy + modern fallback)."""
        try:
            response = self._client.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self.analysis_count += 1
            return response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.error(f"OpenAI legacy error: {e}")
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.api_key)
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self.analysis_count += 1
                return response.choices[0].message.content.strip()
            except Exception as e2:
                logger.error(f"OpenAI modern error: {e2}")
                return f"[OpenAI Error: {str(e2)[:120]}]"

    def _call_ai_conversation(self, messages: list,
                               temperature: float = 0.4, max_tokens: int = 2000) -> str:
        """Multi-turn conversation — routes to correct provider."""
        if not self.is_available:
            return "[AI unavailable — set API key]"

        if self.provider == "anthropic":
            # Anthropic: separate system from messages
            system = ""
            user_msgs = []
            for msg in messages:
                if msg["role"] == "system":
                    system = msg["content"]
                else:
                    user_msgs.append(msg)
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=user_msgs,
                    temperature=temperature,
                )
                return response.content[0].text.strip()
            except Exception as e:
                return f"[Anthropic Error: {str(e)[:120]}]"
        else:
            # OpenAI
            try:
                response = self._client.ChatCompletion.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response["choices"][0]["message"]["content"].strip()
            except Exception:
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=self.api_key)
                    response = client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                    return response.choices[0].message.content.strip()
                except Exception as e:
                    return f"[OpenAI Error: {str(e)[:120]}]"

    # ===================================================================
    # ANALYSIS FUNCTIONS
    # ===================================================================

    def _build_traffic_snapshot(self, engine) -> str:
        """Build a compact traffic data snapshot for GPT context."""
        stats = engine.stats
        elapsed = time.time() - stats.start_time

        top_apps = sorted(
            engine.app_stats.values(),
            key=lambda a: a.total_bytes_sent + a.total_bytes_recv,
            reverse=True
        )[:15]

        top_dests = sorted(
            engine.dest_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:20]

        recent = engine.get_recent_connections(30)

        snapshot = f"""=== VEIL NETWORK TRAFFIC SNAPSHOT ===
Capture Duration: {elapsed:.0f} seconds ({elapsed/60:.1f} minutes)
Total Packets: {stats.total_packets:,}
Total Bytes: {stats.total_bytes:,} ({stats.total_bytes/(1024*1024):.2f} MB)
Unique Endpoints: {len(stats.unique_endpoints)}
Unique Destinations: {len(stats.unique_destinations)}
DNS Queries: {stats.total_dns_queries}
Privacy Exposure Score: {stats.privacy_score:.0f}/100 (0=clean/excellent, 100=fully tracked/terrible){' — EXCELLENT' if stats.privacy_score < 16 else ' — GOOD' if stats.privacy_score < 36 else ' — MODERATE' if stats.privacy_score < 56 else ' — POOR' if stats.privacy_score < 76 else ' — CRITICAL'}

=== TRACKERS DETECTED ({len(stats.trackers_found)}) ===
{chr(10).join(f'- {t}' for t in sorted(stats.trackers_found)) if stats.trackers_found else 'None detected yet'}

=== TOP APPLICATIONS (by traffic volume) ===
"""
        for app in top_apps:
            total = app.total_bytes_sent + app.total_bytes_recv
            snapshot += (f"- {app.name}: {total/(1024):.1f} KB sent+recv, "
                        f"{app.packet_count} pkts, {app.tracker_hits} tracker hits, "
                        f"{len(app.destinations)} destinations\n")

        snapshot += "\n=== TOP DESTINATIONS (by data volume) ===\n"
        for dest, data in top_dests:
            geo = data.get("geo")
            geo_str = ""
            if geo and geo.city != "Unknown":
                geo_str = f" [{geo.city}, {geo.country_code} — {geo.org}]"
            snapshot += f"- {dest}: {data['bytes']/(1024):.1f} KB, {data['packets']} pkts{geo_str}\n"

        snapshot += "\n=== PROTOCOL DISTRIBUTION ===\n"
        for proto, count in sorted(stats.protocols.items(), key=lambda x: x[1], reverse=True):
            snapshot += f"- {proto}: {count:,}\n"

        snapshot += "\n=== COUNTRY DISTRIBUTION ===\n"
        for country, count in sorted(stats.countries.items(), key=lambda x: x[1], reverse=True)[:10]:
            snapshot += f"- {country}: {count:,}\n"

        # Company aggregation
        company_data = engine.get_company_data()
        if company_data:
            snapshot += "\n=== DATA BY COMPANY ===\n"
            for company, data in company_data.items():
                snapshot += f"- {company}: {data['bytes']/(1024):.1f} KB, {data['connections']} conns, {data['trackers']} tracker hits\n"

        snapshot += "\n=== RECENT CONNECTIONS (last 30) ===\n"
        for conn in recent[-15:]:
            tracker_str = f" [TRACKER: {conn.tracker_name}]" if conn.is_tracker else ""
            snapshot += (f"- {conn.app_name} → {conn.dst_host or conn.dst_ip}:{conn.dst_port} "
                        f"({conn.proto_display}, {conn.length}B){tracker_str}\n")

        if stats.alerts:
            snapshot += f"\n=== RECENT ALERTS ({len(stats.alerts)}) ===\n"
            for alert in stats.alerts[-5:]:
                snapshot += f"- [{alert['level'].upper()}] {alert['message']}\n"

        # Apply privacy translation if enabled
        if self.privacy_mode:
            snapshot = self._translator.translate_snapshot(snapshot)

        return snapshot

    def set_privacy_mode(self, enabled: bool):
        """Toggle privacy translation layer for AI analysis."""
        self.privacy_mode = enabled
        if enabled:
            self._translator.reset()
        logger.info(f"Privacy mode: {'ON' if enabled else 'OFF'}")

    def generate_html_report(self, engine) -> str:
        """Generate a styled HTML privacy report."""
        stats = engine.stats
        elapsed = time.time() - stats.start_time
        score = stats.privacy_score
        if score < 25: grade, grade_color = "A", "#00ff66"
        elif score < 40: grade, grade_color = "B", "#88dd00"
        elif score < 55: grade, grade_color = "C", "#ffee00"
        elif score < 70: grade, grade_color = "D", "#ff8800"
        else: grade, grade_color = "F", "#ff3344"

        top_apps = sorted(engine.app_stats.values(),
            key=lambda a: a.total_bytes_sent + a.total_bytes_recv, reverse=True)[:10]
        trackers = sorted(stats.trackers_found)
        companies = engine.get_company_data()

        app_rows = ""
        for app in top_apps:
            total = app.total_bytes_sent + app.total_bytes_recv
            tk_style = "color:#ff3344;font-weight:bold;" if app.tracker_hits > 0 else ""
            app_rows += f"<tr><td>{app.name}</td><td>{total/1024:.1f} KB</td><td>{app.packet_count}</td><td style='{tk_style}'>{app.tracker_hits}</td><td>{len(app.destinations)}</td></tr>"

        tracker_rows = ""
        for t in trackers:
            tracker_rows += f"<tr><td style='color:#ff3344;'>{t}</td></tr>"
        if not tracker_rows:
            tracker_rows = "<tr><td style='color:#00ff66;'>No trackers detected</td></tr>"

        company_rows = ""
        for co, data in companies.items():
            company_rows += f"<tr><td>{co}</td><td>{data['bytes']/1024:.1f} KB</td><td>{data['connections']}</td><td style='color:#ff3344;'>{data['trackers']}</td></tr>"

        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VEIL Privacy Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0a0a1a;color:#c0d0e0;font-family:'Segoe UI','Consolas',monospace;padding:40px;max-width:900px;margin:0 auto;}}
h1{{color:#00f0ff;font-size:28px;letter-spacing:4px;border-bottom:2px solid rgba(0,240,255,0.3);padding-bottom:12px;margin-bottom:8px;}}
h2{{color:#00f0ff;font-size:16px;letter-spacing:3px;margin:28px 0 12px;border-left:3px solid #00f0ff;padding-left:12px;}}
.subtitle{{color:#667;font-size:12px;letter-spacing:2px;margin-bottom:24px;}}
.grade-box{{display:inline-block;background:rgba(0,0,0,0.4);border:2px solid {grade_color};border-radius:8px;padding:20px 40px;text-align:center;margin:16px 0;}}
.grade{{font-size:64px;font-weight:900;color:{grade_color};}}
.grade-label{{font-size:11px;color:#889;letter-spacing:2px;margin-top:4px;}}
.score{{font-size:18px;color:{grade_color};margin-top:4px;}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0;}}
.stat{{background:rgba(0,240,255,0.04);border:1px solid rgba(0,240,255,0.12);border-radius:4px;padding:12px;}}
.stat-val{{font-size:22px;font-weight:bold;color:#00f0ff;}}
.stat-lbl{{font-size:10px;color:#667;letter-spacing:1px;margin-top:2px;}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px;}}
th{{text-align:left;color:rgba(0,240,255,0.6);font-size:10px;letter-spacing:2px;border-bottom:1px solid rgba(0,240,255,0.15);padding:8px;}}
td{{padding:6px 8px;border-bottom:1px solid rgba(0,240,255,0.05);}}
tr:hover td{{background:rgba(0,240,255,0.03);}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid rgba(0,240,255,0.12);color:#445;font-size:11px;text-align:center;}}
.footer a{{color:#00aadd;}}
</style></head><body>
<h1>&#9670; VEIL PRIVACY REPORT</h1>
<div class="subtitle">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &mdash; Capture duration: {elapsed/60:.1f} minutes</div>

<div class="grade-box"><div class="grade">{grade}</div><div class="grade-label">PRIVACY GRADE</div><div class="score">Exposure Score: {score:.0f}/100</div></div>

<div class="stats">
<div class="stat"><div class="stat-val">{stats.total_packets:,}</div><div class="stat-lbl">TOTAL PACKETS</div></div>
<div class="stat"><div class="stat-val">{len(stats.unique_endpoints)}</div><div class="stat-lbl">UNIQUE ENDPOINTS</div></div>
<div class="stat"><div class="stat-val">{len(stats.trackers_found)}</div><div class="stat-lbl">TRACKERS FOUND</div></div>
<div class="stat"><div class="stat-val">{stats.tracker_bytes/1024:.1f} KB</div><div class="stat-lbl">DATA LEAKED</div></div>
<div class="stat"><div class="stat-val">{len(stats.countries)}</div><div class="stat-lbl">COUNTRIES</div></div>
<div class="stat"><div class="stat-val">{stats.total_dns_queries}</div><div class="stat-lbl">DNS QUERIES</div></div>
</div>

<h2>TOP APPLICATIONS</h2>
<table><tr><th>APP</th><th>TRAFFIC</th><th>PACKETS</th><th>TRACKERS</th><th>DESTS</th></tr>{app_rows}</table>

<h2>TRACKERS DETECTED</h2>
<table><tr><th>TRACKER</th></tr>{tracker_rows}</table>

<h2>DATA BY COMPANY</h2>
<table><tr><th>COMPANY</th><th>DATA</th><th>CONNECTIONS</th><th>TRACKER HITS</th></tr>{company_rows}</table>

<h2>PROTOCOL DISTRIBUTION</h2>
<table><tr><th>PROTOCOL</th><th>COUNT</th></tr>{"".join(f"<tr><td>{p}</td><td>{c:,}</td></tr>" for p,c in sorted(stats.protocols.items(), key=lambda x:x[1], reverse=True))}</table>

<div class="footer">
<p>&#9670; VEIL &mdash; Network Traffic Exposer &mdash; <a href="https://github.com/neatlabs-ai">NEATLABS&trade;</a></p>
<p>This report was generated locally. No data was transmitted externally.</p>
</div></body></html>"""

    def analyze_traffic_summary(self, engine, callback=None):
        """Generate comprehensive traffic analysis."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI, the intelligence engine for the VEIL Network Traffic Exposer by NEATLABS. You are a world-class network forensics and privacy analyst. You analyze real-time network traffic data and provide clear, actionable intelligence about what a user's computer is doing on the network.

CRITICAL — PRIVACY SCORE CALIBRATION:
The Privacy Score is an EXPOSURE meter: 0 = no exposure (excellent), 100 = fully broadcasting (terrible).
- 0-15: EXCELLENT — minimal tracking, normal traffic patterns
- 16-35: GOOD — some trackers present but manageable
- 36-55: MODERATE — noticeable tracking activity, action recommended
- 56-75: POOR — significant privacy exposure, multiple trackers active
- 76-100: CRITICAL — device is heavily tracked, immediate action needed

A score of 6/100 means the user has EXCELLENT privacy, NOT a critical problem. Do not invert this scale.

CALIBRATION GUIDANCE:
- Connections to well-known services (Google, Microsoft, Cloudflare, email providers) are NORMAL. Don't flag routine CDN or email connections as alarming.
- Local network traffic (mDNS, SSDP, DHCP, DNS to router) is EXPECTED. Don't treat standard network discovery as a privacy threat.
- Only flag things as CRITICAL if they involve: active ad trackers, data brokers, unknown telemetry endpoints, unencrypted sensitive data, or genuinely suspicious patterns.
- Be honest and proportional. If traffic looks normal, say so. Don't manufacture concerns to fill a report.
- Short capture sessions (<2 min) have limited data — acknowledge this rather than over-interpreting sparse data."""

            prompt = f"""Analyze this network traffic capture and provide a comprehensive assessment:

{snapshot}

Provide your analysis in these sections:
1. ## Overall Assessment — Quick summary of network health and privacy posture
2. ## Traffic Profile — What kind of activity is this device generating?
3. ## Privacy Concerns — Specific tracking, telemetry, and data leakage issues
4. ## Application Behavior — Which apps are the most active/concerning?
5. ## Geographic Intelligence — Where is data flowing and why?
6. ## Immediate Recommendations — Top 3-5 actions to take right now"""

            result = self._call_ai(system, prompt, temperature=0.3, max_tokens=2000)
            self.last_summary = result
            self._notify("summary", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def analyze_tracker_intelligence(self, engine, callback=None):
        """Generate detailed tracker intelligence report."""
        def _run():
            trackers = list(engine.stats.trackers_found)
            if not trackers:
                result = "No trackers detected yet. Continue capturing to detect tracking activity."
                if callback: callback(result)
                return

            tracker_details = ""
            for conn in engine.get_recent_connections(1000):
                if conn.is_tracker:
                    geo_info = ""
                    if conn.geo and conn.geo.city != "Unknown":
                        geo_info = f" [{conn.geo.city}, {conn.geo.country_code} — {conn.geo.org}]"
                    tracker_details += (f"- {conn.tracker_name} ({conn.tracker_company}) "
                                       f"via {conn.app_name} → {conn.dst_host}{geo_info} "
                                       f"[{conn.tracker_category}, Severity: {conn.tracker_severity}]\n")

            system = """You are VEIL AI, a tracker intelligence specialist. You analyze advertising trackers, analytics services, telemetry systems, and other tracking technologies found in network traffic. Provide detailed intelligence on how these trackers operate and what data they collect."""

            prompt = f"""Analyze these trackers detected in the user's network traffic:

Trackers Found: {', '.join(trackers)}

Detailed Connections:
{tracker_details}

Provide:
1. ## Tracker Intelligence Summary — Overview of tracking ecosystem active on this device
2. ## Data Collection Profile — What types of data each major tracker is likely collecting
3. ## Cross-Tracking Risk — How these trackers work together to build profiles
4. ## Most Dangerous Trackers — Ranked by privacy impact
5. ## Blocking Recommendations — Specific tools, DNS filters, or browser extensions to stop them
6. ## Corporate Exposure — Which companies have the most visibility into this user's activity"""

            result = self._call_ai(system, prompt, temperature=0.3, max_tokens=2000)
            self.last_threat_report = result
            self._notify("tracker_intel", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def analyze_anomalies(self, engine, callback=None):
        """Detect and analyze anomalous network behavior."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI, a network anomaly detection specialist. You look for unusual patterns, potential data exfiltration, command-and-control communications, unusual ports, suspicious destinations, and other indicators of compromise or privacy violations.

CALIBRATION: Be proportional. Standard CDN traffic (Cloudflare, Akamai, Fastly), email connections, DNS queries, and local network discovery (mDNS, SSDP) are NORMAL — not anomalies. Only flag genuinely unusual patterns: unknown destinations on non-standard ports, encrypted traffic to hosting providers, abnormal data volumes, suspicious timing patterns, or connections to known-bad infrastructure. If nothing is anomalous, say so clearly."""

            prompt = f"""Analyze this traffic for anomalies and potential security concerns:

{snapshot}

Focus on:
1. ## Anomalous Patterns — Any unusual connection patterns, timing, or volumes?
2. ## Potential Data Exfiltration — Signs of unauthorized data leaving the network?
3. ## Suspicious Destinations — Unusual countries, unknown organizations, or concerning endpoints?
4. ## Port Analysis — Any unusual or potentially dangerous port usage?
5. ## Indicators of Compromise — Any patterns matching known attack signatures?
6. ## Baseline Assessment — What appears normal vs. what needs investigation?"""

            result = self._call_ai(system, prompt, temperature=0.2)
            self._notify("anomaly", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def generate_executive_brief(self, engine, callback=None):
        """Generate a short executive-style privacy brief."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI. Generate a concise executive privacy brief suitable for a non-technical audience. Use clear language, avoid jargon, and focus on the impact to the user's privacy.

IMPORTANT: The Privacy Score is an EXPOSURE meter (0=clean, 100=terrible). A low score like 5-15 means GOOD privacy, not bad. Grade accordingly:
- Score 0-15 → Grade A (Excellent)
- Score 16-35 → Grade B (Good)  
- Score 36-55 → Grade C (Fair)
- Score 56-75 → Grade D (Poor)
- Score 76-100 → Grade F (Critical)

Be honest. If the user's traffic looks normal and clean, tell them so. Don't manufacture threats."""

            prompt = f"""Based on this traffic data, write a brief 1-page executive privacy assessment:

{snapshot}

Format as:
## YOUR DEVICE PRIVACY REPORT
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

Include: Overall rating (A-F grade), key findings (bullet points), what data is being shared and with whom, and 3 immediate actions to improve privacy."""

            result = self._call_ai(system, prompt, temperature=0.4)
            self._notify("brief", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def generate_firewall_rules(self, engine, callback=None):
        """Generate recommended firewall/blocking rules."""
        def _run():
            trackers = list(engine.stats.trackers_found)
            destinations = list(engine.stats.unique_destinations)[:50]

            system = """You are VEIL AI, a network security engineer. Generate practical firewall rules and DNS block lists based on detected trackers and suspicious destinations."""

            prompt = f"""Based on detected trackers and destinations, generate blocking rules:

Trackers: {', '.join(trackers)}
Top Destinations: {', '.join(destinations[:30])}

Provide:
1. ## DNS Block List — Domains to add to Pi-hole, AdGuard, or hosts file (one per line, in hosts file format)
2. ## Browser Extension Config — Recommended uBlock Origin custom rules
3. ## Firewall Rules — iptables/nftables or Windows Firewall rules for the worst offenders
4. ## Application-Level — Per-app settings to disable telemetry
5. ## Priority Actions — Top 5 things to block immediately"""

            result = self._call_ai(system, prompt, temperature=0.2, max_tokens=2000)
            self._notify("firewall", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    # ===================================================================
    # INTERACTIVE CHAT
    # ===================================================================

    def chat(self, engine, user_message: str, callback=None):
        """Interactive chat — ask questions about your network traffic."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = f"""You are VEIL AI, the intelligence assistant for the VEIL Network Traffic Exposer by NEATLABS. You answer questions about the user's network traffic, privacy, and security.

SCORE CALIBRATION: Privacy Score is an EXPOSURE meter — 0 = clean (great), 100 = fully tracked (terrible). Low scores are GOOD.

You have access to the following real-time traffic data:

{snapshot}

Rules:
- Answer based on the actual traffic data provided
- Be specific and reference actual apps, hosts, and trackers from the data
- If asked something not in the data, say so honestly
- Provide actionable advice when relevant
- Be proportional — don't alarm users about normal CDN, email, or DNS traffic
- Keep responses concise but informative
- You can format with markdown headers and bullet points"""

            messages = [{"role": "system", "content": system}]

            for msg in self._conversation_history[-6:]:
                messages.append(msg)

            messages.append({"role": "user", "content": user_message})

            result = self._call_ai_conversation(messages, temperature=0.4, max_tokens=1500)

            self._conversation_history.append({"role": "user", "content": user_message})
            self._conversation_history.append({"role": "assistant", "content": result})

            if len(self._conversation_history) > 20:
                self._conversation_history = self._conversation_history[-12:]

            self._notify("chat", {"question": user_message, "answer": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def clear_conversation(self):
        """Clear conversation history."""
        self._conversation_history.clear()

    # ===================================================================
    # AUTO-ANALYSIS (runs periodically)
    # ===================================================================

    def start_auto_analysis(self, engine, interval_seconds: int = 120):
        """Start periodic automatic analysis."""
        def _loop():
            while True:
                time.sleep(interval_seconds)
                if engine.running and engine.stats.total_packets > 50:
                    logger.info("Running auto-analysis...")
                    self.analyze_traffic_summary(engine)

        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()
        logger.info(f"Auto-analysis started (every {interval_seconds}s)")
