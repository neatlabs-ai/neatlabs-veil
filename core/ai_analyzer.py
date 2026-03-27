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


class AIAnalyzer:
    """
    GPT-4.1-nano powered network traffic analyzer.
    Provides intelligent summaries, threat assessments, and recommendations.
    """

    def __init__(self, api_key: str = "", model: str = "gpt-4.1-nano"):
        self.api_key = api_key
        self.model = model
        self._available = False
        self._client = None
        self._lock = threading.Lock()
        self._analysis_cache: Dict[str, dict] = {}
        self._callbacks: List[Callable] = []
        self._conversation_history: List[dict] = []

        # Analysis state
        self.last_summary = ""
        self.last_threat_report = ""
        self.last_recommendations = []
        self.analysis_count = 0

        if api_key:
            self._init_client()

    def _init_client(self):
        """Initialize OpenAI client (older style)."""
        try:
            import openai
            openai.api_key = self.api_key
            self._client = openai
            self._available = True
            logger.info(f"AI Analyzer initialized with model: {self.model}")
        except ImportError:
            logger.warning("openai package not installed — AI features disabled")
            logger.warning("Install with: pip install openai==0.28")
            self._available = False

    def set_api_key(self, key: str):
        """Set or update the API key."""
        self.api_key = key
        self._init_client()

    @property
    def is_available(self) -> bool:
        return self._available and bool(self.api_key)

    def on_analysis(self, callback: Callable):
        """Register callback for when analysis completes."""
        self._callbacks.append(callback)

    def _notify(self, analysis_type: str, result: dict):
        for cb in self._callbacks:
            try:
                cb(analysis_type, result)
            except Exception as e:
                logger.debug(f"AI callback error: {e}")

    def _call_gpt(self, system_prompt: str, user_prompt: str,
                   temperature: float = 0.3, max_tokens: int = 1500) -> str:
        """Make a ChatCompletion call to GPT-4.1-nano (older API style)."""
        if not self.is_available:
            return "[AI unavailable — set OpenAI API key via AI → Set API Key]"

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
            logger.error(f"GPT API error: {e}")
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
                logger.error(f"GPT fallback API error: {e2}")
                return f"[AI Error: {str(e2)[:100]}]"

    def _call_gpt_conversation(self, messages: list,
                                temperature: float = 0.4, max_tokens: int = 2000) -> str:
        """Make a multi-turn conversation call."""
        if not self.is_available:
            return "[AI unavailable — set OpenAI API key]"

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
                return f"[AI Error: {str(e)[:100]}]"

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
Privacy Score: {stats.privacy_score:.0f}/100

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

        return snapshot

    def analyze_traffic_summary(self, engine, callback=None):
        """Generate comprehensive traffic analysis."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI, the intelligence engine for the VEIL Network Traffic Exposer by NEATLABS. You are a world-class network forensics and privacy analyst. You analyze real-time network traffic data and provide clear, actionable intelligence about what a user's computer is doing on the network.

Your analysis should be thorough but accessible. Use specific data from the traffic snapshot. Flag anything concerning. Be direct about privacy risks."""

            prompt = f"""Analyze this network traffic capture and provide a comprehensive assessment:

{snapshot}

Provide your analysis in these sections:
1. ## Overall Assessment — Quick summary of network health and privacy posture
2. ## Traffic Profile — What kind of activity is this device generating?
3. ## Privacy Concerns — Specific tracking, telemetry, and data leakage issues
4. ## Application Behavior — Which apps are the most active/concerning?
5. ## Geographic Intelligence — Where is data flowing and why?
6. ## Immediate Recommendations — Top 3-5 actions to take right now"""

            result = self._call_gpt(system, prompt, temperature=0.3, max_tokens=2000)
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

            result = self._call_gpt(system, prompt, temperature=0.3, max_tokens=2000)
            self.last_threat_report = result
            self._notify("tracker_intel", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def analyze_anomalies(self, engine, callback=None):
        """Detect and analyze anomalous network behavior."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI, a network anomaly detection specialist. You look for unusual patterns, potential data exfiltration, command-and-control communications, unusual ports, suspicious destinations, and other indicators of compromise or privacy violations."""

            prompt = f"""Analyze this traffic for anomalies and potential security concerns:

{snapshot}

Focus on:
1. ## Anomalous Patterns — Any unusual connection patterns, timing, or volumes?
2. ## Potential Data Exfiltration — Signs of unauthorized data leaving the network?
3. ## Suspicious Destinations — Unusual countries, unknown organizations, or concerning endpoints?
4. ## Port Analysis — Any unusual or potentially dangerous port usage?
5. ## Indicators of Compromise — Any patterns matching known attack signatures?
6. ## Baseline Assessment — What appears normal vs. what needs investigation?"""

            result = self._call_gpt(system, prompt, temperature=0.2)
            self._notify("anomaly", {"text": result, "time": time.time()})
            if callback: callback(result)

        threading.Thread(target=_run, daemon=True).start()

    def generate_executive_brief(self, engine, callback=None):
        """Generate a short executive-style privacy brief."""
        def _run():
            snapshot = self._build_traffic_snapshot(engine)

            system = """You are VEIL AI. Generate a concise executive privacy brief suitable for a non-technical audience. Use clear language, avoid jargon, and focus on the impact to the user's privacy."""

            prompt = f"""Based on this traffic data, write a brief 1-page executive privacy assessment:

{snapshot}

Format as:
## YOUR DEVICE PRIVACY REPORT
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

Include: Overall rating (A-F grade), key findings (bullet points), what data is being shared and with whom, and 3 immediate actions to improve privacy."""

            result = self._call_gpt(system, prompt, temperature=0.4)
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

            result = self._call_gpt(system, prompt, temperature=0.2, max_tokens=2000)
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

You have access to the following real-time traffic data:

{snapshot}

Rules:
- Answer based on the actual traffic data provided
- Be specific and reference actual apps, hosts, and trackers from the data
- If asked something not in the data, say so honestly
- Provide actionable advice when relevant
- Keep responses concise but informative
- You can format with markdown headers and bullet points"""

            messages = [{"role": "system", "content": system}]

            for msg in self._conversation_history[-6:]:
                messages.append(msg)

            messages.append({"role": "user", "content": user_message})

            result = self._call_gpt_conversation(messages, temperature=0.4, max_tokens=1500)

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
