# ◆ VEIL — Network Traffic Exposer

### Every connection. Every tracker. Every byte. **Exposed.**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

**VEIL** is a real-time network traffic visualization and AI-powered analysis dashboard. It captures every packet leaving your machine, identifies trackers and telemetry, maps connections to a 3D globe, and uses GPT-4.1-nano to generate actionable intelligence about your device's privacy posture.

Built by a practitioner. Open-sourced by **NEATLABS™**.

---

## Features

**Core Engine**
- Three-tier packet capture: Scapy → raw sockets → psutil polling (works with or without admin)
- Aggressive process-to-connection mapping with pre-populated PID cache
- 67+ built-in tracker/ad network signatures with heuristic detection
- GeoIP resolution via ip-api.com with async caching
- Company-level traffic aggregation (Google, Meta, Microsoft, Amazon, etc.)
- Phone-home detection — identifies apps silently beaconing out
- Weighted privacy exposure scoring (0–100) with severity awareness and time decay

**Alert Intelligence (10 detection conditions)**
- Critical tracker detection
- Unusual port usage to external IPs
- First connection to new country
- App connecting to new destination after baseline established
- Suspicious TLD detection (.tk, .xyz, .ru, etc.)
- Unencrypted HTTP to external endpoints
- Large outbound data transfers (>512KB)
- Exfiltration pattern detection (send >> receive ratio)
- DNS tunneling detection (abnormally long subdomains)
- VPS/hosting connections on non-standard ports (potential C2)

**AI Intelligence (Multi-Provider)**
- **Dual AI engine** — supports both OpenAI (GPT-4.1-nano) and Anthropic (Claude Sonnet 4)
- Auto-detects provider from API key format (`sk-...` = OpenAI, `sk-ant-...` = Anthropic)
- Full traffic analysis with threat assessment
- Tracker intelligence reports with cross-tracking risk analysis
- Anomaly detection for potential data exfiltration
- Executive privacy briefs (non-technical audience)
- Automated firewall rule generation (iptables, hosts file, uBlock Origin)
- Interactive chat — ask questions about your traffic in natural language
- **AI chat export** — save analysis results as styled HTML or plain text
- Auto-analysis mode (configurable interval)
- **Privacy Translation Layer** — anonymizes IPs/hostnames before sending to AI (toggle in AI menu)

**Visualization**
- Animated 3D globe with connection arcs, particle streams, ring pulses, and nebula background
- Pulsing neon privacy gauge with color transitions
- Real-time bandwidth sparkline with gradient glow
- Racing bar chart for top-talking applications
- Protocol donut chart
- Company traffic aggregation bars
- Threat level meter with animated fill
- Packet pulse indicator
- Connection timeline with bandwidth overlay
- Destination heatmap with risk scoring

**Data & Export**
- High-performance connection table (model/view architecture, 5000+ rows)
- JSON, CSV, and **styled HTML privacy report** export
- **AI analysis export** — save AI chat results as HTML or TXT from the panel
- Session snapshots with before/after comparison
- IP intelligence lookups (reputation, WHOIS, risk scoring)

**Desktop Integration**
- System tray icon with minimize-to-tray
- Tray popup notifications for critical/high alerts
- Adjustable font size (View menu)
- Privacy mode toggle for AI analysis

---

## Quick Start

```bash
# Clone
git clone https://github.com/neatlabs-ai/veil.git
cd veil

# Install dependencies
pip install -r requirements.txt

# Run (basic — psutil polling, no admin needed)
python main.py

# Run with full packet capture (needs admin/root)
sudo python main.py

# Run with AI analysis (OpenAI or Anthropic — auto-detected from key)
python main.py --key YOUR_API_KEY
```

### Windows
```batch
run_veil.bat
```

---

## Requirements

| Package | Required | Purpose |
|---------|----------|---------|
| `PyQt6` | **Yes** | GUI framework |
| `PyQt6-WebEngine` | Recommended | 3D globe visualization |
| `psutil` | Recommended | Process mapping + fallback capture |
| `scapy` | Optional | Full packet capture (needs admin) |
| `openai==0.28` | Optional | OpenAI GPT analysis |
| `anthropic` | Optional | Anthropic Claude analysis |

```bash
# Minimum
pip install PyQt6 psutil

# Full experience (OpenAI)
pip install PyQt6 PyQt6-WebEngine psutil scapy openai==0.28

# Full experience (Anthropic)
pip install PyQt6 PyQt6-WebEngine psutil scapy anthropic

# Both AI providers
pip install PyQt6 PyQt6-WebEngine psutil scapy openai==0.28 anthropic
```

---

## Architecture

```
veil/
├── main.py              # Entry point
├── core/
│   ├── sniffer.py       # Packet capture engine (3 modes)
│   ├── ai_analyzer.py   # GPT-4.1-nano integration
│   └── ip_intel.py      # IP reputation & WHOIS
├── ui/
│   ├── app.py           # Main window (command center)
│   ├── panels.py        # AI chat, IP intel, timeline, snapshots
│   ├── widgets.py       # Animated gauges, sparklines, charts
│   └── styles.py        # Cyberpunk theme
├── assets/
│   └── globe.html       # Canvas 3D globe (zero dependencies)
├── data/
│   └── trackers.json    # 65+ tracker signatures
├── requirements.txt
├── run_veil.bat          # Windows launcher
└── LICENSE
```

---

## Capture Modes

VEIL automatically detects the best available capture method:

1. **Scapy** (admin/root) — Full packet capture with payload inspection, DNS query logging, and protocol analysis
2. **Raw Socket** (root, Linux) — IP-level capture without scapy dependency
3. **psutil Polling** (no admin) — Connection monitoring via OS network tables. No packet data, but maps every connection to its process

---

## AI Analysis

VEIL supports two AI providers — set your key and it auto-detects which one:

| Provider | Key Format | Default Model | Install |
|----------|-----------|---------------|---------|
| **OpenAI** | `sk-...` | gpt-4.1-nano | `pip install openai==0.28` |
| **Anthropic** | `sk-ant-...` | claude-sonnet-4 | `pip install anthropic` |

Set your key via:
- Command line: `python main.py --key sk-your-key`
- Environment: `export OPENAI_API_KEY=sk-your-key`
- In-app: AI menu → Set API Key

VEIL auto-detects the provider from your key prefix. All 5 analysis modes and interactive chat work identically with both providers.

**Privacy Mode:** Enable in AI menu to anonymize IPs and hostnames before they reach any external API.

---

## Screenshots

The dashboard features a cyberpunk aesthetic with:
- Dominant cyan (#00f0ff) with magenta, green, and red accents
- Deep space background (#050510)
- Monospace typography (Consolas)
- Animated widgets with breathing glow effects
- 3D globe with particle streams and ring pulses

---

## Contributing

Contributions welcome. VEIL is a single-developer project built from 28+ years of federal cybersecurity experience — but the code is open and the community is invited.

1. Fork the repo
2. Create a feature branch
3. Submit a PR with a clear description

---

## Disclaimer

VEIL is a **defensive** network monitoring tool for analyzing your own device's traffic. It is designed for privacy awareness, security research, and educational purposes.

- Only capture traffic on networks you own or have permission to monitor
- Packet capture may require administrator/root privileges
- AI analysis sends traffic metadata to OpenAI or Anthropic API (if configured). **Enable Privacy Mode** (AI menu) to anonymize IPs and hostnames before they reach any external API.
- GeoIP lookups use ip-api.com (free tier, rate limited)

---

## Changelog

### v3.1.0 — Intelligence Upgrade
**Core Engine**
- **10-condition alert system** — new country detection, suspicious TLDs, exfiltration patterns, DNS tunneling, VPS/C2 detection, unencrypted HTTP, large transfers
- **Weighted privacy score** — severity-aware tracker scoring, HTTP penalty, time decay, exfiltration signal
- **Aggressive process resolution** — pre-populated PID cache, port-to-PID mapping, 3-tier lookup (dramatically reduces "Unknown" apps)

**AI Engine**
- **Multi-provider support** — OpenAI (GPT-4.1-nano) and Anthropic (Claude Sonnet 4)
- Auto-detects provider from API key format (`sk-...` vs `sk-ant-...`)
- **Privacy Translation Layer** — anonymize IPs/hostnames before AI analysis (toggle in AI menu)

**UI / UX**
- **Enhanced AI chat readability** — 13px font, 170% line height, proper markdown rendering (headers, bullets, numbered lists, bold)
- **AI analysis export** — EXPORT button saves chat as styled HTML or plain text
- **HTML privacy report export** — cyberpunk-styled report with letter grade, opens in browser
- **System tray** — minimize to tray, tray popup notifications for critical alerts, live score tooltip
- **High-performance connection table** — QAbstractTableModel replacing QTableWidget, handles 5000+ rows
- **Adjustable font size** — View menu with 4 size options
- **Inline globe** — embedded via setHtml() for guaranteed rendering (no file path dependency)
- **Auto-organize** — flat-folder downloads auto-restructure on first run

### v3.0.0 — Initial Release
- Three-tier packet capture (Scapy / raw socket / psutil)
- 67 tracker/ad network signatures
- GPT-4.1-nano AI analysis (5 modes + interactive chat)
- 3D globe with connection arcs and particle effects
- 8 animated cyberpunk widgets
- Company-level traffic aggregation
- Phone-home detection
- IP intelligence lookups
- JSON/CSV export

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Credits

**VEIL** is a [NEATLABS™](https://github.com/neatlabs-ai) project — a Service-Disabled Veteran-Owned Small Business (SDVOSB) with 28+ years of federal cybersecurity experience.

Built with Python, PyQt6, Scapy, OpenAI, Anthropic, and HTML5 Canvas.

*Intelligence Technology — Built by Practitioners.*

Copyright © 2025-2026 NEATLABS™ / Security 360, LLC
