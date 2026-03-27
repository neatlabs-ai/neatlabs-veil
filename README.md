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
- Process-to-connection mapping via psutil
- 65+ built-in tracker/ad network signatures with heuristic detection
- GeoIP resolution via ip-api.com with async caching
- Company-level traffic aggregation (Google, Meta, Microsoft, Amazon, etc.)
- Phone-home detection — identifies apps silently beaconing out
- Privacy exposure scoring (0–100) with weighted formula

**AI Intelligence (GPT-4.1-nano)**
- Full traffic analysis with threat assessment
- Tracker intelligence reports with cross-tracking risk analysis
- Anomaly detection for potential data exfiltration
- Executive privacy briefs (non-technical audience)
- Automated firewall rule generation (iptables, hosts file, uBlock Origin)
- Interactive chat — ask questions about your traffic in natural language
- Auto-analysis mode (configurable interval)

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
- Full connection table with filtering and sorting
- JSON and CSV export
- Session snapshots with before/after comparison
- IP intelligence lookups (reputation, WHOIS, risk scoring)

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

# Run with AI analysis
python main.py --key YOUR_OPENAI_API_KEY
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
| `openai==0.28` | Optional | AI-powered traffic analysis |

```bash
# Minimum
pip install PyQt6 psutil

# Full experience
pip install PyQt6 PyQt6-WebEngine psutil scapy openai==0.28
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

Set your OpenAI API key via:
- Command line: `python main.py --key sk-your-key`
- Environment: `export OPENAI_API_KEY=sk-your-key`
- In-app: AI menu → Set API Key

VEIL uses the legacy `openai==0.28` API pattern (`openai.ChatCompletion.create()`) with `gpt-4.1-nano` by default. The AI engine includes a fallback to the newer client pattern if needed.

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
- AI analysis sends anonymized traffic metadata to OpenAI's API (if configured)
- GeoIP lookups use ip-api.com (free tier, rate limited)

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Credits

**VEIL** is a [NEATLABS™](https://github.com/neatlabs-ai) project — a Service-Disabled Veteran-Owned Small Business (SDVOSB) with 28+ years of federal cybersecurity experience.

Built with Python, PyQt6, Scapy, OpenAI, and HTML5 Canvas.

*Intelligence Technology — Built by Practitioners.*

Copyright © 2025-2026 NEATLABS™ / Security 360, LLC
