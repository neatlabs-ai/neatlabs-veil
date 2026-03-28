"""
VEIL Advanced UI Panels
AI Analysis, IP Intelligence, Connection Timeline, Threat Intel, and more.
"""

import time
import logging
from datetime import datetime
from functools import partial

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTextEdit, QLineEdit, QComboBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QListWidget,
    QListWidgetItem, QAbstractItemView, QSplitter, QGroupBox,
    QProgressBar, QCheckBox, QPlainTextEdit, QSizePolicy,
    QInputDialog, QMessageBox, QScrollArea,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCursor

from ui.styles import Colors

logger = logging.getLogger("veil.panels")


# ---------------------------------------------------------------------------
# AI Chat Panel — Interactive GPT-4.1-nano Analysis
# ---------------------------------------------------------------------------

class AIChatPanel(QFrame):
    """Interactive AI analysis chat interface with enhanced readability."""

    analysis_requested = pyqtSignal(str, str)  # (type, context)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        self._ai_analyzer = None
        self._engine = None
        self._chat_history = []  # Store raw text for export

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)

        title = QLabel("VEIL AI \u2014 TRAFFIC INTELLIGENCE")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        # Export button
        self.export_btn = QPushButton("EXPORT")
        self.export_btn.setFixedHeight(24)
        self.export_btn.setFixedWidth(70)
        self.export_btn.setStyleSheet(
            f"font-size: 8px; font-weight: bold; letter-spacing: 2px; "
            f"background: rgba(255,0,170,0.08); border: 1px solid rgba(255,0,170,0.3); "
            f"color: {Colors.MAGENTA}; padding: 2px 8px;")
        self.export_btn.clicked.connect(self._export_chat)
        header_layout.addWidget(self.export_btn)

        self.status_label = QLabel("\u25cf READY")
        self.status_label.setStyleSheet(f"font-size: 10px; color: {Colors.GREEN}; background: transparent; margin-left: 8px;")
        header_layout.addWidget(self.status_label)

        self.model_label = QLabel("GPT-4.1-NANO")
        self.model_label.setStyleSheet(f"font-size: 9px; letter-spacing: 2px; "
                                       f"color: {Colors.TEXT_DIM}; background: transparent; margin-left: 12px;")
        header_layout.addWidget(self.model_label)

        header.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(header)

        # Quick action buttons
        actions_frame = QFrame()
        actions_layout = QHBoxLayout(actions_frame)
        actions_layout.setContentsMargins(8, 6, 8, 6)
        actions_layout.setSpacing(4)

        btn_style_base = (
            "font-size: 9px; font-weight: bold; letter-spacing: 1px; "
            "padding: 5px 10px; border-radius: 2px; min-height: 22px; "
        )

        self.btn_summary = QPushButton("\u26a1 FULL ANALYSIS")
        self.btn_summary.setStyleSheet(
            btn_style_base + f"background: rgba(0,240,255,0.1); border: 1px solid rgba(0,240,255,0.3); color: {Colors.CYAN};")
        self.btn_summary.clicked.connect(self._run_summary)
        actions_layout.addWidget(self.btn_summary)

        self.btn_trackers = QPushButton("\U0001f50d TRACKER INTEL")
        self.btn_trackers.setStyleSheet(
            btn_style_base + f"background: rgba(255,51,68,0.08); border: 1px solid rgba(255,51,68,0.3); color: {Colors.RED};")
        self.btn_trackers.clicked.connect(self._run_tracker_intel)
        actions_layout.addWidget(self.btn_trackers)

        self.btn_anomalies = QPushButton("\u26a0 ANOMALIES")
        self.btn_anomalies.setStyleSheet(
            btn_style_base + f"background: rgba(255,136,0,0.08); border: 1px solid rgba(255,136,0,0.3); color: {Colors.ORANGE};")
        self.btn_anomalies.clicked.connect(self._run_anomaly)
        actions_layout.addWidget(self.btn_anomalies)

        self.btn_brief = QPushButton("\U0001f4cb EXEC BRIEF")
        self.btn_brief.setStyleSheet(
            btn_style_base + f"background: rgba(0,255,102,0.08); border: 1px solid rgba(0,255,102,0.3); color: {Colors.GREEN};")
        self.btn_brief.clicked.connect(self._run_brief)
        actions_layout.addWidget(self.btn_brief)

        self.btn_firewall = QPushButton("\U0001f6e1 BLOCK RULES")
        self.btn_firewall.setStyleSheet(
            btn_style_base + f"background: rgba(170,68,255,0.08); border: 1px solid rgba(170,68,255,0.3); color: {Colors.PURPLE};")
        self.btn_firewall.clicked.connect(self._run_firewall)
        actions_layout.addWidget(self.btn_firewall)

        actions_frame.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(actions_frame)

        # Chat display area — optimized for readability
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet(
            "font-size: 13px; border: none; background: rgba(3,3,12,0.6); "
            "color: rgba(255,255,255,0.9); padding: 16px; "
            "selection-background-color: rgba(0,240,255,0.2); "
            "line-height: 160%;"
        )
        self.chat_display.setPlaceholderText(
            "VEIL AI is ready. Click an analysis button above or ask a question below.\n\n"
            "Try:\n"
            "  \u2022 'Which apps are leaking the most data?'\n"
            "  \u2022 'What is Chrome doing on my network?'\n"
            "  \u2022 'Are there any suspicious connections?'\n"
            "  \u2022 'Generate a privacy report'\n"
            "  \u2022 'What should I block?'"
        )
        layout.addWidget(self.chat_display, stretch=1)

        # Input area
        input_frame = QFrame()
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(8, 6, 8, 6)
        input_layout.setSpacing(6)

        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask VEIL AI about your network traffic...")
        self.chat_input.setFixedHeight(34)
        self.chat_input.setStyleSheet(
            f"font-size: 13px; padding: 4px 12px; "
            f"background: rgba(0,240,255,0.04); "
            f"border: 1px solid rgba(0,240,255,0.2); color: #ffffff;"
        )
        self.chat_input.returnPressed.connect(self._send_chat)
        input_layout.addWidget(self.chat_input)

        self.send_btn = QPushButton("SEND")
        self.send_btn.setFixedWidth(70)
        self.send_btn.setFixedHeight(34)
        self.send_btn.setStyleSheet(
            f"font-size: 10px; font-weight: bold; letter-spacing: 2px; "
            f"background: rgba(0,240,255,0.15); border: 1px solid {Colors.CYAN}; "
            f"color: {Colors.CYAN};")
        self.send_btn.clicked.connect(self._send_chat)
        input_layout.addWidget(self.send_btn)

        input_frame.setStyleSheet(f"border-top: 1px solid {Colors.BORDER};")
        layout.addWidget(input_frame)

        # Welcome message
        self._add_system_message(
            "VEIL AI initialized. I can analyze your network traffic in real-time.\n"
            "Use the action buttons above for structured analysis, or ask me anything."
        )

    def set_analyzer(self, ai_analyzer, engine):
        """Connect the AI analyzer and sniffer engine."""
        self._ai_analyzer = ai_analyzer
        self._engine = engine

        if ai_analyzer and ai_analyzer.is_available:
            self.status_label.setText("\u25cf READY")
            self.status_label.setStyleSheet(f"font-size: 10px; color: {Colors.GREEN}; background: transparent;")
            self.model_label.setText(ai_analyzer.model.upper())
        else:
            self.status_label.setText("\u25cf NO API KEY")
            self.status_label.setStyleSheet(f"font-size: 10px; color: {Colors.ORANGE}; background: transparent;")
            self.model_label.setText("SET KEY IN AI MENU")

    def _add_system_message(self, text: str):
        self.chat_display.append(
            f'<div style="color: {Colors.CYAN}; margin: 12px 0; padding: 10px 14px; '
            f'border-left: 3px solid {Colors.CYAN}; font-family: Consolas, monospace; font-size: 13px;">'
            f'<b style="color: {Colors.CYAN}; font-size: 11px; letter-spacing: 2px;">[ VEIL AI ]</b><br><br>'
            f'{text.replace(chr(10), "<br>")}</div>'
        )

    def _add_user_message(self, text: str):
        self.chat_display.append(
            f'<div style="color: rgba(255,255,255,0.95); margin: 12px 0; padding: 10px 14px; '
            f'border-left: 3px solid {Colors.GREEN}; font-family: Consolas, monospace; font-size: 13px;">'
            f'<b style="color: {Colors.GREEN}; font-size: 11px; letter-spacing: 2px;">[ YOU ]</b><br><br>{text}</div>'
        )

    def _add_ai_response(self, text: str):
        """Format and display AI response with rich markdown rendering."""
        import re

        # Store raw text for export
        self._chat_history.append({"role": "ai", "text": text, "time": time.time()})

        # Enhanced markdown → HTML conversion
        lines = text.split("\n")
        html_lines = []
        in_list = False

        for line in lines:
            stripped = line.strip()

            # Headers: ## Title
            if stripped.startswith("## "):
                if in_list:
                    html_lines.append("</div>")
                    in_list = False
                title_text = stripped[3:]
                html_lines.append(
                    f'<div style="color: #00f0ff; font-size: 15px; font-weight: bold; '
                    f'margin: 18px 0 8px 0; padding: 6px 0; '
                    f'border-bottom: 1px solid rgba(0,240,255,0.15);">'
                    f'\u25b8 {title_text}</div>')
                continue

            # Sub-headers: ### or bold lines
            if stripped.startswith("### "):
                html_lines.append(
                    f'<div style="color: #ff00aa; font-size: 13px; font-weight: bold; '
                    f'margin: 12px 0 6px 0;">{stripped[4:]}</div>')
                continue

            # Bullet points
            if stripped.startswith("- ") or stripped.startswith("* ") or stripped.startswith("\u2022 "):
                if not in_list:
                    html_lines.append('<div style="margin: 4px 0 4px 12px;">')
                    in_list = True
                bullet_text = stripped[2:]
                # Bold within bullets: **text**
                bullet_text = re.sub(r'\*\*(.+?)\*\*', r'<b style="color: #ffffff;">\1</b>', bullet_text)
                html_lines.append(
                    f'<div style="margin: 3px 0; padding: 2px 0;">'
                    f'<span style="color: #00f0ff;">\u2022</span> {bullet_text}</div>')
                continue

            # Numbered lists
            if re.match(r'^\d+\.\s', stripped):
                num_text = re.sub(r'^(\d+)\.\s', r'<b style="color: #00f0ff;">\1.</b> ', stripped)
                num_text = re.sub(r'\*\*(.+?)\*\*', r'<b style="color: #ffffff;">\1</b>', num_text)
                html_lines.append(f'<div style="margin: 4px 0 4px 8px;">{num_text}</div>')
                continue

            if in_list and not stripped:
                html_lines.append("</div>")
                in_list = False

            # Regular text with bold
            if stripped:
                line_html = re.sub(r'\*\*(.+?)\*\*', r'<b style="color: #ffffff;">\1</b>', stripped)
                html_lines.append(f'<div style="margin: 4px 0;">{line_html}</div>')
            else:
                html_lines.append('<div style="height: 8px;"></div>')

        if in_list:
            html_lines.append("</div>")

        html = "\n".join(html_lines)

        model_name = self._ai_analyzer.model.upper() if self._ai_analyzer else "GPT-4.1-NANO"
        self.chat_display.append(
            f'<div style="color: rgba(255,255,255,0.9); margin: 16px 0; padding: 16px; '
            f'background: rgba(0,240,255,0.02); border-left: 3px solid {Colors.MAGENTA}; '
            f'border-radius: 0 4px 4px 0; font-family: Consolas, monospace; '
            f'font-size: 13px; line-height: 170%;">'
            f'<b style="color: {Colors.MAGENTA}; font-size: 11px; letter-spacing: 2px;">'
            f'[ VEIL AI \u2014 {model_name} ]</b>'
            f'<div style="height: 10px;"></div>'
            f'{html}</div>'
        )
        # Scroll to bottom
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.chat_display.setTextCursor(cursor)

    def _export_chat(self):
        """Export AI analysis chat as styled HTML report."""
        from PyQt6.QtWidgets import QFileDialog
        from datetime import datetime as dt

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export AI Analysis",
            f"veil_ai_analysis_{dt.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;Text Files (*.txt)")
        if not filepath:
            return

        if filepath.endswith(".txt"):
            # Plain text export
            content = []
            for entry in self._chat_history:
                ts = dt.fromtimestamp(entry["time"]).strftime("%Y-%m-%d %H:%M:%S")
                role = "VEIL AI" if entry["role"] == "ai" else "USER"
                content.append(f"[{ts}] {role}:\n{entry['text']}\n{'='*60}\n")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"VEIL AI Analysis Report\nGenerated: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n\n")
                f.writelines(content)
        else:
            # Styled HTML export
            entries_html = ""
            for entry in self._chat_history:
                ts = dt.fromtimestamp(entry["time"]).strftime("%H:%M:%S")
                if entry["role"] == "ai":
                    color = "#ff00aa"
                    label = "VEIL AI"
                    text = entry["text"].replace("\n", "<br>").replace("## ", "<h3 style='color:#00f0ff;margin:12px 0 6px;'>").replace("- ", "<br>&bull; ")
                else:
                    color = "#00ff66"
                    label = "YOU"
                    text = entry["text"].replace("\n", "<br>")
                entries_html += (
                    f'<div style="margin:16px 0;padding:16px;border-left:3px solid {color};'
                    f'background:rgba(255,255,255,0.02);border-radius:0 4px 4px 0;">'
                    f'<div style="color:{color};font-size:11px;font-weight:bold;letter-spacing:2px;margin-bottom:8px;">'
                    f'[{ts}] {label}</div>'
                    f'<div style="color:rgba(255,255,255,0.9);font-size:14px;line-height:170%;">{text}</div></div>')

            html = (
                f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VEIL AI Analysis</title>'
                f'<style>*{{margin:0;padding:0;box-sizing:border-box;}}'
                f'body{{background:#0a0a1a;color:#c0d0e0;font-family:Consolas,monospace;padding:40px;max-width:900px;margin:0 auto;}}'
                f'h1{{color:#00f0ff;font-size:24px;letter-spacing:4px;border-bottom:2px solid rgba(0,240,255,0.3);padding-bottom:12px;margin-bottom:8px;}}'
                f'.sub{{color:#667;font-size:11px;letter-spacing:2px;margin-bottom:24px;}}'
                f'h3{{color:#00f0ff;font-size:16px;margin:12px 0 6px;}}'
                f'.footer{{margin-top:40px;padding-top:16px;border-top:1px solid rgba(0,240,255,0.12);color:#445;font-size:11px;text-align:center;}}'
                f'</style></head><body>'
                f'<h1>&#9670; VEIL AI ANALYSIS</h1>'
                f'<div class="sub">Generated {dt.now().strftime("%Y-%m-%d %H:%M:%S")} &mdash; {len(self._chat_history)} entries</div>'
                f'{entries_html}'
                f'<div class="footer">VEIL &mdash; Network Traffic Exposer &mdash; NEATLABS&trade;</div>'
                f'</body></html>')
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)

        self._add_system_message(f"Analysis exported to:\n{filepath}")

    def _set_loading(self, loading: bool):
        self.send_btn.setEnabled(not loading)
        self.btn_summary.setEnabled(not loading)
        self.btn_trackers.setEnabled(not loading)
        self.btn_anomalies.setEnabled(not loading)
        self.btn_brief.setEnabled(not loading)
        self.btn_firewall.setEnabled(not loading)
        if loading:
            self.status_label.setText("\u25cf ANALYZING...")
            self.status_label.setStyleSheet(f"font-size: 10px; color: {Colors.YELLOW}; background: transparent;")
        else:
            self.status_label.setText("\u25cf READY")
            self.status_label.setStyleSheet(f"font-size: 10px; color: {Colors.GREEN}; background: transparent;")

    def _check_ready(self) -> bool:
        if not self._ai_analyzer or not self._ai_analyzer.is_available:
            self._add_system_message(
                "\u26a0 OpenAI API key not configured.\n\n"
                "Set your key via:\n"
                "  AI menu \u2192 Set API Key\n\n"
                "Or: python main.py --key YOUR_KEY"
            )
            return False
        if not self._engine or not self._engine.stats.total_packets:
            self._add_system_message("\u26a0 No traffic data captured yet. Start capture first.")
            return False
        return True

    def _send_chat(self):
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()

        if not self._check_ready():
            return

        self._add_user_message(text)
        self._chat_history.append({"role": "user", "text": text, "time": time.time()})
        self._set_loading(True)

        def on_response(result):
            self._add_ai_response(result)
            self._set_loading(False)

        self._ai_analyzer.chat(self._engine, text, callback=on_response)

    def _run_summary(self):
        if not self._check_ready(): return
        self._add_system_message("Running full traffic analysis...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.analyze_traffic_summary(self._engine, callback=on_result)

    def _run_tracker_intel(self):
        if not self._check_ready(): return
        self._add_system_message("Generating tracker intelligence report...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.analyze_tracker_intelligence(self._engine, callback=on_result)

    def _run_anomaly(self):
        if not self._check_ready(): return
        self._add_system_message("Scanning for network anomalies...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.analyze_anomalies(self._engine, callback=on_result)

    def _run_brief(self):
        if not self._check_ready(): return
        self._add_system_message("Generating executive privacy brief...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.generate_executive_brief(self._engine, callback=on_result)

    def _run_firewall(self):
        if not self._check_ready(): return
        self._add_system_message("Generating firewall & blocking rules...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.generate_firewall_rules(self._engine, callback=on_result)

    def run_app_analysis(self, app_name: str):
        """Trigger analysis for a specific app (called from app table)."""
        if not self._check_ready(): return
        self._add_system_message(f"Analyzing behavior of: {app_name}...")
        self._set_loading(True)

        def on_result(result):
            self._add_ai_response(result)
            self._set_loading(False)
        self._ai_analyzer.analyze_app_behavior(self._engine, app_name, callback=on_result)


# ---------------------------------------------------------------------------
# IP Intelligence Panel
# ---------------------------------------------------------------------------

class IPIntelPanel(QFrame):
    """IP reputation and intelligence lookup panel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        self._ip_intel = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        title = QLabel("IP INTELLIGENCE")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        header.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(header)

        # Lookup bar
        lookup_frame = QFrame()
        lookup_layout = QHBoxLayout(lookup_frame)
        lookup_layout.setContentsMargins(8, 6, 8, 6)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address or hostname...")
        self.ip_input.setFixedHeight(30)
        self.ip_input.returnPressed.connect(self._do_lookup)
        lookup_layout.addWidget(self.ip_input)

        lookup_btn = QPushButton("LOOKUP")
        lookup_btn.setFixedWidth(80)
        lookup_btn.setFixedHeight(30)
        lookup_btn.clicked.connect(self._do_lookup)
        lookup_layout.addWidget(lookup_btn)
        layout.addWidget(lookup_frame)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setShowGrid(False)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 140)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.results_table)

        # Connection-linked lookups list
        self.auto_lookups = QPlainTextEdit()
        self.auto_lookups.setReadOnly(True)
        self.auto_lookups.setMaximumBlockCount(200)
        self.auto_lookups.setMaximumHeight(150)
        self.auto_lookups.setStyleSheet(
            "font-size: 10px; border: none; background: transparent; "
            f"color: {Colors.TEXT_MID}; padding: 4px 8px;"
        )
        layout.addWidget(self.auto_lookups)

    def set_intel(self, ip_intel):
        self._ip_intel = ip_intel

    def _do_lookup(self):
        ip = self.ip_input.text().strip()
        if not ip or not self._ip_intel:
            return

        rep = self._ip_intel.lookup(ip)
        # Give the async lookup a moment, then poll
        QTimer.singleShot(2500, lambda: self._display_result(ip))

    def _display_result(self, ip: str):
        if not self._ip_intel:
            return
        rep = self._ip_intel.get_cached(ip)
        if not rep:
            rep = self._ip_intel.lookup(ip)

        data = [
            ("IP Address", rep.ip),
            ("Hostname", rep.hostname or "N/A"),
            ("Organization", rep.org or "Unknown"),
            ("ISP", rep.isp or "Unknown"),
            ("ASN", rep.asn or "Unknown"),
            ("Country", rep.country or "Unknown"),
            ("City", rep.city or "Unknown"),
            ("Is Proxy", "⚠ YES" if rep.is_proxy else "No"),
            ("Is VPN", "⚠ YES" if rep.is_vpn else "No"),
            ("Is Tor Exit", "🔴 YES" if rep.is_tor else "No"),
            ("Is Datacenter", "Yes" if rep.is_datacenter else "No"),
            ("Risk Score", f"{rep.risk_score}/100"),
            ("Risk Level", rep.risk_level.upper()),
        ]

        self.results_table.setRowCount(len(data))
        for row, (prop, val) in enumerate(data):
            prop_item = QTableWidgetItem(prop)
            prop_item.setForeground(QColor(Colors.TEXT_DIM))
            val_item = QTableWidgetItem(str(val))

            # Color by risk
            if "YES" in str(val) or "critical" in str(val).lower():
                val_item.setForeground(QColor(Colors.RED))
            elif "high" in str(val).lower() or "⚠" in str(val):
                val_item.setForeground(QColor(Colors.ORANGE))
            elif rep.risk_level == "low":
                val_item.setForeground(QColor(Colors.GREEN))

            self.results_table.setItem(row, 0, prop_item)
            self.results_table.setItem(row, 1, val_item)

    def log_auto_lookup(self, ip: str, host: str, org: str, risk: str):
        """Log an automated lookup from packet capture."""
        ts = datetime.now().strftime("%H:%M:%S")
        risk_icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk, "⚪")
        self.auto_lookups.appendPlainText(f"[{ts}] {risk_icon} {ip} — {host} ({org}) [{risk.upper()}]")


# ---------------------------------------------------------------------------
# Connection Timeline Widget
# ---------------------------------------------------------------------------

class ConnectionTimeline(QFrame):
    """Visual timeline of connections over time — ASCII-art style bandwidth graph."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        title = QLabel("NETWORK TIMELINE")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        self.time_label = QLabel("")
        self.time_label.setStyleSheet(f"font-size: 10px; color: {Colors.CYAN}; background: transparent;")
        header_layout.addWidget(self.time_label)
        header.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(header)

        self.display = QPlainTextEdit()
        self.display.setReadOnly(True)
        self.display.setMaximumBlockCount(120)
        self.display.setStyleSheet(
            "font-size: 10px; font-family: 'Courier New', monospace; "
            "border: none; background: transparent; "
            f"color: {Colors.CYAN}; padding: 4px 8px; line-height: 1.2;"
        )
        layout.addWidget(self.display)

        self._history = []
        self._max_points = 60

    def add_datapoint(self, packets_per_sec: int, bandwidth_bps: float,
                      tracker_pps: int = 0):
        """Add a timeline datapoint."""
        self._history.append({
            "time": time.time(),
            "pps": packets_per_sec,
            "bps": bandwidth_bps,
            "trackers": tracker_pps,
        })
        if len(self._history) > self._max_points:
            self._history = self._history[-self._max_points:]

        self._render()

    def _render(self):
        """Render ASCII bandwidth graph."""
        if len(self._history) < 2:
            return

        max_bps = max(d["bps"] for d in self._history) or 1
        height = 12
        width = min(len(self._history), self._max_points)

        lines = []
        # Header
        bps_label = f"{max_bps/1024:.0f} KB/s" if max_bps < 1048576 else f"{max_bps/1048576:.1f} MB/s"
        lines.append(f"  ┌{'─' * width}┐ {bps_label}")

        # Graph rows
        for row in range(height, 0, -1):
            threshold = (row / height) * max_bps
            line = "  │"
            for dp in self._history[-width:]:
                if dp["bps"] >= threshold:
                    if dp["trackers"] > 0:
                        line += "█"  # Tracker traffic
                    else:
                        line += "▓"  # Normal traffic
                elif dp["bps"] >= threshold * 0.7:
                    line += "▒"
                elif dp["bps"] >= threshold * 0.3:
                    line += "░"
                else:
                    line += " "
            line += "│"
            lines.append(line)

        lines.append(f"  └{'─' * width}┘")

        # Time axis
        if self._history:
            start = datetime.fromtimestamp(self._history[0]["time"]).strftime("%H:%M:%S")
            end = datetime.fromtimestamp(self._history[-1]["time"]).strftime("%H:%M:%S")
            lines.append(f"   {start}{' ' * max(0, width - 17)}{end}")

        self.display.setPlainText("\n".join(lines))
        self.time_label.setText(f"{len(self._history)} samples")


# ---------------------------------------------------------------------------
# Destination Heatmap Table
# ---------------------------------------------------------------------------

class DestinationHeatmap(QFrame):
    """Destination analysis with risk heatmap coloring."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        title = QLabel("DESTINATION INTELLIGENCE")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        self.count_label = QLabel("0")
        self.count_label.setStyleSheet(f"font-size: 11px; color: {Colors.CYAN}; background: transparent;")
        header_layout.addWidget(self.count_label)
        header.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Host", "IP", "Bytes", "Packets", "Location", "Org", "Risk"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 70)
        self.table.setColumnWidth(3, 60)
        self.table.setColumnWidth(4, 120)
        self.table.setColumnWidth(5, 100)
        self.table.verticalHeader().setDefaultSectionSize(26)
        layout.addWidget(self.table)

    def update_data(self, dest_stats: dict, ip_intel=None):
        """Refresh the destination heatmap."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        sorted_dests = sorted(dest_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:100]
        self.count_label.setText(f"{len(sorted_dests)} destinations")

        for host, data in sorted_dests:
            row = self.table.rowCount()
            self.table.insertRow(row)

            geo = data.get("geo")
            loc = f"{geo.city}, {geo.country_code}" if geo and geo.city != "Unknown" else ""
            org = geo.org if geo and geo.org != "Unknown" else ""

            # Get risk from IP intel
            risk = "—"
            risk_color = Colors.TEXT_DIM
            if ip_intel and geo:
                rep = ip_intel.get_cached(geo.ip)
                if rep:
                    risk = rep.risk_level.upper()
                    risk_color = {
                        "LOW": Colors.GREEN, "MEDIUM": Colors.YELLOW,
                        "HIGH": Colors.ORANGE, "CRITICAL": Colors.RED,
                    }.get(risk, Colors.TEXT_DIM)

            items = [
                host, geo.ip if geo else "", f"{data['bytes']/1024:.1f}K",
                str(data["packets"]), loc, org, risk
            ]

            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 6:  # Risk column
                    item.setForeground(QColor(risk_color))
                elif col == 0:
                    item.setForeground(QColor("#ffffff"))
                self.table.setItem(row, col, item)

        self.table.setSortingEnabled(True)


# ---------------------------------------------------------------------------
# Session Snapshot Panel
# ---------------------------------------------------------------------------

class SessionSnapshotPanel(QFrame):
    """Periodic session snapshots for trend analysis."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        self._snapshots = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        title = QLabel("SESSION SNAPSHOTS")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        snap_btn = QPushButton("📸 SNAPSHOT")
        snap_btn.setFixedWidth(100)
        snap_btn.setFixedHeight(24)
        snap_btn.setStyleSheet(
            f"font-size: 9px; letter-spacing: 1px; padding: 2px 8px; "
            f"background: rgba(0,240,255,0.08); border: 1px solid rgba(0,240,255,0.2); color: {Colors.CYAN};")
        snap_btn.clicked.connect(self._take_snapshot_manual)
        header_layout.addWidget(snap_btn)

        header.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER};")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Packets", "Endpoints", "Trackers", "Data", "Score", "Δ Packets"])
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setDefaultSectionSize(26)
        layout.addWidget(self.table)

        self._engine = None
        self._take_snapshot_cb = None

    def set_engine(self, engine):
        self._engine = engine

    def _take_snapshot_manual(self):
        if self._engine:
            self.take_snapshot(self._engine)

    def take_snapshot(self, engine):
        """Take a snapshot of current session stats."""
        stats = engine.stats
        snap = {
            "time": time.time(),
            "packets": stats.total_packets,
            "endpoints": len(stats.unique_endpoints),
            "trackers": len(stats.trackers_found),
            "bytes": stats.total_bytes,
            "score": stats.privacy_score,
        }

        delta = 0
        if self._snapshots:
            delta = snap["packets"] - self._snapshots[-1]["packets"]

        self._snapshots.append(snap)

        row = self.table.rowCount()
        self.table.insertRow(row)

        ts = datetime.fromtimestamp(snap["time"]).strftime("%H:%M:%S")
        items = [
            ts,
            f"{snap['packets']:,}",
            str(snap["endpoints"]),
            str(snap["trackers"]),
            f"{snap['bytes']/(1024*1024):.2f} MB",
            f"{snap['score']:.0f}",
            f"+{delta:,}" if delta > 0 else str(delta),
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 3 and snap["trackers"] > 0:
                item.setForeground(QColor(Colors.RED))
            elif col == 5:
                if snap["score"] > 70:
                    item.setForeground(QColor(Colors.RED))
                elif snap["score"] > 40:
                    item.setForeground(QColor(Colors.ORANGE))
                else:
                    item.setForeground(QColor(Colors.GREEN))
            elif col == 6 and delta > 100:
                item.setForeground(QColor(Colors.YELLOW))
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()


# ---------------------------------------------------------------------------
# Network Summary Cards
# ---------------------------------------------------------------------------

class NetworkSummaryCards(QFrame):
    """High-level summary cards with trend indicators."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        title = QLabel("NETWORK INTELLIGENCE")
        title.setStyleSheet(f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
                           f"color: {Colors.TEXT_MID}; background: transparent; "
                           f"border-bottom: 1px solid {Colors.BORDER}; padding-bottom: 6px;")
        layout.addWidget(title)

        self.cards = {}
        card_defs = [
            ("data_rate", "DATA RATE", "0 B/s", Colors.CYAN),
            ("top_app", "TOP APP", "—", Colors.GREEN),
            ("top_dest", "TOP DEST", "—", Colors.MAGENTA),
            ("tracker_rate", "TRACKER RATE", "0/min", Colors.RED),
            ("countries", "COUNTRIES", "0", Colors.YELLOW),
            ("risk_trend", "RISK TREND", "—", Colors.ORANGE),
        ]

        for key, label, default, color in card_defs:
            card = QFrame()
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(4, 3, 4, 3)

            lbl = QLabel(label)
            lbl.setStyleSheet(f"font-size: 9px; color: {Colors.TEXT_DIM}; background: transparent; min-width: 80px;")
            card_layout.addWidget(lbl)

            val = QLabel(default)
            val.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {color}; background: transparent;")
            val.setAlignment(Qt.AlignmentFlag.AlignRight)
            card_layout.addWidget(val)

            self.cards[key] = val
            layout.addWidget(card)

    def update_cards(self, engine):
        """Update all summary cards from engine data."""
        stats = engine.stats

        # Data rate
        bw = engine.bandwidth
        if bw < 1024:
            self.cards["data_rate"].setText(f"{bw:.0f} B/s")
        elif bw < 1048576:
            self.cards["data_rate"].setText(f"{bw/1024:.1f} KB/s")
        else:
            self.cards["data_rate"].setText(f"{bw/1048576:.2f} MB/s")

        # Top app
        top_apps = engine.get_top_apps(1)
        if top_apps:
            self.cards["top_app"].setText(top_apps[0].name)

        # Top destination
        top_dests = engine.get_top_destinations(1)
        if top_dests:
            host = top_dests[0][0]
            if len(host) > 20:
                host = host[:17] + "..."
            self.cards["top_dest"].setText(host)

        # Tracker rate
        elapsed = max(1, time.time() - stats.start_time)
        tracker_per_min = (len(stats.trackers_found) / elapsed) * 60
        self.cards["tracker_rate"].setText(f"{tracker_per_min:.1f}/min")

        # Countries
        self.cards["countries"].setText(str(len(stats.countries)))

        # Risk trend
        score = stats.privacy_score
        if score > 75:
            self.cards["risk_trend"].setText("▲ CRITICAL")
            self.cards["risk_trend"].setStyleSheet(f"font-size: 12px; font-weight: bold; color: {Colors.RED}; background: transparent;")
        elif score > 50:
            self.cards["risk_trend"].setText("▲ HIGH")
            self.cards["risk_trend"].setStyleSheet(f"font-size: 12px; font-weight: bold; color: {Colors.ORANGE}; background: transparent;")
        elif score > 25:
            self.cards["risk_trend"].setText("► MODERATE")
            self.cards["risk_trend"].setStyleSheet(f"font-size: 12px; font-weight: bold; color: {Colors.YELLOW}; background: transparent;")
        else:
            self.cards["risk_trend"].setText("▼ LOW")
            self.cards["risk_trend"].setStyleSheet(f"font-size: 12px; font-weight: bold; color: {Colors.GREEN}; background: transparent;")
