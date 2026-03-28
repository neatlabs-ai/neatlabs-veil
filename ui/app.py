"""
VEIL 3.0 — Network Traffic Exposer
Full-featured cyberpunk network traffic visualization dashboard.
Every connection. Every tracker. Every byte. Exposed.

NEATLABS™ Intelligence Technology
Open Source — github.com/neatlabs-ai
"""

import sys
import os
import time
import json
import logging
from datetime import datetime
from collections import defaultdict
from typing import List
from functools import partial

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QSplitter, QFrame, QComboBox, QLineEdit, QHeaderView,
    QStatusBar, QMenuBar, QMenu, QFileDialog, QMessageBox, QTextEdit,
    QProgressBar, QDockWidget, QGroupBox, QCheckBox,
    QListWidget, QListWidgetItem, QAbstractItemView, QToolBar, QSizePolicy,
    QSpacerItem, QPlainTextEdit, QInputDialog, QSystemTrayIcon,
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSize, QUrl, QDateTime,
)
from PyQt6.QtGui import (
    QColor, QFont, QIcon, QAction, QPalette, QPainter, QBrush, QPen,
    QLinearGradient, QRadialGradient,
)

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False

from ui.styles import CYBERPUNK_STYLESHEET, Colors
from core.sniffer import SnifferEngine, ConnectionInfo
from core.ai_analyzer import AIAnalyzer
from core.ip_intel import IPIntelligence
from ui.panels import (
    AIChatPanel, IPIntelPanel, ConnectionTimeline,
    DestinationHeatmap, SessionSnapshotPanel,
)
from ui.widgets import (
    AnimatedPrivacyGauge, SparklineGraph, AnimatedStatCard,
    ThreatMeter, TopTalkersWidget, CompanyTrafficWidget,
    PacketPulse, ProtocolDonut,
)

logger = logging.getLogger("veil.app")

__version__ = "3.1.0"

# ---------------------------------------------------------------------------
# Helper Widgets
# ---------------------------------------------------------------------------

class GlowLine(QFrame):
    """Horizontal glowing separator line."""
    def __init__(self, color=Colors.CYAN, parent=None):
        super().__init__(parent)
        self.setFixedHeight(1)
        self.setStyleSheet(f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                          f"stop:0 transparent, stop:0.3 {color}, "
                          f"stop:0.7 {color}, stop:1 transparent);")


class PanelHeader(QFrame):
    """Section header with title and optional count badge."""
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet(
            f"font-size: 10px; font-weight: bold; letter-spacing: 3px; "
            f"color: {Colors.TEXT_MID}; background: transparent;")
        layout.addWidget(self.title_label)
        layout.addStretch()
        self.count_label = QLabel("")
        self.count_label.setStyleSheet(f"font-size: 11px; color: {Colors.CYAN}; background: transparent;")
        layout.addWidget(self.count_label)
        self.setStyleSheet(f"border-bottom: 1px solid {Colors.BORDER}; background: transparent;")

    def set_count(self, text: str):
        self.count_label.setText(text)


# ---------------------------------------------------------------------------
# Live Feed Widget
# ---------------------------------------------------------------------------

class LiveFeedWidget(QFrame):
    """Real-time scrolling packet feed with color-coded entries."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = PanelHeader("Live Packet Feed")
        layout.addWidget(self.header)
        self.text_area = QPlainTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMaximumBlockCount(500)
        self.text_area.setStyleSheet(
            "font-size: 11px; border: none; background: transparent; "
            "color: rgba(0, 240, 255, 0.8); padding: 4px 8px;")
        layout.addWidget(self.text_area)
        self._count = 0

    def add_packet(self, conn: ConnectionInfo):
        self._count += 1
        ts = datetime.fromtimestamp(conn.timestamp).strftime("%H:%M:%S")
        if conn.is_tracker:
            tag = "\U0001f534"
        elif conn.proto_display == "DNS":
            tag = "\U0001f7e3"
        elif conn.proto_display in ("HTTPS", "TLS 1.3"):
            tag = "\U0001f7e2"
        else:
            tag = "\U0001f535"
        host = conn.dst_host or conn.dst_ip
        if len(host) > 40:
            host = host[:37] + "..."
        line = f"{tag} [{ts}] {conn.app_name:<16} {conn.proto_display:<6} > {host}"
        if conn.is_tracker:
            line += f" !! {conn.tracker_name}"
        self.text_area.appendPlainText(line)
        self.header.set_count(f"{self._count:,}")


# ---------------------------------------------------------------------------
# Alerts Widget
# ---------------------------------------------------------------------------

class AlertsWidget(QFrame):
    """Security alerts panel."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = PanelHeader("Security Alerts")
        layout.addWidget(self.header)
        self.text_area = QPlainTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMaximumBlockCount(200)
        self.text_area.setStyleSheet(
            "font-size: 11px; border: none; background: transparent; "
            "color: #ff3344; padding: 4px 8px;")
        layout.addWidget(self.text_area)
        self._count = 0

    def add_alert(self, alert: dict):
        self._count += 1
        ts = datetime.fromtimestamp(alert["time"]).strftime("%H:%M:%S")
        level = alert.get("level", "info").upper()
        icon = "\U0001f534" if level == "CRITICAL" else "\u26a0\ufe0f"
        line = f"{icon} [{ts}] [{level}] {alert['message']}"
        if alert.get("app"):
            line += f" -- {alert['app']}"
        self.text_area.appendPlainText(line)
        self.header.set_count(f"{self._count}")


# ---------------------------------------------------------------------------
# Connection Table
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Connection Table — High-performance model/view (#4)
# ---------------------------------------------------------------------------

class ConnectionTableModel(Qt.QAbstractTableModel if hasattr(Qt, 'QAbstractTableModel') else object):
    """Dummy fallback — actual model defined below."""
    pass

# Use QAbstractTableModel for proper model/view performance
from PyQt6.QtCore import QAbstractTableModel, QModelIndex

class ConnModel(QAbstractTableModel):
    """High-performance table model for connection data."""
    COLUMNS = ["Time", "App", "Protocol", "Destination", "Host",
               "Port", "Bytes", "Dir", "Tracker", "Country", "Org"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[list] = []
        self._colors: List[list] = []
        self._max_rows = 5000

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._data[index.row()][index.column()]
        if role == Qt.ItemDataRole.ForegroundRole:
            c = self._colors[index.row()][index.column()]
            return QColor(c) if c else None
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def add_connection(self, conn):
        ts = datetime.fromtimestamp(conn.timestamp).strftime("%H:%M:%S")
        row_data = [
            ts, conn.app_name, conn.proto_display, conn.dst_ip,
            conn.dst_host or conn.dst_ip, str(conn.dst_port),
            self._fmt(conn.length), conn.direction,
            conn.tracker_name if conn.is_tracker else "",
            conn.geo.country_code if conn.geo else "",
            conn.geo.org if conn.geo else "",
        ]
        row_colors = [None] * len(self.COLUMNS)
        if conn.is_tracker:
            row_colors = [Colors.RED] * len(self.COLUMNS)
        else:
            row_colors[2] = Colors.PROTOCOL_COLORS.get(conn.proto_display, None)
            row_colors[7] = Colors.ORANGE if conn.direction == "OUT" else Colors.GREEN

        if len(self._data) >= self._max_rows:
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self._data.pop(0)
            self._colors.pop(0)
            self.endRemoveRows()

        pos = len(self._data)
        self.beginInsertRows(QModelIndex(), pos, pos)
        self._data.append(row_data)
        self._colors.append(row_colors)
        self.endInsertRows()

    @staticmethod
    def _fmt(b):
        if b < 1024: return f"{b} B"
        elif b < 1048576: return f"{b/1024:.1f} K"
        return f"{b/1048576:.1f} M"


class ConnectionTable(QFrame):
    """Connection table using model/view for performance."""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        from PyQt6.QtWidgets import QTableView
        self.model = ConnModel()
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setSortingEnabled(True)
        self.view.verticalHeader().setVisible(False)
        self.view.setShowGrid(False)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i, w in enumerate([80, 110, 65, 140, 200, 55, 70, 45, 140, 80, 100]):
            self.view.setColumnWidth(i, w)
        self.view.verticalHeader().setDefaultSectionSize(26)
        layout.addWidget(self.view)

    def add_connection(self, conn):
        self.model.add_connection(conn)
        self.view.scrollToBottom()

    def setRowCount(self, n):
        """Compatibility — clear all data."""
        if n == 0:
            self.model.beginResetModel()
            self.model._data.clear()
            self.model._colors.clear()
            self.model.endResetModel()


# ---------------------------------------------------------------------------
# App Monitor Table
# ---------------------------------------------------------------------------

class AppMonitorTable(QTableWidget):
    """Shows which applications are making network connections."""
    COLUMNS = ["App", "Packets", "Sent", "Received", "Trackers", "Destinations"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setDefaultSectionSize(28)

    def update_data(self, app_stats: dict):
        self.setSortingEnabled(False)
        self.setRowCount(0)
        sorted_apps = sorted(app_stats.values(),
                           key=lambda a: a.total_bytes_sent + a.total_bytes_recv, reverse=True)
        for app in sorted_apps[:50]:
            row = self.rowCount()
            self.insertRow(row)
            for col, text in enumerate([
                app.name, str(app.packet_count),
                self._fmt(app.total_bytes_sent), self._fmt(app.total_bytes_recv),
                str(app.tracker_hits), str(len(app.destinations))
            ]):
                item = QTableWidgetItem(text)
                if col == 4 and app.tracker_hits > 0:
                    item.setForeground(QColor(Colors.RED))
                elif col == 0:
                    item.setForeground(QColor("#ffffff"))
                self.setItem(row, col, item)
        self.setSortingEnabled(True)

    @staticmethod
    def _fmt(b):
        if b < 1024: return f"{b} B"
        elif b < 1048576: return f"{b/1024:.1f} K"
        return f"{b/1048576:.1f} M"


# ---------------------------------------------------------------------------
# Tracker Panel
# ---------------------------------------------------------------------------

class TrackerPanel(QFrame):
    """Detected trackers with details."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = PanelHeader("Active Trackers Detected")
        layout.addWidget(self.header)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Tracker", "Company", "Category", "Severity"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self._known = set()

    def add_tracker(self, conn: ConnectionInfo):
        if not conn.is_tracker or conn.tracker_name in self._known:
            return
        self._known.add(conn.tracker_name)
        row = self.table.rowCount()
        self.table.insertRow(row)
        sev_color = Colors.SEVERITY_COLORS.get(conn.tracker_severity, Colors.CYAN)
        for col, text in enumerate([conn.tracker_name, conn.tracker_company,
                                    conn.tracker_category, conn.tracker_severity.upper()]):
            item = QTableWidgetItem(text)
            if col == 3: item.setForeground(QColor(sev_color))
            elif col == 0: item.setForeground(QColor(Colors.RED))
            self.table.setItem(row, col, item)
        self.header.set_count(f"{len(self._known)} trackers")


# ---------------------------------------------------------------------------
# DNS Log Panel
# ---------------------------------------------------------------------------

class DNSLogPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = PanelHeader("DNS Query Log")
        layout.addWidget(self.header)
        self.text_area = QPlainTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMaximumBlockCount(500)
        self.text_area.setStyleSheet(
            "font-size: 11px; border: none; background: transparent; "
            "color: #aa44ff; padding: 4px 8px;")
        layout.addWidget(self.text_area)
        self._count = 0

    def add_query(self, conn: ConnectionInfo):
        if not conn.dns_query:
            return
        self._count += 1
        ts = datetime.fromtimestamp(conn.timestamp).strftime("%H:%M:%S")
        self.text_area.appendPlainText(f"[{ts}] {conn.dns_query}")
        self.header.set_count(f"{self._count}")


# ---------------------------------------------------------------------------
# Phone Home Detector Panel
# ---------------------------------------------------------------------------

class PhoneHomePanel(QFrame):
    """Detects apps that silently beacon out."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = PanelHeader("Phone-Home Detector")
        layout.addWidget(self.header)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["App", "Conns", "Dests", "Trackers", "Suspicion"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setDefaultSectionSize(26)
        layout.addWidget(self.table)

    def update_data(self, phone_home_data: list):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for entry in phone_home_data[:15]:
            row = self.table.rowCount()
            self.table.insertRow(row)
            suspicion = entry["suspicion"]
            if suspicion >= 75:
                susp_text, susp_color = f"{suspicion:.0f}% CRITICAL", Colors.RED
            elif suspicion >= 50:
                susp_text, susp_color = f"{suspicion:.0f}% HIGH", Colors.ORANGE
            elif suspicion >= 25:
                susp_text, susp_color = f"{suspicion:.0f}% MODERATE", Colors.YELLOW
            else:
                susp_text, susp_color = f"{suspicion:.0f}% LOW", Colors.GREEN
            for col, (text, color) in enumerate([
                (entry["app"], "#ffffff"),
                (str(entry["connections"]), Colors.CYAN),
                (str(entry["destinations"]), Colors.MAGENTA),
                (str(entry["tracker_connections"]), Colors.RED if entry["tracker_connections"] > 0 else Colors.TEXT_DIM),
                (susp_text, susp_color),
            ]):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(color))
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)
        self.header.set_count(f"{len(phone_home_data)} apps")


# ---------------------------------------------------------------------------
# Globe Widget
# ---------------------------------------------------------------------------

class GlobeWidget(QFrame):
    """3D globe — pure Canvas, zero dependencies, inline HTML."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CyberPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if HAS_WEBENGINE:
            self.web_view = QWebEngineView()
            self.web_view.setStyleSheet("background: #030308;")
            layout.addWidget(self.web_view)
            self.web_view.setHtml(self._globe_html(), QUrl("about:blank"))
        else:
            fb = QLabel("3D GLOBE REQUIRES PyQt6-WebEngine\n\npip install PyQt6-WebEngine")
            fb.setAlignment(Qt.AlignmentFlag.AlignCenter)
            fb.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 14px; padding: 40px;")
            layout.addWidget(fb)
            self.web_view = None

    def add_connection_arc(self, lat, lng, is_tracker=False):
        if self.web_view and HAS_WEBENGINE:
            tk = "true" if is_tracker else "false"
            js = f"if(typeof activateArc==='function')activateArc({{lat:{lat},lng:{lng},tracker:{tk}}});"
            try:
                self.web_view.page().runJavaScript(js)
            except Exception:
                pass

    @staticmethod
    def _globe_html():
        return r'''<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>*{margin:0;padding:0;box-sizing:border-box;}body{background:#030308;overflow:hidden;height:100vh;width:100vw;cursor:grab;font-family:'Courier New',monospace;}body.dragging{cursor:grabbing;}canvas{display:block;width:100%;height:100%;}</style>
</head><body><canvas id="g"></canvas><script>
var C=document.getElementById('g'),X=C.getContext('2d'),W,H,cx,cy;
function rz(){W=C.width=window.innerWidth;H=C.height=window.innerHeight;cx=W/2;cy=H/2;iS();iN();}
rz();window.addEventListener('resize',rz);
var O={lat:38.88,lng:-76.95},MA=55,MP=350,MR=18,MD=90;
var rX=0.4,rY=0,dr=false,lx=0,ly=0,ar=true;
var GR=function(){return Math.min(W,H)*0.31;};
function rot(x,y,z){var cy1=Math.cos(rX),sy1=Math.sin(rX),y1=y*cy1-z*sy1,z1=y*sy1+z*cy1;var cx1=Math.cos(rY),sx1=Math.sin(rY);return{x:x*cx1+z1*sx1,y:y1,z:-x*sx1+z1*cx1};}
function pj(x,y,z){var f=600,s=f/(f+z);return{x:cx+x*s,y:cy+y*s,s:s,z:z};}
function ll(la,lo,r){var p=(90-la)*Math.PI/180,t=(lo+180)*Math.PI/180;return{x:-r*Math.sin(p)*Math.cos(t),y:r*Math.cos(p),z:r*Math.sin(p)*Math.sin(t)};}

var st=[],nb=[];
function iS(){st=[];for(var i=0;i<400;i++)st.push({x:Math.random()*W,y:Math.random()*H,sz:Math.random()*1.6+0.2,sp:Math.random()*2+0.5,of:Math.random()*6.28,hu:Math.random()<0.12?180+Math.random()*60:0});}
function iN(){nb=[];for(var i=0;i<10;i++)nb.push({x:Math.random()*W,y:Math.random()*H,r:60+Math.random()*240,hu:[190,260,320,210,280][Math.floor(Math.random()*5)],al:0.012+Math.random()*0.018,dr:Math.random()*0.06-0.03});}

var cd=[];
[[30,50,-128,-65,280],[50,60,-130,-55,100],[25,30,-100,-80,50],[55,70,-170,-130,35],
[10,25,-110,-60,70],[-55,12,-82,-34,260],[0,5,-80,-50,40],
[36,60,-10,30,230],[44,55,20,45,70],[55,65,5,30,45],[60,70,5,30,35],
[-35,35,-18,52,280],[0,15,30,42,50],
[15,40,35,60,70],[24,38,44,56,35],
[45,65,40,140,180],[50,70,60,100,70],
[5,35,65,90,140],[8,20,72,88,45],
[20,50,100,140,180],[22,46,108,130,70],
[-10,20,95,142,110],[-45,-10,112,155,140],[-47,-34,166,178,25],
[30,46,128,146,45],[50,58,-10,2,35],[63,67,-24,-13,12],[60,82,-55,-15,25]
].forEach(function(r){for(var i=0;i<r[4];i++)cd.push({lat:r[0]+Math.random()*(r[1]-r[0]),lng:r[2]+Math.random()*(r[3]-r[2]),sz:0.4+Math.random()*1.8,br:0.15+Math.random()*0.35,ci:Math.random()<0.05});});

var arcs=[],dm=[],rp=[],pt=[];
var tA=0,tkA=0,aC=0;

window.activateArc=function(d){
var tk=d.tracker||false;
var cs=tk?['#ff3344','#ff1133','#ff5566']:['#00f0ff','#ff00aa','#00ff88','#8844ff','#ffaa00','#00ddff'];
var c=cs[Math.floor(Math.random()*cs.length)];
arcs.push({sLa:O.lat,sLo:O.lng,eLa:d.lat,eLo:d.lng,p:0,lt:0,ml:3.5+Math.random()*4,sp:0.2+Math.random()*0.3,c:c,tk:tk,pp:0,ps:0.25+Math.random()*0.2,w:tk?2.5:1.5,gs:tk?16:10});
if(arcs.length>MA)arcs.shift();
dm.push({lat:d.lat,lng:d.lng,c:c,al:1.0,t:performance.now()/1000,tk:tk});
if(dm.length>MD)dm.shift();
rp.push({lat:d.lat,lng:d.lng,c:c,r:0,mr:tk?38:28,al:0.9,sp:35+Math.random()*25});
if(rp.length>MR)rp.shift();
for(var i=0;i<3+Math.floor(Math.random()*5);i++){
pt.push({sLa:O.lat,sLo:O.lng,eLa:d.lat,eLo:d.lng,pg:Math.random()*0.3,sp:0.12+Math.random()*0.25,c:c,sz:tk?3:2,li:2.5+Math.random()*3,ag:0});}
if(pt.length>MP)pt.splice(0,pt.length-MP);
tA++;if(tk)tkA++;};

var sd=[{lat:37.77,lng:-122.42},{lat:51.51,lng:-0.13},{lat:35.68,lng:139.69},{lat:50.12,lng:8.68},{lat:1.35,lng:103.82},{lat:-33.87,lng:151.21},{lat:37.4,lng:-122.07},{lat:47.6,lng:-122.3},{lat:40.71,lng:-74.01},{lat:19.08,lng:72.88},{lat:-23.55,lng:-46.63},{lat:59.33,lng:18.07},{lat:55.75,lng:37.62},{lat:22.28,lng:114.16},{lat:48.86,lng:2.35},{lat:52.52,lng:13.41},{lat:34.05,lng:-118.24},{lat:25.2,lng:55.27}];

C.addEventListener('mousedown',function(e){dr=true;document.body.classList.add('dragging');lx=e.clientX;ly=e.clientY;ar=false;});
C.addEventListener('mousemove',function(e){if(!dr)return;rY+=(e.clientX-lx)*0.005;rX+=(e.clientY-ly)*0.005;rX=Math.max(-1.3,Math.min(1.3,rX));lx=e.clientX;ly=e.clientY;});
C.addEventListener('mouseup',function(){dr=false;document.body.classList.remove('dragging');setTimeout(function(){ar=true;},4000);});
C.addEventListener('mouseleave',function(){dr=false;document.body.classList.remove('dragging');});

function dBg(t){
var bg=X.createRadialGradient(cx,cy,0,cx,cy,Math.max(W,H)*0.7);
bg.addColorStop(0,'#080818');bg.addColorStop(0.4,'#050512');bg.addColorStop(0.7,'#030309');bg.addColorStop(1,'#020206');
X.fillStyle=bg;X.fillRect(0,0,W,H);
nb.forEach(function(n){n.x+=n.dr;if(n.x<-n.r)n.x=W+n.r;if(n.x>W+n.r)n.x=-n.r;
var g=X.createRadialGradient(n.x,n.y,0,n.x,n.y,n.r);
g.addColorStop(0,'hsla('+n.hu+',80%,35%,'+n.al+')');g.addColorStop(0.4,'hsla('+n.hu+',60%,20%,'+(n.al*0.5)+')');g.addColorStop(1,'transparent');
X.fillStyle=g;X.beginPath();X.arc(n.x,n.y,n.r,0,6.28);X.fill();});
st.forEach(function(s){var a=0.2+Math.sin(t*s.sp+s.of)*0.25;
X.fillStyle=s.hu>0?'hsla('+s.hu+',70%,75%,'+a+')':'rgba(255,255,255,'+a+')';X.fillRect(s.x,s.y,s.sz,s.sz);});}

function dGl(t){var r=GR();
for(var i=3;i>=0;i--){var gr=r*(1.08+i*0.06),ga=(0.025-i*0.004)+Math.sin(t*0.4)*0.005;
var at=X.createRadialGradient(cx,cy,r*0.95,cx,cy,gr);
at.addColorStop(0,'rgba(0,180,255,0)');at.addColorStop(0.3,'rgba(0,180,255,'+ga+')');at.addColorStop(0.6,'rgba(0,120,255,'+(ga*0.6)+')');at.addColorStop(1,'rgba(0,60,255,0)');
X.fillStyle=at;X.beginPath();X.arc(cx,cy,gr,0,6.28);X.fill();}
var bg2=X.createRadialGradient(cx-r*0.2,cy-r*0.2,r*0.05,cx,cy,r);
bg2.addColorStop(0,'#0e0e30');bg2.addColorStop(0.4,'#090920');bg2.addColorStop(0.7,'#060615');bg2.addColorStop(1,'#030310');
X.fillStyle=bg2;X.beginPath();X.arc(cx,cy,r,0,6.28);X.fill();
var rim=X.createRadialGradient(cx,cy,r*0.88,cx,cy,r*1.01);
rim.addColorStop(0,'rgba(0,180,255,0)');rim.addColorStop(0.7,'rgba(0,180,255,'+(0.04+Math.sin(t*0.6)*0.015)+')');rim.addColorStop(1,'rgba(0,100,255,0)');
X.fillStyle=rim;X.beginPath();X.arc(cx,cy,r*1.01,0,6.28);X.fill();
X.lineWidth=0.4;
for(var la=-80;la<=80;la+=20){X.strokeStyle='rgba(0,200,255,'+(0.035+Math.sin(t*0.3+la*0.05)*0.008)+')';X.beginPath();var fv=true;
for(var lo=0;lo<=360;lo+=2.5){var p=ll(la,lo,r),rv=rot(p.x,p.y,p.z);if(rv.z>0){fv=true;continue;}var pp=pj(rv.x,rv.y,rv.z);if(fv){X.moveTo(pp.x,pp.y);fv=false;}else X.lineTo(pp.x,pp.y);}X.stroke();}
for(var lo2=0;lo2<360;lo2+=20){X.strokeStyle='rgba(0,200,255,'+(0.035+Math.sin(t*0.3+lo2*0.03)*0.008)+')';X.beginPath();var fv2=true;
for(var la2=-90;la2<=90;la2+=2.5){var p2=ll(la2,lo2,r),rv2=rot(p2.x,p2.y,p2.z);if(rv2.z>0){fv2=true;continue;}var pp2=pj(rv2.x,rv2.y,rv2.z);if(fv2){X.moveTo(pp2.x,pp2.y);fv2=false;}else X.lineTo(pp2.x,pp2.y);}X.stroke();}
var ea=0.12+Math.sin(t*1.2)*0.04;X.strokeStyle='rgba(0,200,255,'+ea+')';X.lineWidth=1.5;X.beginPath();X.arc(cx,cy,r,0,6.28);X.stroke();
X.strokeStyle='rgba(0,160,255,'+(ea*0.3)+')';X.lineWidth=0.8;X.beginPath();X.arc(cx,cy,r*1.015,0,6.28);X.stroke();}

function dCn(t){var r=GR();cd.forEach(function(d){
var p=ll(d.lat,d.lng,r*1.003),rv=rot(p.x,p.y,p.z);if(rv.z>0)return;
var pp=pj(rv.x,rv.y,rv.z),dp=Math.min(0.65,0.2+pp.s*0.3),sz=Math.max(0.6,d.sz*pp.s);
if(d.ci){X.fillStyle='rgba(0,220,255,'+(dp*1.2)+')';X.beginPath();X.arc(pp.x,pp.y,sz*1.5,0,6.28);X.fill();
var cg=X.createRadialGradient(pp.x,pp.y,0,pp.x,pp.y,sz*6);cg.addColorStop(0,'rgba(0,200,255,'+(dp*0.25)+')');cg.addColorStop(1,'rgba(0,200,255,0)');
X.fillStyle=cg;X.beginPath();X.arc(pp.x,pp.y,sz*6,0,6.28);X.fill();}
else{X.fillStyle='rgba(0,'+(180+Math.floor(d.br*60))+','+(200+Math.floor(d.br*55))+','+(dp*d.br)+')';X.fillRect(pp.x-sz/2,pp.y-sz/2,sz,sz);}});}

function dOr(t){var r=GR(),p=ll(O.lat,O.lng,r*1.01),rv=rot(p.x,p.y,p.z);if(rv.z>r*0.3)return;var pp=pj(rv.x,rv.y,rv.z);
for(var i=0;i<3;i++){var pr=(8+i*9+Math.sin(t*3-i*0.8)*6)*pp.s,pa=Math.max(0,(0.45-i*0.12)+Math.sin(t*3-i*0.8)*0.15);
X.strokeStyle='rgba(0,255,102,'+pa+')';X.lineWidth=1.8-i*0.4;X.beginPath();X.arc(pp.x,pp.y,pr,0,6.28);X.stroke();}
var sa=t*2;X.strokeStyle='rgba(0,255,102,0.3)';X.lineWidth=1.2;X.beginPath();X.arc(pp.x,pp.y,22*pp.s,sa,sa+1.8);X.stroke();
X.fillStyle='#00ff66';X.shadowColor='#00ff66';X.shadowBlur=20;X.beginPath();X.arc(pp.x,pp.y,5*pp.s,0,6.28);X.fill();X.shadowBlur=0;
if(rv.z<-r*0.1){X.fillStyle='rgba(0,255,102,0.75)';X.font='bold '+Math.max(8,Math.round(10*pp.s))+'px monospace';X.fillText('YOUR DEVICE',pp.x+14*pp.s,pp.y-10*pp.s);}}

function dAr(dt,t){var r=GR();aC=0;arcs.forEach(function(a){a.lt+=dt;a.pp+=dt*a.ps;if(a.pp>1)a.pp=0;if(a.lt>=a.ml)return;aC++;
var pts=[],ns=56,dL=a.eLo-a.sLo;if(dL>180)dL-=360;if(dL<-180)dL+=360;
var ds=Math.sqrt(Math.pow(a.eLa-a.sLa,2)+Math.pow(dL,2));
for(var i=0;i<=ns;i++){var tt=i/ns,la=a.sLa+(a.eLa-a.sLa)*tt,lo=a.sLo+dL*tt,el=1+Math.sin(tt*Math.PI)*(ds/180)*0.4;
var p=ll(la,lo,r*el),rv=rot(p.x,p.y,p.z),pp=pj(rv.x,rv.y,rv.z);pts.push({x:pp.x,y:pp.y,z:rv.z,s:pp.s});}
var lr=a.lt/a.ml,ba=lr<0.1?lr/0.1:lr>0.7?(1-lr)/0.3:1;
for(var i2=1;i2<pts.length;i2++){if(pts[i2-1].z>r*0.4&&pts[i2].z>r*0.4)continue;
var sa2=ba*(pts[i2].z<0?0.75:0.12);
X.globalAlpha=sa2*0.3;X.strokeStyle=a.c;X.lineWidth=a.gs;X.beginPath();X.moveTo(pts[i2-1].x,pts[i2-1].y);X.lineTo(pts[i2].x,pts[i2].y);X.stroke();
X.globalAlpha=sa2;X.lineWidth=a.w;X.beginPath();X.moveTo(pts[i2-1].x,pts[i2-1].y);X.lineTo(pts[i2].x,pts[i2].y);X.stroke();}
X.globalAlpha=1;
var pi=Math.floor(a.pp*ns);if(pi>=0&&pi<pts.length&&pts[pi].z<r*0.3){var pp2=pts[pi];
for(var j=Math.max(0,pi-5);j<pi;j++){if(pts[j].z>r*0.3)continue;var ta2=(1-(pi-j)/6)*0.45*ba;
X.fillStyle=a.c;X.globalAlpha=ta2;X.beginPath();X.arc(pts[j].x,pts[j].y,(a.tk?2.5:1.5)*pts[j].s,0,6.28);X.fill();}
X.globalAlpha=1;X.fillStyle='#fff';X.shadowColor=a.c;X.shadowBlur=18;X.beginPath();X.arc(pp2.x,pp2.y,(a.tk?5:3.5)*pp2.s,0,6.28);X.fill();X.shadowBlur=0;}});}

function dPt(dt){var r=GR();pt.forEach(function(p){p.ag+=dt;if(p.ag>p.li)return;p.pg+=dt*p.sp;if(p.pg>1)p.pg=0;
var dL=p.eLo-p.sLo;if(dL>180)dL-=360;if(dL<-180)dL+=360;var ds=Math.sqrt(Math.pow(p.eLa-p.sLa,2)+Math.pow(dL,2));
var la=p.sLa+(p.eLa-p.sLa)*p.pg,lo=p.sLo+dL*p.pg,el=1+Math.sin(p.pg*Math.PI)*(ds/180)*0.4;
var p3=ll(la,lo,r*el),rv=rot(p3.x,p3.y,p3.z);if(rv.z>r*0.3)return;var pp=pj(rv.x,rv.y,rv.z);
var la2=Math.min(1,1-(p.ag/p.li));X.fillStyle=p.c;X.globalAlpha=la2*0.55;X.beginPath();X.arc(pp.x,pp.y,p.sz*pp.s,0,6.28);X.fill();X.globalAlpha=1;});
for(var i=pt.length-1;i>=0;i--)if(pt[i].ag>pt[i].li)pt.splice(i,1);}

function dRp(dt){var r=GR();rp.forEach(function(p){p.r+=dt*p.sp;p.al=Math.max(0,0.9*(1-p.r/p.mr));if(p.al<=0)return;
var p3=ll(p.lat,p.lng,r*1.01),rv=rot(p3.x,p3.y,p3.z);if(rv.z>r*0.2)return;var pp=pj(rv.x,rv.y,rv.z);
X.strokeStyle=p.c;X.globalAlpha=p.al;X.lineWidth=1.5;X.beginPath();X.arc(pp.x,pp.y,p.r*pp.s,0,6.28);X.stroke();X.globalAlpha=1;});
for(var i=rp.length-1;i>=0;i--)if(rp[i].al<=0)rp.splice(i,1);}

function dDm(t){var r=GR();dm.forEach(function(m,i){var p=ll(m.lat,m.lng,r*1.01),rv=rot(p.x,p.y,p.z);if(rv.z>r*0.2)return;
var pp=pj(rv.x,rv.y,rv.z),dc=Math.max(0.03,m.al-(t-m.t)*0.012);if(dc<=0)return;
var pl=1+Math.sin(t*2.5+i*0.7)*0.4,sz=(m.tk?4.5:3)*pp.s*pl;
X.fillStyle=m.c;X.globalAlpha=dc*0.35;X.shadowColor=m.c;X.shadowBlur=m.tk?12:8;X.beginPath();X.arc(pp.x,pp.y,sz*1.8,0,6.28);X.fill();X.shadowBlur=0;
X.globalAlpha=dc*0.8;X.beginPath();X.arc(pp.x,pp.y,sz,0,6.28);X.fill();
X.fillStyle='#fff';X.globalAlpha=dc*0.4;X.beginPath();X.arc(pp.x,pp.y,sz*0.35,0,6.28);X.fill();X.globalAlpha=1;});}

function dHd(t){var a=0.3+Math.sin(t)*0.05;
X.strokeStyle='rgba(0,240,255,'+(a*0.5)+')';X.lineWidth=1;
[[15,50,15,15,50,15],[W-15,H-50,W-15,H-15,W-50,H-15],[W-15,50,W-15,15,W-50,15],[15,H-50,15,H-15,50,H-15]].forEach(function(c){
X.beginPath();X.moveTo(c[0],c[1]);X.lineTo(c[2],c[3]);X.lineTo(c[4],c[5]);X.stroke();});
X.fillStyle='rgba(0,240,255,'+a+')';X.font='9px monospace';X.fillText('VEIL GLOBE v3.0',22,32);
X.fillStyle='rgba(0,240,255,'+(a*0.65)+')';X.fillText('ACTIVE ARCS: '+aC,22,48);X.fillText('TOTAL: '+tA,22,62);X.fillText('TRACKERS: '+tkA,22,76);X.fillText('ENDPOINTS: '+dm.length,22,90);
X.fillStyle='rgba(0,255,102,0.5)';X.textAlign='right';X.fillText('MONITORING',W-22,32);X.textAlign='left';
if(tkA>0){var tw=tkA+' TRACKER'+(tkA>1?'S':'')+' DETECTED';X.font='bold 11px monospace';var tm=X.measureText(tw);X.fillStyle='rgba(255,51,68,'+(0.5+Math.sin(t*3)*0.3)+')';X.fillText(tw,cx-tm.width/2,H-22);}
X.strokeStyle='rgba(0,240,255,'+(0.03+Math.sin(t*0.5)*0.015)+')';X.lineWidth=0.5;X.beginPath();X.moveTo(cx-28,cy);X.lineTo(cx+28,cy);X.stroke();X.beginPath();X.moveTo(cx,cy-28);X.lineTo(cx,cy+28);X.stroke();
X.fillStyle='rgba(0,240,255,0.005)';for(var y=0;y<H;y+=3)X.fillRect(0,y,W,1);}

var lT=0,dT=0;
function render(ts){requestAnimationFrame(render);var t=ts/1000,dt=Math.min(0.05,t-lT);lT=t;
if(ar)rY+=0.003;dBg(t);dGl(t);dCn(t);dOr(t);dAr(dt,t);dPt(dt);dRp(dt);dDm(t);dHd(t);
dT+=dt;if(dT>0.7){dT=0;if(Math.random()<0.6){var d=sd[Math.floor(Math.random()*sd.length)];
window.activateArc({lat:d.lat+Math.random()*3-1.5,lng:d.lng+Math.random()*3-1.5,tracker:Math.random()<0.18});}}}
requestAnimationFrame(render);
</script></body></html>'''


# ===========================================================================
# Main Window — The Command Center
# ===========================================================================

class VeilMainWindow(QMainWindow):
    """VEIL 3.0 — Network Traffic Exposer — Main Application Window."""

    packet_received = pyqtSignal(object)
    alert_received = pyqtSignal(object)

    def __init__(self, openai_key: str = ""):
        super().__init__()
        self.setWindowTitle(f"VEIL {__version__} — Network Traffic Exposer | NEATLABS")
        self.setMinimumSize(1400, 850)
        self.resize(1600, 950)

        # Core engine
        self.engine = SnifferEngine()
        self.engine.on_packet(self._on_packet_threadsafe)
        self.engine.on_alert(self._on_alert_threadsafe)

        self.ai_analyzer = AIAnalyzer(api_key=openai_key, model="gpt-4.1-nano")
        self.ip_intel = IPIntelligence()

        # Thread-safe signals
        self.packet_received.connect(self._handle_packet)
        self.alert_received.connect(self._handle_alert)

        # Build UI
        self._build_menu_bar()
        self._build_toolbar()
        self._build_ui()
        self._build_status_bar()

        # Timers
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_stats)
        self.update_timer.start(1000)

        self.clock_timer = QTimer()
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start(1000)

        self.snapshot_timer = QTimer()
        self.snapshot_timer.timeout.connect(self._take_snapshot)
        self.snapshot_timer.start(30000)

        self._last_pkt_count = 0
        self._last_tracker_count = 0
        self._current_font_size = 12

        # System tray icon (#5)
        self._setup_tray()

        logger.info(f"VEIL {__version__} UI initialized")

    # ---- Menu Bar ----
    def _build_menu_bar(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        for text, shortcut, slot in [
            ("&Start Capture", "Ctrl+S", self.start_capture),
            ("Sto&p Capture", "Ctrl+P", self.stop_capture),
        ]:
            action = QAction(text, self)
            action.setShortcut(shortcut)
            action.triggered.connect(slot)
            file_menu.addAction(action)
        file_menu.addSeparator()
        for text, shortcut, slot in [
            ("Export &JSON...", "Ctrl+J", self.export_json),
            ("Export &CSV...", "Ctrl+E", self.export_csv),
            ("Export &HTML Report...", "Ctrl+H", self.export_html_report),
        ]:
            action = QAction(text, self)
            action.setShortcut(shortcut)
            action.triggered.connect(slot)
            file_menu.addAction(action)
        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # View menu
        view_menu = menubar.addMenu("&View")
        self.toggle_globe_action = QAction("Show &Globe", self, checkable=True, checked=True)
        self.toggle_globe_action.triggered.connect(lambda c: self.globe.setVisible(c))
        view_menu.addAction(self.toggle_globe_action)
        view_menu.addSeparator()
        font_menu = view_menu.addMenu("&Font Size")
        for label, size in [("Small (10px)", 10), ("Medium (12px)", 12),
                            ("Large (14px)", 14), ("Extra Large (16px)", 16)]:
            fa = QAction(label, self, checkable=True, checked=(size == 12))
            fa.triggered.connect(lambda checked, s=size: self._set_font_size(s))
            font_menu.addAction(fa)
        self._font_actions = font_menu.actions()

        # Capture menu
        capture_menu = menubar.addMenu("&Capture")
        self.iface_menu = capture_menu.addMenu("&Interface")
        self._populate_interfaces()
        capture_menu.addSeparator()
        clear_action = QAction("&Clear All Data", self)
        clear_action.triggered.connect(self._clear_data)
        capture_menu.addAction(clear_action)

        # AI menu
        ai_menu = menubar.addMenu("&AI")
        set_key = QAction("Set &API Key...", self)
        set_key.triggered.connect(self._set_api_key)
        ai_menu.addAction(set_key)

        self.privacy_toggle = QAction("&Privacy Mode (Anonymize Data)", self, checkable=True)
        self.privacy_toggle.setToolTip("Anonymize IPs and hostnames before sending to AI")
        self.privacy_toggle.triggered.connect(self._toggle_privacy_mode)
        ai_menu.addAction(self.privacy_toggle)

        ai_menu.addSeparator()
        for text, slot_name in [
            ("Full Traffic &Analysis", "_run_summary"),
            ("&Tracker Intelligence", "_run_tracker_intel"),
            ("Anomaly &Detection", "_run_anomaly"),
            ("&Executive Brief", "_run_brief"),
            ("&Generate Block Rules", "_run_firewall"),
        ]:
            action = QAction(text, self)
            action.triggered.connect(lambda checked, s=slot_name: getattr(self.ai_chat, s)())
            ai_menu.addAction(action)

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about = QAction("&About VEIL", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _populate_interfaces(self):
        try:
            import psutil
            for name in psutil.net_if_addrs().keys():
                action = QAction(name, self, checkable=True)
                action.triggered.connect(partial(self._set_interface, name))
                self.iface_menu.addAction(action)
        except ImportError:
            self.iface_menu.addAction(QAction("Default", self, checkable=True, checked=True))

    def _set_interface(self, name):
        self.engine.interface = name
        for a in self.iface_menu.actions():
            a.setChecked(a.text() == name)

    # ---- Toolbar ----
    def _build_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(52)
        toolbar.setStyleSheet(
            f"QToolBar {{ background: rgba(5,5,16,0.95); "
            f"border-bottom: 1px solid {Colors.BORDER}; padding: 4px 16px; spacing: 12px; }}")

        logo = QLabel("  \u25c6 VEIL")
        logo.setStyleSheet("font-size: 22px; font-weight: 900; letter-spacing: 6px; "
                          "color: #00f0ff; background: transparent; padding-right: 8px;")
        toolbar.addWidget(logo)

        subtitle = QLabel("NETWORK TRAFFIC EXPOSER  ")
        subtitle.setStyleSheet(f"font-size: 9px; letter-spacing: 3px; "
                              f"color: {Colors.TEXT_DIM}; background: transparent;")
        toolbar.addWidget(subtitle)

        toolbar.addSeparator()

        # Packet pulse indicator
        self.packet_pulse = PacketPulse()
        toolbar.addWidget(self.packet_pulse)

        toolbar.addSeparator()

        self.start_btn = QPushButton("\u25b6 START")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setFixedWidth(110)
        toolbar.addWidget(self.start_btn)

        self.stop_btn = QPushButton("\u25a0 STOP")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setFixedWidth(100)
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)

        toolbar.addSeparator()

        filter_label = QLabel("  FILTER: ")
        filter_label.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 10px; "
                                   f"letter-spacing: 2px; background: transparent;")
        toolbar.addWidget(filter_label)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("app name, host, or IP...")
        self.filter_input.setFixedWidth(220)
        self.filter_input.setFixedHeight(30)
        toolbar.addWidget(self.filter_input)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        spacer.setStyleSheet("background: transparent;")
        toolbar.addWidget(spacer)

        self.capture_status = QLabel("\u25cf IDLE")
        self.capture_status.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 11px; "
                                          f"font-weight: bold; background: transparent; padding-right: 8px;")
        toolbar.addWidget(self.capture_status)

        self.mode_label = QLabel(f"MODE: {self.engine.capture_mode.upper()}")
        self.mode_label.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 9px; "
                                      f"letter-spacing: 2px; background: transparent; padding-right: 16px;")
        toolbar.addWidget(self.mode_label)

        v_label = QLabel(f"v{__version__}  ")
        v_label.setStyleSheet(f"font-size: 9px; letter-spacing: 2px; "
                             f"color: {Colors.TEXT_DIM}; background: transparent;")
        toolbar.addWidget(v_label)

        neatlabs = QLabel("NEATLABS  ")
        neatlabs.setStyleSheet(f"font-size: 9px; letter-spacing: 3px; "
                              f"color: {Colors.TEXT_DIM}; background: transparent;")
        toolbar.addWidget(neatlabs)

        self.addToolBar(toolbar)

    # ---- Main UI Layout ----
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(8, 4, 8, 4)
        main_layout.setSpacing(8)

        # ==== LEFT COLUMN (main content) ====
        left_col = QVBoxLayout()
        left_col.setSpacing(6)

        # ---- Stats Row: 6 Animated Cards ----
        stats_row = QHBoxLayout()
        stats_row.setSpacing(6)
        self.stat_conns = AnimatedStatCard("Active Connections", Colors.CYAN)
        self.stat_endpoints = AnimatedStatCard("Unique Endpoints", Colors.MAGENTA)
        self.stat_trackers = AnimatedStatCard("Trackers Found", Colors.RED)
        self.stat_leaked = AnimatedStatCard("Data Leaked", Colors.ORANGE)
        self.stat_packets = AnimatedStatCard("Total Packets", Colors.GREEN)
        self.stat_dns = AnimatedStatCard("DNS Queries", Colors.PURPLE)
        for card in [self.stat_conns, self.stat_endpoints, self.stat_trackers,
                     self.stat_leaked, self.stat_packets, self.stat_dns]:
            stats_row.addWidget(card)
        left_col.addLayout(stats_row)

        # ---- Middle: Globe + Right Panels ----
        middle_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.globe = GlobeWidget()
        self.globe.setMinimumWidth(400)
        middle_splitter.addWidget(self.globe)

        # Right panel tabs
        right_tabs = QTabWidget()
        right_tabs.setMinimumWidth(360)

        self.ai_chat = AIChatPanel()
        self.ai_chat.set_analyzer(self.ai_analyzer, self.engine)
        right_tabs.addTab(self.ai_chat, "AI ANALYSIS")

        self.live_feed = LiveFeedWidget()
        right_tabs.addTab(self.live_feed, "LIVE FEED")

        self.alerts_panel = AlertsWidget()
        right_tabs.addTab(self.alerts_panel, "ALERTS")

        self.dns_panel = DNSLogPanel()
        right_tabs.addTab(self.dns_panel, "DNS LOG")

        self.timeline = ConnectionTimeline()
        right_tabs.addTab(self.timeline, "TIMELINE")

        self.phone_home_panel = PhoneHomePanel()
        right_tabs.addTab(self.phone_home_panel, "PHONE HOME")

        middle_splitter.addWidget(right_tabs)
        middle_splitter.setSizes([600, 400])
        left_col.addWidget(middle_splitter, stretch=1)

        # ---- Bottom: Tables + Sidebar ----
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        bottom_tabs = QTabWidget()

        self.conn_table = ConnectionTable()
        bottom_tabs.addTab(self.conn_table, "CONNECTIONS")

        self.app_table = AppMonitorTable()
        bottom_tabs.addTab(self.app_table, "APPS")

        self.tracker_panel = TrackerPanel()
        bottom_tabs.addTab(self.tracker_panel, "TRACKERS")

        self.dest_heatmap = DestinationHeatmap()
        bottom_tabs.addTab(self.dest_heatmap, "DESTINATIONS")

        self.ip_intel_panel = IPIntelPanel()
        self.ip_intel_panel.set_intel(self.ip_intel)
        bottom_tabs.addTab(self.ip_intel_panel, "IP INTEL")

        self.snapshot_panel = SessionSnapshotPanel()
        self.snapshot_panel.set_engine(self.engine)
        bottom_tabs.addTab(self.snapshot_panel, "SNAPSHOTS")

        bottom_splitter.addWidget(bottom_tabs)

        # ==== RIGHT SIDEBAR (animated widgets) ====
        sidebar = QVBoxLayout()
        sidebar.setSpacing(6)

        # Privacy Gauge — the hero widget
        self.privacy_gauge = AnimatedPrivacyGauge()
        self.privacy_gauge.setMinimumHeight(200)
        self.privacy_gauge.setMaximumHeight(220)
        sidebar.addWidget(self.privacy_gauge)

        # Bandwidth sparkline
        self.bandwidth_spark = SparklineGraph("BANDWIDTH", Colors.CYAN, 80)
        self.bandwidth_spark.setFixedHeight(75)
        sidebar.addWidget(self.bandwidth_spark)

        # Threat meter
        self.threat_meter = ThreatMeter()
        sidebar.addWidget(self.threat_meter)

        # Protocol donut
        self.proto_donut = ProtocolDonut()
        sidebar.addWidget(self.proto_donut)

        # Company traffic
        self.company_widget = CompanyTrafficWidget()
        self.company_widget.setFixedHeight(130)
        sidebar.addWidget(self.company_widget)

        # Top talkers
        self.top_talkers = TopTalkersWidget()
        self.top_talkers.setFixedHeight(180)
        sidebar.addWidget(self.top_talkers)

        sidebar.addStretch()

        # Quick action buttons
        ai_btn = QPushButton("AI ANALYZE")
        ai_btn.setStyleSheet(
            f"font-size: 10px; font-weight: bold; letter-spacing: 2px; "
            f"background: rgba(255,0,170,0.1); border: 1px solid rgba(255,0,170,0.4); "
            f"color: {Colors.MAGENTA}; padding: 8px; min-height: 28px;")
        ai_btn.clicked.connect(lambda: self.ai_chat._run_summary())
        sidebar.addWidget(ai_btn)

        export_btn = QPushButton("EXPORT DATA")
        export_btn.setObjectName("exportBtn")
        export_btn.clicked.connect(self.export_json)
        sidebar.addWidget(export_btn)

        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setFixedWidth(250)
        bottom_splitter.addWidget(sidebar_widget)

        left_col.addWidget(bottom_splitter, stretch=1)
        main_layout.addLayout(left_col)

    # ---- Status Bar ----
    def _build_status_bar(self):
        self.statusBar().showMessage(f"VEIL {__version__} Ready — Press START to begin capture")
        self.uptime_label = QLabel("UPTIME: 00:00:00")
        self.uptime_label.setStyleSheet(f"color: {Colors.TEXT_DIM}; padding-right: 16px;")
        self.statusBar().addPermanentWidget(self.uptime_label)
        self.mode_status = QLabel(f"CAPTURE: {self.engine.capture_mode.upper()}")
        self.mode_status.setStyleSheet(f"color: {Colors.TEXT_DIM}; padding-right: 16px;")
        self.statusBar().addPermanentWidget(self.mode_status)
        self.geo_cache = QLabel("GEO CACHE: 0")
        self.geo_cache.setStyleSheet(f"color: {Colors.TEXT_DIM}; padding-right: 16px;")
        self.statusBar().addPermanentWidget(self.geo_cache)
        self.clock_label = QLabel("")
        self.clock_label.setStyleSheet(f"color: {Colors.CYAN}; font-weight: bold; padding-right: 8px;")
        self.statusBar().addPermanentWidget(self.clock_label)

    # ---- Engine Callbacks (thread-safe) ----
    def _on_packet_threadsafe(self, conn):
        self.packet_received.emit(conn)

    def _on_alert_threadsafe(self, alert):
        self.alert_received.emit(alert)

    def _handle_packet(self, conn):
        # Apply filter
        f = self.filter_input.text().lower().strip()
        if f:
            searchable = f"{conn.app_name} {conn.dst_host} {conn.dst_ip} {conn.tracker_name}".lower()
            if f not in searchable:
                return

        self.live_feed.add_packet(conn)
        self.conn_table.add_connection(conn)
        self.tracker_panel.add_tracker(conn)
        self.dns_panel.add_query(conn)

        # Pulse indicator
        self.packet_pulse.pulse(conn.is_tracker)

        # Globe arc
        if conn.geo and conn.geo.lat != 0:
            self.globe.add_connection_arc(conn.geo.lat, conn.geo.lng, conn.is_tracker)

    def _handle_alert(self, alert):
        self.alerts_panel.add_alert(alert)
        # Tray notification for critical/high alerts when minimized
        if alert.get("level") in ("critical", "high") and not self.isVisible():
            self._tray_notify(
                f"VEIL Alert [{alert['level'].upper()}]",
                alert.get("message", "Security alert detected")
            )

    # ---- Periodic Updates ----
    def _update_stats(self):
        if not self.engine.running:
            return

        stats = self.engine.stats

        # Animated stat cards
        self.stat_conns.set_value(str(stats.total_sessions))
        self.stat_endpoints.set_value(str(len(stats.unique_endpoints)))
        self.stat_trackers.set_value(str(len(stats.trackers_found)))
        leaked_mb = stats.tracker_bytes / (1024 * 1024)
        self.stat_leaked.set_value(f"{leaked_mb:.1f} MB")
        self.stat_packets.set_value(f"{stats.total_packets:,}")
        self.stat_dns.set_value(str(stats.total_dns_queries))

        # Privacy gauge (animated ring)
        self.privacy_gauge.set_score(stats.privacy_score)

        # Bandwidth sparkline
        bw = self.engine.bandwidth
        mbps = bw / (1024 * 1024)
        if mbps < 1:
            bw_text = f"{bw/1024:.1f} KB/s"
        else:
            bw_text = f"{mbps:.2f} MB/s"
        self.bandwidth_spark.add_value(bw, bw_text)

        # Threat meter
        self.threat_meter.set_level(stats.privacy_score / 100)

        # Protocol donut
        self.proto_donut.update_data(dict(stats.protocols))

        # Company traffic
        self.company_widget.update_data(self.engine.get_company_data())

        # Top talkers
        self.top_talkers.update_data(self.engine.app_stats)

        # App table
        self.app_table.update_data(self.engine.app_stats)

        # Phone home detector (every 5 seconds)
        if stats.total_packets % 5 == 0:
            self.phone_home_panel.update_data(self.engine.get_phone_home_data())
            self.dest_heatmap.update_data(self.engine.dest_stats, self.ip_intel)

        # Timeline
        pps = stats.total_packets - self._last_pkt_count
        tracker_pps = len(stats.trackers_found) - self._last_tracker_count
        self.timeline.add_datapoint(pps, self.engine.bandwidth, tracker_pps)
        self._last_pkt_count = stats.total_packets
        self._last_tracker_count = len(stats.trackers_found)

        # Uptime
        elapsed = time.time() - stats.start_time
        h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
        self.uptime_label.setText(f"UPTIME: {h:02d}:{m:02d}:{s:02d}")
        self.geo_cache.setText(f"GEO CACHE: {self.engine.geo_resolver.cache_size}")

        self.statusBar().showMessage(
            f"Capturing -- {stats.total_packets:,} packets | "
            f"{len(stats.unique_endpoints)} endpoints | "
            f"{len(stats.trackers_found)} trackers | "
            f"{len(self.engine.company_stats)} companies")

    def _update_clock(self):
        self.clock_label.setText(datetime.now().strftime("%H:%M:%S"))

    # ---- Actions ----
    def start_capture(self):
        self.engine.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.capture_status.setText("\u25cf INTERCEPTING")
        self.capture_status.setStyleSheet("color: #00ff66; font-size: 11px; "
                                          "font-weight: bold; background: transparent; padding-right: 8px;")
        self.statusBar().showMessage("Capture started...")

    def stop_capture(self):
        self.engine.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.capture_status.setText("\u25cf STOPPED")
        self.capture_status.setStyleSheet(f"color: {Colors.RED}; font-size: 11px; "
                                          f"font-weight: bold; background: transparent; padding-right: 8px;")
        self.statusBar().showMessage("Capture stopped")

    def export_json(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", f"veil_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)")
        if filepath:
            self.engine.export_json(filepath)
            self.statusBar().showMessage(f"Exported to {filepath}")

    def export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", f"veil_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)")
        if filepath:
            self.engine.export_csv(filepath)
            self.statusBar().showMessage(f"Exported to {filepath}")

    def _clear_data(self):
        reply = QMessageBox.question(self, "Clear Data", "Clear all captured data?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.engine.stats = type(self.engine.stats)(start_time=time.time())
            self.engine.app_stats.clear()
            self.engine.dest_stats.clear()
            self.engine.company_stats.clear()
            self.engine.phone_home_apps.clear()
            self.engine.connections.clear()
            self.conn_table.setRowCount(0)
            self.statusBar().showMessage("Data cleared")

    def _show_about(self):
        QMessageBox.about(self, "About VEIL",
            f"<h2 style='color:#00f0ff'>\u25c6 VEIL {__version__}</h2>"
            "<p><b>Network Traffic Exposer</b></p>"
            "<p style='color:#888'>AI-Enhanced Cyberpunk Dashboard</p>"
            "<br>"
            "<p>Real-time network traffic visualization and AI-powered analysis. "
            "Exposes every connection your computer makes &mdash; who it's talking to, "
            "what data is flowing, which apps are phoning home, "
            "and which trackers are active.</p>"
            "<br>"
            "<p><b>AI Engine:</b> OpenAI GPT-4.1-nano / Anthropic Claude (user's choice)</p>"
            "<p><b>Capture:</b> Scapy / Raw Socket / psutil (3-tier fallback)</p>"
            "<p><b>Tracker DB:</b> 67+ signatures</p>"
            "<br>"
            "<p><b>Features:</b></p>"
            "<p>&bull; Real-time packet capture with process mapping<br>"
            "&bull; GeoIP resolution with 3D globe visualization<br>"
            "&bull; Tracker &amp; ad network detection (67+ signatures)<br>"
            "&bull; Company-level traffic aggregation<br>"
            "&bull; Phone-home detection with suspicion scoring<br>"
            "&bull; AI-powered traffic analysis (5 modes + interactive chat)<br>"
            "&bull; IP intelligence &amp; reputation lookup<br>"
            "&bull; Firewall rule generation (iptables, hosts, uBlock)<br>"
            "&bull; Connection timeline &amp; session snapshots<br>"
            "&bull; JSON/CSV export</p>"
            "<hr>"
            "<p style='color:#00f0ff'><b>NEATLABS\u2122 &mdash; Intelligence Technology</b></p>"
            "<p style='color:#888'>Service-Disabled Veteran-Owned Small Business (SDVOSB)</p>"
            "<p><a href='https://github.com/neatlabs-ai' style='color:#00aadd;'>github.com/neatlabs-ai</a></p>"
            "<br>"
            "<p style='color:#555'>Built with Python, PyQt6, Scapy, OpenAI, Canvas 3D</p>"
            "<p style='color:#444'>Copyright \u00a9 2025-2026 NEATLABS\u2122 / Security 360, LLC</p>"
        )

    def _set_api_key(self):
        key, ok = QInputDialog.getText(self, "Set AI API Key",
            "Enter your API key:\n\n"
            "  OpenAI:     sk-...          (GPT-4.1-nano)\n"
            "  Anthropic:  sk-ant-...      (Claude Sonnet 4)\n\n"
            "VEIL auto-detects the provider from your key format.")
        if ok and key.strip():
            key = key.strip()
            self.ai_analyzer.set_api_key(key)
            self.ai_chat.set_analyzer(self.ai_analyzer, self.engine)

            provider = self.ai_analyzer.provider_display
            self.statusBar().showMessage(f"AI configured: {provider}")

            # Update model label in chat panel
            self.ai_chat.model_label.setText(self.ai_analyzer.model.upper())

            QMessageBox.information(self, "AI Ready",
                f"AI engine configured successfully.\n\n"
                f"Provider: {self.ai_analyzer.provider.upper()}\n"
                f"Model: {self.ai_analyzer.model}\n\n"
                f"All analysis features are now available.")

    def _take_snapshot(self):
        if self.engine.running and self.engine.stats.total_packets > 0:
            self.snapshot_panel.take_snapshot(self.engine)

    # ---- System Tray (#5) ----
    def _setup_tray(self):
        """Create system tray icon with context menu."""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setToolTip(f"VEIL {__version__} — Network Traffic Exposer")

            tray_menu = QMenu()
            tray_menu.setStyleSheet("QMenu{background:#0a0a1a;color:#00f0ff;border:1px solid rgba(0,240,255,0.2);}"
                                   "QMenu::item{padding:6px 20px;}QMenu::item:selected{background:rgba(0,240,255,0.1);}")
            show_action = QAction("Show VEIL", self)
            show_action.triggered.connect(self._tray_show)
            tray_menu.addAction(show_action)
            tray_menu.addSeparator()
            start_action = QAction("Start Capture", self)
            start_action.triggered.connect(self.start_capture)
            tray_menu.addAction(start_action)
            stop_action = QAction("Stop Capture", self)
            stop_action.triggered.connect(self.stop_capture)
            tray_menu.addAction(stop_action)
            tray_menu.addSeparator()
            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(self._tray_quit)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self._tray_activated)
            self.tray_icon.show()
            logger.info("System tray icon created")
        except Exception as e:
            logger.debug(f"System tray not available: {e}")
            self.tray_icon = None

    def _tray_show(self):
        self.showNormal()
        self.activateWindow()

    def _tray_quit(self):
        if self.engine.running:
            self.engine.stop()
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.quit()

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._tray_show()

    def _tray_notify(self, title: str, message: str):
        """Show tray notification for critical alerts."""
        if self.tray_icon and self.tray_icon.isVisible():
            try:
                self.tray_icon.showMessage(title, message,
                    QSystemTrayIcon.MessageIcon.Warning, 5000)
            except Exception:
                pass

    def changeEvent(self, event):
        """Minimize to tray instead of taskbar."""
        from PyQt6.QtCore import QEvent
        if event.type() == QEvent.Type.WindowStateChange:
            if self.windowState() & Qt.WindowState.WindowMinimized:
                if self.tray_icon and self.tray_icon.isVisible():
                    event.ignore()
                    self.hide()
                    score = int(self.engine.stats.privacy_score)
                    self.tray_icon.setToolTip(
                        f"VEIL — Privacy Score: {score}/100 | "
                        f"{self.engine.stats.total_packets:,} packets")
                    return
        super().changeEvent(event)

    # ---- HTML Report Export (#7) ----
    def export_html_report(self):
        """Export styled HTML privacy report."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export HTML Report",
            f"veil_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html)")
        if filepath:
            try:
                html = self.ai_analyzer.generate_html_report(self.engine)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(html)
                self.statusBar().showMessage(f"HTML report exported to {filepath}")
                # Offer to open it
                reply = QMessageBox.question(self, "Report Exported",
                    f"Report saved to:\n{filepath}\n\nOpen in browser?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    import webbrowser
                    webbrowser.open(f"file:///{filepath}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Error: {e}")

    # ---- Font Size (#9) ----
    def _set_font_size(self, size: int):
        """Change application font size."""
        self._current_font_size = size
        app = QApplication.instance()
        if app:
            # Update base stylesheet with new size
            from ui.styles import CYBERPUNK_STYLESHEET
            adjusted = CYBERPUNK_STYLESHEET.replace("font-size: 12px", f"font-size: {size}px")
            adjusted = adjusted.replace("font-size: 11px", f"font-size: {max(9, size - 1)}px")
            adjusted = adjusted.replace("font-size: 10px", f"font-size: {max(8, size - 2)}px")
            app.setStyleSheet(adjusted)
        # Update font action checkmarks
        sizes = [10, 12, 14, 16]
        if hasattr(self, '_font_actions'):
            for i, action in enumerate(self._font_actions):
                action.setChecked(sizes[i] == size)
        self.statusBar().showMessage(f"Font size set to {size}px")

    # ---- Privacy Mode Toggle ----
    def _toggle_privacy_mode(self, enabled):
        """Toggle AI privacy translation layer."""
        self.ai_analyzer.set_privacy_mode(enabled)
        status = "ON — IPs and hostnames will be anonymized before AI analysis" if enabled else "OFF — Full data sent to AI"
        self.statusBar().showMessage(f"Privacy Mode: {status}")
        if enabled:
            QMessageBox.information(self, "Privacy Mode Enabled",
                "Privacy Translation Layer is now ACTIVE.\n\n"
                "When AI analysis runs, your personal data will be anonymized:\n"
                "  - IP addresses replaced with [ENDPOINT_1], [ENDPOINT_2], etc.\n"
                "  - Personal hostnames replaced with [HOST_1], [HOST_2], etc.\n"
                "  - Local network IPs shown as [LOCAL_NET]\n\n"
                "Tracker names, companies, protocols, and traffic patterns\n"
                "are preserved for accurate analysis.\n\n"
                "No personally identifiable information is sent to OpenAI.")

    def closeEvent(self, event):
        if self.engine.running:
            self.engine.stop()
        if hasattr(self, 'tray_icon') and self.tray_icon:
            self.tray_icon.hide()
        event.accept()
