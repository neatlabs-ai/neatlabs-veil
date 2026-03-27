"""
VEIL 3.0 Cyberpunk Theme — PyQt6 Stylesheet
NEATLABS™ Intelligence Technology
"""

CYBERPUNK_STYLESHEET = """
QWidget { background-color: #050510; color: #00f0ff; font-family: "Consolas", "Courier New", monospace; font-size: 12px; selection-background-color: rgba(0, 240, 255, 0.25); selection-color: #ffffff; }
QMainWindow { background-color: #050510; }
QMainWindow::separator { background-color: rgba(0, 240, 255, 0.15); width: 2px; height: 2px; }
QFrame { border: none; }
.CyberPanel { background-color: rgba(5, 8, 22, 0.92); border: 1px solid rgba(0, 240, 255, 0.12); border-radius: 3px; }
.CyberPanel:hover { border: 1px solid rgba(0, 240, 255, 0.28); }
QLabel { color: #00f0ff; background: transparent; padding: 0px; }
QPushButton { background-color: rgba(0, 240, 255, 0.06); border: 1px solid rgba(0, 240, 255, 0.25); color: #00f0ff; padding: 8px 18px; font-size: 11px; font-weight: bold; letter-spacing: 2px; border-radius: 2px; min-height: 28px; }
QPushButton:hover { background-color: rgba(0, 240, 255, 0.14); border: 1px solid rgba(0, 240, 255, 0.5); }
QPushButton:pressed { background-color: rgba(0, 240, 255, 0.25); }
QPushButton:disabled { background-color: rgba(0, 240, 255, 0.02); border: 1px solid rgba(0, 240, 255, 0.08); color: rgba(0, 240, 255, 0.15); }
QPushButton#startBtn { background-color: rgba(0, 255, 102, 0.08); border: 1px solid rgba(0, 255, 102, 0.35); color: #00ff66; }
QPushButton#startBtn:hover { background-color: rgba(0, 255, 102, 0.18); border: 1px solid #00ff66; }
QPushButton#stopBtn { background-color: rgba(255, 51, 68, 0.08); border: 1px solid rgba(255, 51, 68, 0.35); color: #ff3344; }
QPushButton#stopBtn:hover { background-color: rgba(255, 51, 68, 0.18); border: 1px solid #ff3344; }
QPushButton#exportBtn { background-color: rgba(255, 0, 170, 0.06); border: 1px solid rgba(255, 0, 170, 0.25); color: #ff00aa; }
QTableWidget, QTableView { background-color: rgba(5, 8, 22, 0.95); alternate-background-color: rgba(0, 240, 255, 0.015); border: 1px solid rgba(0, 240, 255, 0.08); gridline-color: rgba(0, 240, 255, 0.04); font-size: 11px; selection-background-color: rgba(0, 240, 255, 0.1); }
QTableWidget::item, QTableView::item { padding: 4px 8px; border-bottom: 1px solid rgba(0, 240, 255, 0.03); }
QTableWidget::item:selected { background-color: rgba(0, 240, 255, 0.1); color: #ffffff; }
QHeaderView::section { background-color: rgba(5, 8, 22, 0.98); color: rgba(0, 240, 255, 0.55); border: none; border-bottom: 1px solid rgba(0, 240, 255, 0.12); border-right: 1px solid rgba(0, 240, 255, 0.04); padding: 6px 8px; font-size: 10px; font-weight: bold; letter-spacing: 1px; }
QScrollBar:vertical { background: rgba(5, 5, 16, 0.5); width: 7px; margin: 0; border: none; }
QScrollBar::handle:vertical { background: rgba(0, 240, 255, 0.18); min-height: 30px; border-radius: 3px; }
QScrollBar::handle:vertical:hover { background: rgba(0, 240, 255, 0.3); }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal { background: rgba(5, 5, 16, 0.5); height: 7px; }
QScrollBar::handle:horizontal { background: rgba(0, 240, 255, 0.18); min-width: 30px; border-radius: 3px; }
QTabWidget::pane { border: 1px solid rgba(0, 240, 255, 0.12); background-color: rgba(5, 8, 22, 0.92); }
QTabBar::tab { background-color: rgba(5, 8, 22, 0.8); border: 1px solid rgba(0, 240, 255, 0.08); color: rgba(0, 240, 255, 0.45); padding: 7px 14px; font-size: 10px; font-weight: bold; letter-spacing: 2px; min-width: 80px; }
QTabBar::tab:selected { background-color: rgba(0, 240, 255, 0.06); border-bottom: 2px solid #00f0ff; color: #00f0ff; }
QTabBar::tab:hover:!selected { background-color: rgba(0, 240, 255, 0.04); color: rgba(0, 240, 255, 0.65); }
QComboBox { background-color: rgba(5, 8, 22, 0.95); border: 1px solid rgba(0, 240, 255, 0.18); color: #00f0ff; padding: 6px 12px; font-size: 11px; border-radius: 2px; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background-color: rgba(5, 8, 22, 0.98); border: 1px solid rgba(0, 240, 255, 0.18); color: #00f0ff; selection-background-color: rgba(0, 240, 255, 0.12); }
QLineEdit { background-color: rgba(5, 8, 22, 0.95); border: 1px solid rgba(0, 240, 255, 0.18); color: #00f0ff; padding: 6px 12px; font-size: 11px; border-radius: 2px; }
QLineEdit:focus { border: 1px solid rgba(0, 240, 255, 0.45); }
QProgressBar { background-color: rgba(0, 240, 255, 0.06); border: 1px solid rgba(0, 240, 255, 0.12); border-radius: 2px; height: 8px; text-align: center; font-size: 9px; color: #00f0ff; }
QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00f0ff, stop:1 #ff00aa); border-radius: 2px; }
QSplitter::handle { background-color: rgba(0, 240, 255, 0.08); }
QSplitter::handle:hover { background-color: rgba(0, 240, 255, 0.22); }
QStatusBar { background-color: rgba(5, 5, 16, 0.95); border-top: 1px solid rgba(0, 240, 255, 0.12); color: rgba(0, 240, 255, 0.45); font-size: 10px; }
QStatusBar::item { border: none; }
QToolTip { background-color: rgba(5, 8, 22, 0.97); border: 1px solid rgba(0, 240, 255, 0.25); color: #00f0ff; padding: 6px 10px; font-size: 11px; }
QMenuBar { background-color: rgba(5, 5, 16, 0.95); border-bottom: 1px solid rgba(0, 240, 255, 0.08); color: rgba(0, 240, 255, 0.55); font-size: 11px; }
QMenuBar::item:selected { background-color: rgba(0, 240, 255, 0.08); }
QMenu { background-color: rgba(5, 8, 22, 0.98); border: 1px solid rgba(0, 240, 255, 0.18); color: #00f0ff; padding: 4px; }
QMenu::item { padding: 6px 24px; }
QMenu::item:selected { background-color: rgba(0, 240, 255, 0.1); }
QMenu::separator { height: 1px; background-color: rgba(0, 240, 255, 0.08); margin: 4px 8px; }
QTextEdit, QPlainTextEdit { background-color: rgba(5, 8, 22, 0.95); border: 1px solid rgba(0, 240, 255, 0.08); color: #00f0ff; font-size: 11px; }
QListWidget { background-color: rgba(5, 8, 22, 0.95); border: 1px solid rgba(0, 240, 255, 0.08); alternate-background-color: rgba(0, 240, 255, 0.015); }
QListWidget::item { padding: 6px 10px; border-bottom: 1px solid rgba(0, 240, 255, 0.03); }
QListWidget::item:selected { background-color: rgba(0, 240, 255, 0.1); }
QGroupBox { border: 1px solid rgba(0, 240, 255, 0.12); border-radius: 2px; margin-top: 12px; padding-top: 12px; font-size: 10px; font-weight: bold; color: rgba(0, 240, 255, 0.45); }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QCheckBox { color: rgba(0, 240, 255, 0.65); spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid rgba(0, 240, 255, 0.25); background: rgba(5, 8, 22, 0.95); border-radius: 2px; }
QCheckBox::indicator:checked { background: rgba(0, 240, 255, 0.25); border: 1px solid #00f0ff; }
"""


class Colors:
    """Color constants for VEIL cyberpunk theme."""
    CYAN = "#00f0ff"
    MAGENTA = "#ff00aa"
    GREEN = "#00ff66"
    RED = "#ff3344"
    ORANGE = "#ff8800"
    YELLOW = "#ffee00"
    PURPLE = "#aa44ff"
    ELECTRIC_BLUE = "#4488ff"
    PINK = "#ff44aa"
    TEAL = "#00ddbb"
    WHITE = "#ffffff"
    BG_DARK = "#050510"
    BG_PANEL = "rgba(5, 8, 22, 0.92)"
    BG_DEEPER = "rgba(3, 3, 12, 0.95)"
    TEXT_DIM = "rgba(0, 240, 255, 0.45)"
    TEXT_MID = "rgba(0, 240, 255, 0.7)"
    TEXT_BRIGHT = "rgba(0, 240, 255, 0.9)"
    BORDER = "rgba(0, 240, 255, 0.12)"
    BORDER_HOVER = "rgba(0, 240, 255, 0.28)"

    SEVERITY_COLORS = {
        "critical": "#ff3344", "high": "#ff8800",
        "medium": "#ffee00", "low": "#00f0ff",
    }
    PROTOCOL_COLORS = {
        "HTTPS": "#00ff66", "HTTP": "#ffee00", "TLS 1.3": "#00ff66",
        "TLS 1.2": "#00dd88", "TCP": "#00f0ff", "UDP": "#aa44ff",
        "DNS": "#ff00aa", "QUIC": "#ff8800", "WSS": "#ff00aa",
        "ICMP": "#ffaa00", "OTHER": "#555555",
    }
    RISK_COLORS = {
        "none": "#333333", "low": "#00ff66",
        "medium": "#ffee00", "high": "#ff8800", "critical": "#ff3344",
    }
