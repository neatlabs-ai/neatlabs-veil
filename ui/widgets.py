"""
VEIL 3.0 Animated Widget Library
Custom-painted PyQt6 widgets with cyberpunk visual effects.
Pulsing gauges, sparkline graphs, racing bars, threat meters, and more.

NEATLABS™ Intelligence Technology
"""

import math
import time
from PyQt6.QtWidgets import QWidget, QSizePolicy
from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QLinearGradient,
    QRadialGradient, QPainterPath, QConicalGradient,
)

from ui.styles import Colors


# ---------------------------------------------------------------------------
# Animated Privacy Gauge — The Hero Widget
# ---------------------------------------------------------------------------

class AnimatedPrivacyGauge(QWidget):
    """
    Pulsing neon ring gauge showing privacy exposure score (0–100).
    Features: smooth interpolation, breathing glow, floating particles,
    color transitions green→yellow→orange→red, tick marks, status text.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(200, 200)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._score = 0.0
        self._display_score = 0.0
        self._target_score = 0.0
        self._phase = 0.0
        self._particles = []

        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)  # ~30 fps

    def set_score(self, score: float):
        self._target_score = max(0, min(100, score))

    def _tick(self):
        self._display_score += (self._target_score - self._display_score) * 0.06
        self._phase += 0.05

        # Spawn particles occasionally
        if len(self._particles) < 12 and self._display_score > 5:
            if hash(str(self._phase)) % 7 == 0:
                angle = (self._phase * 40) % 360
                self._particles.append({
                    "angle": angle, "r": 0.0, "speed": 0.3 + (hash(str(angle)) % 10) * 0.05,
                    "life": 1.0, "size": 1.5 + (hash(str(angle + 1)) % 10) * 0.2,
                })

        # Update particles
        for p in self._particles:
            p["r"] += p["speed"]
            p["life"] -= 0.015
        self._particles = [p for p in self._particles if p["life"] > 0]

        self.update()

    def _score_color(self, score: float) -> QColor:
        if score < 25:
            return QColor(0, 255, 102)
        elif score < 50:
            t = (score - 25) / 25
            return QColor(int(255 * t), int(255 - 17 * t), int(102 - 102 * t))
        elif score < 75:
            t = (score - 50) / 25
            return QColor(255, int(238 - 102 * t), 0)
        else:
            t = (score - 75) / 25
            return QColor(255, int(136 - 85 * t), int(68 * t))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) * 0.38
        score = self._display_score
        color = self._score_color(score)

        # Background
        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        # Breathing glow
        breath = 0.3 + math.sin(self._phase) * 0.08
        glow = QRadialGradient(cx, cy, radius * 1.4)
        gc = QColor(color)
        gc.setAlphaF(breath * 0.15)
        glow.setColorAt(0, gc)
        glow.setColorAt(0.6, QColor(0, 0, 0, 0))
        glow.setColorAt(1, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(glow))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), radius * 1.4, radius * 1.4)

        # Track ring (dim)
        painter.setPen(QPen(QColor(255, 255, 255, 15), 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(QRectF(cx - radius, cy - radius, radius * 2, radius * 2), 225 * 16, -270 * 16)

        # Score arc
        arc_span = (score / 100) * 270
        pen_color = QColor(color)
        pen_color.setAlphaF(0.8 + math.sin(self._phase * 1.5) * 0.15)
        painter.setPen(QPen(pen_color, 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(QRectF(cx - radius, cy - radius, radius * 2, radius * 2), 225 * 16, int(-arc_span * 16))

        # Outer glow arc
        glow_color = QColor(color)
        glow_color.setAlphaF(0.15 + math.sin(self._phase * 1.5) * 0.08)
        painter.setPen(QPen(glow_color, 16, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(QRectF(cx - radius, cy - radius, radius * 2, radius * 2), 225 * 16, int(-arc_span * 16))

        # Tick marks
        painter.setPen(QPen(QColor(255, 255, 255, 30), 1))
        for i in range(28):
            angle_deg = 225 - (i / 27) * 270
            angle_rad = math.radians(angle_deg)
            inner = radius - 18
            outer = radius - 12
            x1 = cx + inner * math.cos(angle_rad)
            y1 = cy - inner * math.sin(angle_rad)
            x2 = cx + outer * math.cos(angle_rad)
            y2 = cy - outer * math.sin(angle_rad)
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Floating particles
        for p in self._particles:
            angle_rad = math.radians(225 - (p["angle"] / 360) * 270)
            pr = radius + p["r"] * 15
            px = cx + pr * math.cos(angle_rad)
            py = cy - pr * math.sin(angle_rad)
            pc = QColor(color)
            pc.setAlphaF(p["life"] * 0.5)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(pc))
            painter.drawEllipse(QPointF(px, py), p["size"], p["size"])

        # Score text
        painter.setPen(QColor(color))
        score_font = QFont("Consolas", max(18, int(radius * 0.35)), QFont.Weight.Bold)
        painter.setFont(score_font)
        painter.drawText(QRectF(0, cy - radius * 0.35, w, radius * 0.5),
                        Qt.AlignmentFlag.AlignCenter, str(int(score)))

        # Label
        painter.setPen(QColor(255, 255, 255, 80))
        label_font = QFont("Consolas", max(7, int(radius * 0.08)))
        label_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(label_font)
        painter.drawText(QRectF(0, cy - radius * 0.55, w, 16),
                        Qt.AlignmentFlag.AlignCenter, "PRIVACY EXPOSURE")

        # Status text
        if score < 25:
            status = "LOW EXPOSURE"
        elif score < 50:
            status = "MODERATE EXPOSURE"
        elif score < 75:
            status = "HIGH — TAKE ACTION"
        else:
            status = "CRITICAL — BROADCASTING"

        painter.setPen(QColor(color))
        status_font = QFont("Consolas", max(7, int(radius * 0.09)), QFont.Weight.Bold)
        status_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 2)
        painter.setFont(status_font)
        painter.drawText(QRectF(0, cy + radius * 0.2, w, 20),
                        Qt.AlignmentFlag.AlignCenter, status)

        painter.end()


# ---------------------------------------------------------------------------
# Sparkline Graph — Bandwidth Visualization
# ---------------------------------------------------------------------------

class SparklineGraph(QWidget):
    """Real-time sparkline with gradient fill and glow trail."""

    def __init__(self, label="BANDWIDTH", color=Colors.CYAN, max_points=80, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(70)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._label = label
        self._color = QColor(color)
        self._values = []
        self._max_points = max_points
        self._display_text = ""
        self._rolling_max = 1.0
        self._phase = 0.0

        self._timer = QTimer()
        self._timer.timeout.connect(lambda: (self._tick_phase(), self.update()))
        self._timer.start(50)

    def _tick_phase(self):
        self._phase += 0.04

    def add_value(self, value: float, display_text: str = ""):
        self._values.append(value)
        if len(self._values) > self._max_points:
            self._values = self._values[-self._max_points:]
        target_max = max(self._values) if self._values else 1
        self._rolling_max += (max(target_max, 1) - self._rolling_max) * 0.1
        if display_text:
            self._display_text = display_text

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()

        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        # Header
        painter.setPen(QColor(255, 255, 255, 80))
        font = QFont("Consolas", 7)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(font)
        painter.drawText(QRectF(8, 4, w, 14), Qt.AlignmentFlag.AlignLeft, self._label)

        # Value text
        if self._display_text:
            painter.setPen(self._color)
            font = QFont("Consolas", 10, QFont.Weight.Bold)
            painter.setFont(font)
            painter.drawText(QRectF(8, 4, w - 16, 14),
                           Qt.AlignmentFlag.AlignRight, self._display_text)

        if len(self._values) < 2:
            painter.end()
            return

        graph_top = 22
        graph_bottom = h - 4
        graph_h = graph_bottom - graph_top
        step_x = (w - 16) / (self._max_points - 1)
        margin_x = 8

        # Build path
        path = QPainterPath()
        fill_path = QPainterPath()

        for i, val in enumerate(self._values):
            x = margin_x + i * step_x
            y = graph_bottom - (val / self._rolling_max) * graph_h * 0.9
            y = max(graph_top, min(graph_bottom, y))
            if i == 0:
                path.moveTo(x, y)
                fill_path.moveTo(x, graph_bottom)
                fill_path.lineTo(x, y)
            else:
                path.lineTo(x, y)
                fill_path.lineTo(x, y)

        # Close fill path
        last_x = margin_x + (len(self._values) - 1) * step_x
        fill_path.lineTo(last_x, graph_bottom)
        fill_path.closeSubpath()

        # Gradient fill
        grad = QLinearGradient(0, graph_top, 0, graph_bottom)
        fc = QColor(self._color)
        fc.setAlphaF(0.15 + math.sin(self._phase) * 0.03)
        grad.setColorAt(0, fc)
        grad.setColorAt(1, QColor(0, 0, 0, 0))
        painter.fillPath(fill_path, QBrush(grad))

        # Glow line
        glow_color = QColor(self._color)
        glow_color.setAlphaF(0.2)
        painter.setPen(QPen(glow_color, 4))
        painter.drawPath(path)

        # Main line
        line_color = QColor(self._color)
        line_color.setAlphaF(0.8)
        painter.setPen(QPen(line_color, 1.5))
        painter.drawPath(path)

        # Endpoint dot
        if self._values:
            last_val = self._values[-1]
            last_y = graph_bottom - (last_val / self._rolling_max) * graph_h * 0.9
            last_y = max(graph_top, min(graph_bottom, last_y))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(self._color))
            painter.drawEllipse(QPointF(last_x, last_y), 3, 3)

        painter.end()


# ---------------------------------------------------------------------------
# Animated Stat Card
# ---------------------------------------------------------------------------

class AnimatedStatCard(QWidget):
    """Stat card with subtle pulse animation."""

    def __init__(self, label: str, color: str = Colors.CYAN, parent=None):
        super().__init__(parent)
        self.setFixedHeight(72)
        self.setMinimumWidth(130)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._label = label
        self._color = QColor(color)
        self._value = "0"
        self._phase = 0.0

        self._timer = QTimer()
        self._timer.timeout.connect(lambda: (self._tick(), self.update()))
        self._timer.start(60)

    def _tick(self):
        self._phase += 0.04

    def set_value(self, value: str):
        self._value = value

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()

        # Background with subtle border pulse
        border_alpha = 0.12 + math.sin(self._phase) * 0.03
        painter.fillRect(0, 0, w, h, QColor(5, 8, 22))
        painter.setPen(QPen(QColor(0, 240, 255, int(border_alpha * 255)), 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        # Bottom accent line
        accent = QColor(self._color)
        accent.setAlphaF(0.3 + math.sin(self._phase * 1.2) * 0.1)
        painter.setPen(QPen(accent, 2))
        painter.drawLine(0, h - 1, w, h - 1)

        # Label
        painter.setPen(QColor(255, 255, 255, 100))
        font = QFont("Consolas", 8)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.5)
        painter.setFont(font)
        painter.drawText(QRectF(12, 8, w - 24, 14), Qt.AlignmentFlag.AlignLeft, self._label.upper())

        # Value
        painter.setPen(self._color)
        val_font = QFont("Consolas", 22, QFont.Weight.Bold)
        painter.setFont(val_font)
        painter.drawText(QRectF(12, 24, w - 24, 36), Qt.AlignmentFlag.AlignLeft, self._value)

        painter.end()


# ---------------------------------------------------------------------------
# Threat Meter
# ---------------------------------------------------------------------------

class ThreatMeter(QWidget):
    """Horizontal threat level meter with animated fill."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(50)
        self.setMaximumHeight(60)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._level = 0.0
        self._display_level = 0.0
        self._phase = 0.0

        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_level(self, level: float):
        self._level = max(0, min(1, level))

    def _tick(self):
        self._display_level += (self._level - self._display_level) * 0.08
        self._phase += 0.06
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()

        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        # Header
        painter.setPen(QColor(255, 255, 255, 80))
        font = QFont("Consolas", 7)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(font)
        painter.drawText(QRectF(8, 4, w, 14), Qt.AlignmentFlag.AlignLeft, "THREAT LEVEL")

        # Level text
        level_pct = self._display_level * 100
        if level_pct < 25:
            label, color = "LOW", QColor(0, 255, 102)
        elif level_pct < 50:
            label, color = "MODERATE", QColor(255, 238, 0)
        elif level_pct < 75:
            label, color = "HIGH", QColor(255, 136, 0)
        else:
            label, color = "CRITICAL", QColor(255, 51, 68)

        painter.setPen(color)
        font = QFont("Consolas", 8, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(8, 4, w - 16, 14), Qt.AlignmentFlag.AlignRight, label)

        # Bar track
        bar_y = 22
        bar_h = 12
        margin = 8
        bar_w = w - margin * 2

        painter.fillRect(QRectF(margin, bar_y, bar_w, bar_h), QColor(255, 255, 255, 10))

        # Animated fill
        fill_w = self._display_level * bar_w
        if fill_w > 1:
            grad = QLinearGradient(margin, 0, margin + fill_w, 0)
            c1 = QColor(0, 255, 102)
            c2 = QColor(color)
            c2.setAlphaF(0.7 + math.sin(self._phase * 2) * 0.15)
            grad.setColorAt(0, c1)
            grad.setColorAt(1, c2)
            painter.fillRect(QRectF(margin, bar_y, fill_w, bar_h), QBrush(grad))

            # Glow at tip
            glow = QRadialGradient(margin + fill_w, bar_y + bar_h / 2, 15)
            gc = QColor(color)
            gc.setAlphaF(0.3 + math.sin(self._phase * 2) * 0.1)
            glow.setColorAt(0, gc)
            glow.setColorAt(1, QColor(0, 0, 0, 0))
            painter.fillRect(QRectF(margin + fill_w - 15, bar_y - 5, 30, bar_h + 10), QBrush(glow))

        # Segment lines
        painter.setPen(QPen(QColor(5, 5, 16), 1))
        for i in range(1, 4):
            x = margin + (i / 4) * bar_w
            painter.drawLine(QPointF(x, bar_y), QPointF(x, bar_y + bar_h))

        painter.end()


# ---------------------------------------------------------------------------
# Top Talkers — Racing Bar Chart
# ---------------------------------------------------------------------------

class TopTalkersWidget(QWidget):
    """Animated racing bar chart showing top apps by traffic."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._apps = []
        self._display_bars = {}
        self._max_bars = 8
        self._phase = 0.0

        self._bar_colors = [
            QColor(0, 240, 255), QColor(255, 0, 170), QColor(0, 255, 102),
            QColor(255, 136, 0), QColor(170, 68, 255), QColor(255, 238, 0),
            QColor(255, 51, 68), QColor(100, 200, 255),
        ]

        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def update_data(self, app_stats: dict):
        sorted_apps = sorted(
            app_stats.values(),
            key=lambda a: a.total_bytes_sent + a.total_bytes_recv,
            reverse=True
        )[:self._max_bars]
        self._apps = [
            (a.name, a.total_bytes_sent + a.total_bytes_recv, a.tracker_hits)
            for a in sorted_apps
        ]

    def _tick(self):
        self._phase += 0.06
        if self._apps:
            max_bytes = max(b for _, b, _ in self._apps) or 1
            for name, bytes_val, _ in self._apps:
                target = bytes_val / max_bytes
                current = self._display_bars.get(name, 0.0)
                self._display_bars[name] = current + (target - current) * 0.08
        self.update()

    def paintEvent(self, event):
        if not self._apps:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()
        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        painter.setPen(QColor(255, 255, 255, 80))
        font = QFont("Consolas", 7)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(font)
        painter.drawText(QRectF(8, 4, w, 14), Qt.AlignmentFlag.AlignLeft, "TOP TALKERS")

        bar_top = 22
        bar_h = 18
        gap = 3
        label_w = 90
        margin = 8
        bar_area_w = w - label_w - margin * 2 - 60

        for i, (name, total_bytes, tracker_hits) in enumerate(self._apps):
            if i >= self._max_bars:
                break
            y = bar_top + i * (bar_h + gap)
            if y + bar_h > h:
                break

            frac = self._display_bars.get(name, 0.0)
            bar_w = frac * bar_area_w
            color = self._bar_colors[i % len(self._bar_colors)]

            name_display = name[:12] if len(name) > 12 else name
            painter.setPen(QColor(255, 255, 255, 170))
            painter.setFont(QFont("Consolas", 8))
            painter.drawText(QRectF(margin, y, label_w, bar_h),
                           Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name_display)

            bar_x = margin + label_w
            bar_color = QColor(color)
            bar_color.setAlphaF(0.5 + 0.15 * math.sin(self._phase + i * 0.5))
            grad = QLinearGradient(bar_x, 0, bar_x + bar_w, 0)
            grad.setColorAt(0, bar_color)
            bright = QColor(color)
            bright.setAlphaF(0.8)
            grad.setColorAt(1, bright)
            painter.fillRect(QRectF(bar_x, y + 2, max(2, bar_w), bar_h - 4), grad)

            if tracker_hits > 0:
                painter.setPen(QColor(255, 51, 68, 200))
                painter.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
                painter.drawText(QRectF(bar_x + bar_w + 4, y, 30, bar_h),
                               Qt.AlignmentFlag.AlignVCenter, f"!{tracker_hits}")

            painter.setPen(color)
            painter.setFont(QFont("Consolas", 7))
            painter.drawText(QRectF(w - 60 - margin, y, 60, bar_h),
                           Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                           self._fmt_bytes(total_bytes))
        painter.end()

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b < 1024: return f"{b} B"
        elif b < 1048576: return f"{b/1024:.1f} KB"
        elif b < 1073741824: return f"{b/1048576:.1f} MB"
        return f"{b/1073741824:.2f} GB"


# ---------------------------------------------------------------------------
# Company Traffic Widget
# ---------------------------------------------------------------------------

class CompanyTrafficWidget(QWidget):
    """Shows traffic aggregated by parent company with visual bars."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._companies = {}
        self._phase = 0.0

        self._company_colors = {
            "Google": QColor(66, 133, 244), "Microsoft": QColor(0, 120, 212),
            "Meta": QColor(24, 119, 242), "Amazon": QColor(255, 153, 0),
            "Apple": QColor(160, 160, 160), "ByteDance": QColor(255, 0, 80),
            "Cloudflare": QColor(245, 130, 32), "Adobe": QColor(255, 0, 0),
            "X Corp": QColor(100, 100, 100), "Netflix": QColor(229, 9, 20),
            "Akamai": QColor(0, 151, 216), "Spotify": QColor(30, 215, 96),
        }

        self._timer = QTimer()
        self._timer.timeout.connect(lambda: (self._tick(), self.update()))
        self._timer.start(60)

    def _tick(self):
        self._phase += 0.05

    def update_data(self, company_data: dict):
        self._companies = company_data

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()
        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        painter.setPen(QColor(255, 255, 255, 80))
        font = QFont("Consolas", 7)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(font)
        painter.drawText(QRectF(8, 4, w, 14), Qt.AlignmentFlag.AlignLeft, "DATA BY COMPANY")

        if not self._companies:
            painter.setPen(QColor(255, 255, 255, 40))
            painter.setFont(QFont("Consolas", 9))
            painter.drawText(QRectF(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "Collecting...")
            painter.end()
            return

        sorted_co = sorted(self._companies.items(), key=lambda x: x[1].get("bytes", 0), reverse=True)[:6]
        total = sum(d.get("bytes", 0) for _, d in sorted_co) or 1

        bar_top = 22
        bar_h = 14
        gap = 3
        margin = 8

        for i, (name, data) in enumerate(sorted_co):
            y = bar_top + i * (bar_h + gap)
            if y + bar_h > h:
                break
            frac = data.get("bytes", 0) / total
            bar_w = max(2, frac * (w - margin * 2 - 100))
            color = self._company_colors.get(name, QColor(0, 240, 255))

            painter.setPen(QColor(255, 255, 255, 170))
            painter.setFont(QFont("Consolas", 8))
            painter.drawText(QRectF(margin, y, 80, bar_h), Qt.AlignmentFlag.AlignVCenter, name[:10])

            bx = margin + 82
            bc = QColor(color)
            bc.setAlphaF(0.5 + 0.1 * math.sin(self._phase + i))
            painter.fillRect(QRectF(bx, y + 1, bar_w, bar_h - 2), bc)

            painter.setPen(color)
            painter.setFont(QFont("Consolas", 7))
            painter.drawText(QRectF(w - 50 - margin, y, 50, bar_h),
                           Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                           f"{frac*100:.0f}%")
        painter.end()


# ---------------------------------------------------------------------------
# Packet Pulse — Activity Indicator
# ---------------------------------------------------------------------------

class PacketPulse(QWidget):
    """Tiny animated circle that pulses with each packet."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self._intensity = 0.0
        self._color = QColor(0, 240, 255)

        self._timer = QTimer()
        self._timer.timeout.connect(self._decay)
        self._timer.start(33)

    def pulse(self, is_tracker=False):
        self._intensity = 1.0
        self._color = QColor(255, 51, 68) if is_tracker else QColor(0, 240, 255)

    def _decay(self):
        if self._intensity > 0:
            self._intensity *= 0.88
            if self._intensity < 0.02:
                self._intensity = 0
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = QColor(self._color)
        c.setAlphaF(self._intensity * 0.8)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(c))
        r = 3 + self._intensity * 4
        painter.drawEllipse(QPointF(8, 8), r, r)
        painter.end()


# ---------------------------------------------------------------------------
# Protocol Donut Chart
# ---------------------------------------------------------------------------

class ProtocolDonut(QWidget):
    """Mini donut chart showing protocol distribution."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(120, 120)
        self.setMaximumSize(180, 180)
        self._data = {}
        self._phase = 0.0

        self._proto_colors = {
            "HTTPS": QColor(0, 255, 102), "HTTP": QColor(255, 238, 0),
            "TCP": QColor(0, 240, 255), "UDP": QColor(170, 68, 255),
            "DNS": QColor(255, 0, 170), "QUIC": QColor(255, 136, 0),
        }

        self._timer = QTimer()
        self._timer.timeout.connect(lambda: (self._tick(), self.update()))
        self._timer.start(50)

    def _tick(self):
        self._phase += 0.04

    def update_data(self, protocols: dict):
        self._data = dict(protocols)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) * 0.4
        inner_r = radius * 0.6

        painter.fillRect(0, 0, w, h, QColor(5, 5, 16))

        if not self._data:
            painter.end()
            return

        total = sum(self._data.values()) or 1
        start_angle = 90 * 16

        for proto, count in sorted(self._data.items(), key=lambda x: x[1], reverse=True):
            span = (count / total) * 360 * 16
            color = self._proto_colors.get(proto, QColor(100, 100, 100))
            arc_color = QColor(color)
            arc_color.setAlphaF(0.6 + 0.1 * math.sin(self._phase))
            painter.setPen(Qt.PenStyle.NoPen)

            path = QPainterPath()
            rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
            inner_rect = QRectF(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2)
            path.arcMoveTo(rect, start_angle / 16)
            path.arcTo(rect, start_angle / 16, span / 16)
            path.arcTo(inner_rect, (start_angle + span) / 16, -span / 16)
            path.closeSubpath()

            painter.setBrush(QBrush(arc_color))
            painter.drawPath(path)
            start_angle += int(span)

        painter.setPen(QColor(255, 255, 255, 130))
        painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(0, cy - 8, w, 16), Qt.AlignmentFlag.AlignCenter, f"{len(self._data)}")
        painter.setPen(QColor(255, 255, 255, 60))
        painter.setFont(QFont("Consolas", 6))
        painter.drawText(QRectF(0, cy + 4, w, 12), Qt.AlignmentFlag.AlignCenter, "PROTOS")
        painter.end()
