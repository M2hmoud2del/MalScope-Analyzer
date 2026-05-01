"""
MalScope Stats Panel Widget
=============================
Live statistics cards showing scan results summary.
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout
from PyQt5.QtCore import Qt
from gui.theme import COLORS


class StatCard(QFrame):
    """A single stat card with icon, label, and value."""

    def __init__(self, icon, label, color, parent=None):
        super().__init__(parent)
        self.color = color
        self.setStyleSheet(f"StatCard{{background-color:{COLORS['bg_card']};border:1px solid {color}30;border-radius:8px;border-left:3px solid {color};}}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)

        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size:18px;border:none;background:transparent;")
        top.addWidget(icon_lbl)
        top.addStretch()
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet(f"color:{color};font-size:20px;font-weight:800;border:none;background:transparent;")
        self.value_label.setAlignment(Qt.AlignRight)
        top.addWidget(self.value_label)
        layout.addLayout(top)

        name_lbl = QLabel(label)
        name_lbl.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:13px;font-weight:600;letter-spacing:0.5px;border:none;background:transparent;")
        layout.addWidget(name_lbl)

    def set_value(self, value):
        self.value_label.setText(str(value))


class StatsPanel(QWidget):
    """Panel showing scan statistics in card format."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet(f"StatsPanel{{background-color:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:8px;}}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        header = QLabel("📈  STATISTICS")
        header.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:1px;border:none;background:transparent;")
        layout.addWidget(header)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet(f"color:{COLORS['border']};"); sep.setFixedHeight(1)
        layout.addWidget(sep)

        grid = QGridLayout()
        grid.setSpacing(6)

        self.card_total = StatCard("📄", "Total Files", COLORS['accent_blue'])
        self.card_malicious = StatCard("🔴", "Malicious", COLORS['severity_critical'])
        self.card_suspicious = StatCard("🟡", "Suspicious", COLORS['severity_high'])
        self.card_clean = StatCard("🟢", "Clean", COLORS['severity_low'])

        grid.addWidget(self.card_total, 0, 0)
        grid.addWidget(self.card_malicious, 0, 1)
        grid.addWidget(self.card_suspicious, 1, 0)
        grid.addWidget(self.card_clean, 1, 1)
        layout.addLayout(grid)

        # Average risk score
        self.avg_score_label = QLabel("Avg Risk: —")
        self.avg_score_label.setAlignment(Qt.AlignCenter)
        self.avg_score_label.setStyleSheet(f"color:{COLORS['text_dim']};font-size:11px;font-weight:600;padding:4px;border:none;background:transparent;")
        layout.addWidget(self.avg_score_label)

    def update_stats(self, total=0, malicious=0, suspicious=0, clean=0, avg_score=None):
        self.card_total.set_value(total)
        self.card_malicious.set_value(malicious)
        self.card_suspicious.set_value(suspicious)
        self.card_clean.set_value(clean)
        if avg_score is not None:
            from gui.theme import score_color
            color = score_color(avg_score)
            self.avg_score_label.setText(f"Avg Risk Score: {avg_score:.1f}/10")
            self.avg_score_label.setStyleSheet(f"color:{color};font-size:11px;font-weight:700;padding:4px;border:none;background:transparent;")
        else:
            self.avg_score_label.setText("Avg Risk: —")

    def update_progress(self, current: int, total: int):
        self._counts["total"] = total
        self.update_stats(**self._counts)

    def increment(self, category: str):
        if category in self._counts:
            self._counts[category] += 1
            self.update_stats(**self._counts)

    def reset(self):
        self._counts = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}
        self.update_stats()
