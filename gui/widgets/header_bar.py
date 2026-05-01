"""
MalScope Header Bar Widget
============================
Top header with branding, pipeline stage indicators, threat count badges, and clock.
"""

from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel, QFrame
from PyQt5.QtCore import Qt, QTimer, QDateTime
from PyQt5.QtGui import QFont

from gui.theme import COLORS, FONTS


class PipelineStageIndicator(QWidget):
    """A single pipeline stage indicator (icon + label)."""

    STAGES = [
        ("📁", "Input"),
        ("🔬", "Static"),
        ("⚡", "Dynamic"),
        ("📊", "Scoring"),
        ("🤖", "AI"),
        ("📄", "Report"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stage_labels = []
        self.current_stage = -1
        self._build_ui()

    def _build_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        for i, (icon, name) in enumerate(self.STAGES):
            # Stage container
            stage_frame = QFrame()
            stage_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 4px;
                    padding: 2px 6px;
                }}
            """)
            stage_layout = QHBoxLayout(stage_frame)
            stage_layout.setContentsMargins(4, 2, 4, 2)
            stage_layout.setSpacing(3)

            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 12px; border: none; background: transparent;")
            stage_layout.addWidget(icon_lbl)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(f"""
                font-size: 10px;
                font-weight: 600;
                color: {COLORS['text_dim']};
                border: none;
                background: transparent;
            """)
            stage_layout.addWidget(name_lbl)

            self.stage_labels.append((stage_frame, name_lbl))
            layout.addWidget(stage_frame)

            # Add connector arrow between stages (except after last)
            if i < len(self.STAGES) - 1:
                arrow = QLabel("›")
                arrow.setStyleSheet(f"""
                    color: {COLORS['border_light']};
                    font-size: 16px;
                    font-weight: bold;
                    border: none;
                    background: transparent;
                """)
                arrow.setAlignment(Qt.AlignCenter)
                layout.addWidget(arrow)

    def set_stage(self, stage_name: str, state: str = "active"):
        """
        Update a pipeline stage's visual state.
        state: 'idle', 'active', 'completed', 'error'
        """
        stage_map = {name.lower(): i for i, (_, name) in enumerate(self.STAGES)}
        idx = stage_map.get(stage_name.lower(), -1)
        if idx == -1:
            return

        frame, label = self.stage_labels[idx]

        if state == "active":
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['accent_blue']}22;
                    border: 1px solid {COLORS['accent_blue']};
                    border-radius: 4px;
                    padding: 2px 6px;
                }}
            """)
            label.setStyleSheet(f"""
                font-size: 10px; font-weight: 700;
                color: {COLORS['accent_cyan']};
                border: none; background: transparent;
            """)
        elif state == "completed":
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['success']}18;
                    border: 1px solid {COLORS['success']}80;
                    border-radius: 4px;
                    padding: 2px 6px;
                }}
            """)
            label.setStyleSheet(f"""
                font-size: 10px; font-weight: 700;
                color: {COLORS['success']};
                border: none; background: transparent;
            """)
        elif state == "error":
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['error']}18;
                    border: 1px solid {COLORS['error']}80;
                    border-radius: 4px;
                    padding: 2px 6px;
                }}
            """)
            label.setStyleSheet(f"""
                font-size: 10px; font-weight: 700;
                color: {COLORS['error']};
                border: none; background: transparent;
            """)
        else:  # idle
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 4px;
                    padding: 2px 6px;
                }}
            """)
            label.setStyleSheet(f"""
                font-size: 10px; font-weight: 600;
                color: {COLORS['text_dim']};
                border: none; background: transparent;
            """)

    def reset_all(self):
        """Reset all stages to idle state."""
        for _, name in self.STAGES:
            self.set_stage(name, "idle")


class ThreatBadge(QLabel):
    """A colored badge showing a threat count."""

    def __init__(self, label: str, color: str, parent=None):
        super().__init__(parent)
        self.color = color
        self.count = 0
        self.label_text = label
        self._update_display()
        self.setStyleSheet(f"""
            background-color: {color}18;
            color: {color};
            border: 1px solid {color}60;
            border-radius: 10px;
            padding: 2px 10px;
            font-size: 11px;
            font-weight: 700;
        """)

    def set_count(self, count: int):
        self.count = count
        self._update_display()

    def _update_display(self):
        self.setText(f"{self.label_text}: {self.count}")


class HeaderBar(QWidget):
    """Top header bar for the MalScope dashboard."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setStyleSheet(f"""
            HeaderBar {{
                background-color: {COLORS['bg_secondary']};
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        self._build_ui()
        self._start_clock()

    def _build_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.setSpacing(12)

        # ── App Branding ──
        brand_container = QWidget()
        brand_layout = QHBoxLayout(brand_container)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(8)

        shield_icon = QLabel("🛡️")
        shield_icon.setStyleSheet("font-size: 22px; border: none; background: transparent;")
        brand_layout.addWidget(shield_icon)

        title = QLabel("MalScope")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet(f"""
            color: {COLORS['text_bright']};
            border: none;
            background: transparent;
        """)
        brand_layout.addWidget(title)

        subtitle = QLabel("Malware Analysis Dashboard")
        subtitle.setStyleSheet(f"""
            color: {COLORS['text_dim']};
            font-size: 10px;
            border: none;
            background: transparent;
            padding-top: 4px;
        """)
        brand_layout.addWidget(subtitle)

        layout.addWidget(brand_container)

        # ── Spacer ──
        layout.addStretch()

        # ── Pipeline Status ──
        self.pipeline_indicator = PipelineStageIndicator()
        layout.addWidget(self.pipeline_indicator)

        layout.addStretch()

        # ── Threat Badges ──
        self.badge_malicious = ThreatBadge("Malicious", COLORS["severity_critical"])
        self.badge_suspicious = ThreatBadge("Suspicious", COLORS["severity_high"])
        self.badge_clean = ThreatBadge("Clean", COLORS["severity_low"])
        layout.addWidget(self.badge_malicious)
        layout.addWidget(self.badge_suspicious)
        layout.addWidget(self.badge_clean)

        # ── Separator ──
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color: {COLORS['border']}; background: transparent;")
        sep.setFixedWidth(1)
        layout.addWidget(sep)

        # ── Clock ──
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-family: {FONTS['family_mono']};
            font-size: 11px;
            font-weight: 600;
            border: none;
            background: transparent;
        """)
        layout.addWidget(self.clock_label)

    def _start_clock(self):
        self._update_clock()
        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start(1000)

    def _update_clock(self):
        now = QDateTime.currentDateTime()
        self.clock_label.setText(now.toString("yyyy-MM-dd  hh:mm:ss"))

    def update_threat_counts(self, malicious: int, suspicious: int, clean: int):
        """Update the threat count badges."""
        self.badge_malicious.set_count(malicious)
        self.badge_suspicious.set_count(suspicious)
        self.badge_clean.set_count(clean)
