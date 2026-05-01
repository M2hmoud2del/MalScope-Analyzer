"""
MalScope AI Insights Widget
============================
Styled read-only text panel for AI-generated explanations, threat badges, and recommendations.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTextEdit, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from gui.theme import COLORS, severity_color


class AIInsightsTab(QScrollArea):
    """Tab showing AI-generated insights and recommendations."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setStyleSheet(f"QScrollArea{{border:none;background:{COLORS['bg_card']};}}")
        
        self.content = QWidget()
        self.content.setStyleSheet(f"background:{COLORS['bg_card']};")
        self.layout = QVBoxLayout(self.content)
        self.layout.setContentsMargins(12, 12, 12, 12)
        self.layout.setSpacing(10)
        
        self._show_empty()
        self.setWidget(self.content)

    def _show_empty(self):
        lbl = QLabel("Select a file to view AI Insights")
        lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:11px;font-style:italic;border:none;background:transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(lbl)
        self.layout.addStretch()

    def _clear(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def load_data(self, ai_data: dict, verdict: str = ""):
        self._clear()
        if not ai_data:
            self._show_empty()
            return

        # Threat Classification Badge
        classification = ai_data.get("classification", verdict.capitalize() if verdict else "Unknown")
        color = severity_color(classification)
        
        badge_layout = QVBoxLayout()
        badge_layout.setSpacing(2)
        
        header_lbl = QLabel("🤖 AI THREAT CLASSIFICATION")
        header_lbl.setStyleSheet(f"color:{COLORS['accent_purple']};font-size:10px;font-weight:700;letter-spacing:0.5px;padding:4px 0 2px 0;")
        badge_layout.addWidget(header_lbl)
        
        badge = QLabel(classification.upper())
        badge.setStyleSheet(f"color:{color};font-size:12px;font-weight:bold;padding:6px 12px;background:{color}20;border:1px solid {color}50;border-radius:4px;")
        badge.setAlignment(Qt.AlignCenter)
        badge_layout.addWidget(badge)
        
        self.layout.addLayout(badge_layout)
        
        # Confidence Level
        confidence = ai_data.get("confidence")
        if confidence:
            conf_lbl = QLabel(f"Confidence: {confidence}")
            conf_lbl.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;")
            self.layout.addWidget(conf_lbl)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{COLORS['border']};")
        self.layout.addWidget(sep)

        # AI Explanation
        explanation = ai_data.get("explanation", "")
        if explanation:
            exp_header = QLabel("🧠 BEHAVIORAL EXPLANATION")
            exp_header.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:0.5px;padding:4px 0 2px 0;")
            self.layout.addWidget(exp_header)
            
            exp_text = QTextEdit()
            exp_text.setReadOnly(True)
            exp_text.setPlainText(explanation)
            exp_text.setStyleSheet(f"QTextEdit{{background:{COLORS['bg_input']};color:{COLORS['text_primary']};border:1px solid {COLORS['border']};border-radius:4px;padding:8px;font-size:12px;}}")
            exp_text.setMinimumHeight(100)
            self.layout.addWidget(exp_text)

        # Recommendations
        recommendations = ai_data.get("recommendations", [])
        if recommendations:
            rec_header = QLabel("🛡️ SECURITY RECOMMENDATIONS")
            rec_header.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:0.5px;padding:4px 0 2px 0;")
            self.layout.addWidget(rec_header)
            
            for rec in recommendations:
                rec_lbl = QLabel(f"• {rec}")
                rec_lbl.setWordWrap(True)
                rec_lbl.setStyleSheet(f"color:{COLORS['text_primary']};font-size:11px;padding-left:8px;background:transparent;")
                self.layout.addWidget(rec_lbl)

        self.layout.addStretch()
