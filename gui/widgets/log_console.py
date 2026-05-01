"""
MalScope Log Console Widget
==============================
SIEM-style scrolling log feed with color-coded levels and filtering.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QComboBox, QPushButton, QFrame
)
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtGui import QFont, QTextCursor, QColor
from gui.theme import COLORS, FONTS

LOG_COLORS = {
    "INFO":     COLORS['info'],
    "WARN":     COLORS['warning'],
    "WARNING":  COLORS['warning'],
    "ERROR":    COLORS['error'],
    "CRITICAL": COLORS['severity_critical'],
    "SUCCESS":  COLORS['success'],
    "DEBUG":    COLORS['text_dim'],
}


class LogConsole(QWidget):
    """SIEM-style log console with colored log levels."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._auto_scroll = True
        self._log_count = 0
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header bar
        header_bar = QHBoxLayout()
        title = QLabel("📋  LIVE LOG CONSOLE")
        title.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:1px;border:none;background:transparent;")
        header_bar.addWidget(title)
        header_bar.addStretch()

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "INFO", "WARN", "ERROR", "CRITICAL", "SUCCESS"])
        self.filter_combo.setFixedWidth(90)
        self.filter_combo.setFixedHeight(22)
        self.filter_combo.setStyleSheet(f"font-size:10px;padding:2px 4px;")
        header_bar.addWidget(self.filter_combo)

        self.btn_autoscroll = QPushButton("⬇ Auto")
        self.btn_autoscroll.setFixedSize(55, 22)
        self.btn_autoscroll.setCheckable(True)
        self.btn_autoscroll.setChecked(True)
        self.btn_autoscroll.setStyleSheet(f"QPushButton{{font-size:9px;padding:2px 4px;border-radius:3px;background:{COLORS['accent_blue']};color:#fff;border:none;}}QPushButton:!checked{{background:{COLORS['bg_elevated']};color:{COLORS['text_dim']};}}")
        self.btn_autoscroll.toggled.connect(lambda c: setattr(self, '_auto_scroll', c))
        header_bar.addWidget(self.btn_autoscroll)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setFixedSize(45, 22)
        self.btn_clear.setStyleSheet(f"font-size:9px;padding:2px 4px;border-radius:3px;")
        self.btn_clear.clicked.connect(self.clear)
        header_bar.addWidget(self.btn_clear)

        layout.addLayout(header_bar)

        # Log text area
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Consolas", 10))
        self.text_edit.setStyleSheet(f"QTextEdit{{background-color:{COLORS['bg_input']};color:{COLORS['text_primary']};border:1px solid {COLORS['border']};border-radius:6px;padding:6px;}}")
        layout.addWidget(self.text_edit)

    def append_log(self, level: str, message: str):
        """Append a log entry with timestamp and color-coded level."""
        level = level.upper()
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss.zzz")
        color = LOG_COLORS.get(level, COLORS['text_secondary'])
        time_color = COLORS['text_dim']

        html = (
            f'<span style="color:{time_color};font-size:10px;">[{timestamp}]</span> '
            f'<span style="color:{color};font-weight:bold;font-size:10px;">[{level}]</span> '
            f'<span style="color:{COLORS["text_primary"]};font-size:10px;">{message}</span>'
        )

        # Check filter
        current_filter = self.filter_combo.currentText()
        if current_filter != "All" and level != current_filter:
            return

        self.text_edit.append(html)
        self._log_count += 1

        if self._auto_scroll:
            cursor = self.text_edit.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.text_edit.setTextCursor(cursor)

    def clear(self):
        self.text_edit.clear()
        self._log_count = 0
