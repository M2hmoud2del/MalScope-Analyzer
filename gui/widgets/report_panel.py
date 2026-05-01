"""
MalScope Report Panel Widget
=============================
Widget for generating PDF reports with progress tracking and scope selection.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QProgressBar, 
    QLabel, QComboBox, QGroupBox
)
from PyQt5.QtCore import Qt
from gui.theme import COLORS


class ReportPanel(QGroupBox):
    """Panel for configuring and generating PDF reports."""

    def __init__(self, parent=None):
        super().__init__("📄 REPORT GENERATION", parent)
        self.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 18px;
                font-size: 11px;
                font-weight: 700;
                color: {COLORS['accent_cyan']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 2px 10px;
            }}
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Scope selector
        scope_layout = QHBoxLayout()
        scope_lbl = QLabel("Report Scope:")
        scope_lbl.setStyleSheet(f"color:{COLORS['text_primary']};font-size:11px;")
        
        self.combo_scope = QComboBox()
        self.combo_scope.addItems(["Current File", "All Scanned Files"])
        
        scope_layout.addWidget(scope_lbl)
        scope_layout.addWidget(self.combo_scope, 1)
        layout.addLayout(scope_layout)

        # Generate Button
        self.btn_generate = QPushButton("Generate PDF Report")
        self.btn_generate.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent_blue']};
                color: {COLORS['text_bright']};
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_cyan']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_elevated']};
                color: {COLORS['text_dim']};
            }}
        """)
        self.btn_generate.clicked.connect(self._on_generate_clicked)
        layout.addWidget(self.btn_generate)

        # Progress and Status
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        layout.addWidget(self.progress)

        status_layout = QHBoxLayout()
        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;")
        
        self.btn_open = QPushButton("Open Report")
        self.btn_open.setVisible(False)
        self.btn_open.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {COLORS['accent_blue']};
                border: 1px solid {COLORS['accent_blue']};
                padding: 2px 8px;
                font-size: 10px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background: {COLORS['accent_blue']}20;
            }}
        """)
        self.btn_open.clicked.connect(self._on_open_clicked)

        status_layout.addWidget(self.lbl_status)
        status_layout.addStretch()
        status_layout.addWidget(self.btn_open)
        layout.addLayout(status_layout)

        self._report_path = ""

    def _on_generate_clicked(self):
        # Notify the parent/orchestrator via signals (will be wired in main_window)
        # For now, just simulate UI state change
        self.btn_generate.setEnabled(False)
        self.lbl_status.setText("Generating...")
        self.lbl_status.setStyleSheet(f"color:{COLORS['warning']};font-size:10px;")
        self.btn_open.setVisible(False)
        self.progress.setValue(10) # Indeterminate or starting state
        
        # We don't emit the signal directly here because we'll connect it from main_window

    def update_progress(self, value: int):
        self.progress.setValue(value)

    def report_completed(self, path: str):
        self._report_path = path
        self.btn_generate.setEnabled(True)
        self.progress.setValue(100)
        self.lbl_status.setText("✓ Report Ready")
        self.lbl_status.setStyleSheet(f"color:{COLORS['success']};font-size:10px;font-weight:bold;")
        self.btn_open.setVisible(True)

    def report_error(self, error_msg: str):
        self.btn_generate.setEnabled(True)
        self.progress.setValue(0)
        self.lbl_status.setText(f"Error: {error_msg}")
        self.lbl_status.setStyleSheet(f"color:{COLORS['severity_critical']};font-size:10px;")
        self.btn_open.setVisible(False)

    def _on_open_clicked(self):
        if self._report_path:
            import os
            # Cross-platform file opening
            if os.name == 'nt':
                os.startfile(self._report_path)
            elif os.name == 'posix':
                import subprocess
                subprocess.call(('open', self._report_path))

    def reset(self):
        self.progress.setValue(0)
        self.lbl_status.setText("Ready")
        self.lbl_status.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;")
        self.btn_open.setVisible(False)
        self.btn_generate.setEnabled(True)
        self._report_path = ""
