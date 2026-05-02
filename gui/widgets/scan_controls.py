"""
MalScope Scan Controls Widget
===============================
Start/Stop/Clear buttons and scan mode selector.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QComboBox, QLabel, QFrame, QProgressBar
)
from PyQt5.QtCore import Qt, pyqtSignal
from gui.theme import COLORS


class ScanControlPanel(QWidget):
    start_clicked = pyqtSignal()
    stop_clicked = pyqtSignal()
    clear_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scanning = False
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet(f"ScanControlPanel{{background-color:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:8px;}}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        header = QLabel("SCAN CONTROLS")
        from gui.theme import get_icon
        # Add an icon before the text
        header_icon = QLabel()
        header_icon.setPixmap(get_icon("fa5s.sliders-h", color=COLORS['accent_cyan']).pixmap(10, 10))
        
        h_layout = QHBoxLayout()
        h_layout.setContentsMargins(0,0,0,0)
        h_layout.addWidget(header_icon)
        h_layout.addWidget(header)
        h_layout.addStretch()
        
        header.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:1px;border:none;background:transparent;")
        layout.addLayout(h_layout)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet(f"color:{COLORS['border']};"); sep.setFixedHeight(1)
        layout.addWidget(sep)

        mode_layout = QHBoxLayout()
        mode_label = QLabel("Mode:")
        mode_label.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;border:none;background:transparent;")
        mode_layout.addWidget(mode_label)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Full Analysis", "Quick Scan", "Static Only"])
        mode_layout.addWidget(self.mode_combo, 1)
        layout.addLayout(mode_layout)

        self.btn_start = QPushButton("  Start Scan")
        from gui.theme import get_icon
        self.btn_start.setIcon(get_icon("fa5s.play", color="#ffffff"))
        self.btn_start.setCursor(Qt.PointingHandCursor)
        self.btn_start.setFixedHeight(40)
        self.btn_start.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: #ffffff; 
                border: none; 
                border-radius: 6px;
                padding: 0px 16px; 
                font-size: 15px; 
                font-weight: bold;
                outline: none;
            }}
            QPushButton:hover {{
                background-color: #16a34a;
            }}
            QPushButton:pressed {{
                background-color: #15803d;
                border: none;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_elevated']};
                color: {COLORS['text_dim']};
            }}
        """)
        self.btn_start.clicked.connect(self._on_start)
        layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("  Stop Scan")
        self.btn_stop.setIcon(get_icon("fa5s.stop", color="#ffffff"))
        self.btn_stop.setCursor(Qt.PointingHandCursor)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setFixedHeight(40)
        self.btn_stop.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['error']};
                color: #ffffff; 
                border: none; 
                border-radius: 6px;
                padding: 0px 16px; 
                font-size: 15px; 
                font-weight: bold;
                outline: none;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
            QPushButton:pressed {{
                background-color: #b91c1c;
                border: none;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_elevated']};
                color: {COLORS['text_dim']};
            }}
        """)
        self.btn_stop.clicked.connect(self._on_stop)
        layout.addWidget(self.btn_stop)

        self.progress_label = QLabel("Progress")
        self.progress_label.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;border:none;background:transparent;")
        self.progress_label.hide()
        layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100); self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(6); self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.btn_clear = QPushButton("  Clear Results")
        self.btn_clear.setIcon(get_icon("fa5s.trash-alt", color=COLORS['text_secondary']))
        self.btn_clear.setCursor(Qt.PointingHandCursor)
        self.btn_clear.setStyleSheet(f"QPushButton{{background:transparent;color:{COLORS['text_secondary']};border:1px solid {COLORS['border']};border-radius:6px;padding:7px 16px;font-size:11px;font-weight:600;}}QPushButton:hover{{background:{COLORS['bg_hover']};color:{COLORS['text_primary']};}}")
        self.btn_clear.clicked.connect(self.clear_clicked.emit)
        layout.addWidget(self.btn_clear)

    def _on_start(self):
        self.start_clicked.emit()

    def _on_stop(self):
        self.stop_clicked.emit()

    def set_state(self, state: str):
        self._state = state
        if state == "scanning":
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.mode_combo.setEnabled(False)
            self.progress_label.show()
            self.progress_bar.show()
            self.progress_bar.setValue(0)
            self.progress_label.setText("Scanning...")
            self.progress_label.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:600;border:none;background:transparent;")
            
        elif state == "completed":
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.mode_combo.setEnabled(True)
            self.progress_bar.setValue(100)
            self.progress_label.setText("✓ Scan Complete")
            self.progress_label.setStyleSheet(f"color:{COLORS['success']};font-size:10px;font-weight:700;border:none;background:transparent;")
            
        elif state == "idle":
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.mode_combo.setEnabled(True)
            self.progress_label.setText("Idle")
            self.progress_label.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;border:none;background:transparent;")
            self.progress_label.hide()
            self.progress_bar.hide()

    def update_progress(self, current, total):
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)
            self.progress_label.setText(f"Progress: {current}/{total} files ({pct}%)")
            self.progress_label.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:600;border:none;background:transparent;")

    def scan_finished(self):
        self.set_state("completed")

    def get_scan_mode(self):
        return self.mode_combo.currentText()
