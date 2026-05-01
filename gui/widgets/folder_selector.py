"""
MalScope Folder Selector Widget
================================
Styled card for selecting the target scan directory.
"""

import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from gui.theme import COLORS


class FolderSelectorCard(QWidget):
    """Card widget for selecting a folder to scan."""

    folder_selected = pyqtSignal(str, int)  # (path, file_count)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.folder_path = ""
        self.file_count = 0
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet(f"""
            FolderSelectorCard {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        # ── Section Label ──
        header = QLabel("📁  TARGET DIRECTORY")
        header.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            border: none;
            background: transparent;
        """)
        layout.addWidget(header)

        # ── Separator ──
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {COLORS['border']};")
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # ── Path Display ──
        self.path_label = QLabel("No folder selected")
        self.path_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 11px;
            padding: 6px 8px;
            background-color: {COLORS['bg_input']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
        """)
        self.path_label.setWordWrap(True)
        self.path_label.setMinimumHeight(36)
        layout.addWidget(self.path_label)

        # ── File Count Badge ──
        self.file_count_label = QLabel("")
        self.file_count_label.setStyleSheet(f"""
            color: {COLORS['text_dim']};
            font-size: 10px;
            border: none;
            background: transparent;
        """)
        self.file_count_label.setAlignment(Qt.AlignRight)
        self.file_count_label.hide()
        layout.addWidget(self.file_count_label)

        # ── Browse Button ──
        self.btn_browse = QPushButton("🔍  Browse Folder")
        self.btn_browse.setCursor(Qt.PointingHandCursor)
        self.btn_browse.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent_blue']};
                color: {COLORS['text_bright']};
                border: none;
                border-radius: 6px;
                padding: 9px 16px;
                font-size: 12px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: #4f8ff7;
            }}
            QPushButton:pressed {{
                background-color: #2563eb;
            }}
        """)
        self.btn_browse.clicked.connect(self._open_folder_dialog)
        layout.addWidget(self.btn_browse)

    def _open_folder_dialog(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Target Folder")
        if folder:
            self.folder_path = folder
            # Count files in directory
            try:
                files = [f for f in os.listdir(folder)
                         if os.path.isfile(os.path.join(folder, f))]
                self.file_count = len(files)
            except OSError:
                self.file_count = 0

            # Update display
            display_path = folder
            if len(display_path) > 40:
                display_path = "..." + display_path[-37:]
            self.path_label.setText(display_path)
            self.path_label.setToolTip(folder)
            self.path_label.setStyleSheet(f"""
                color: {COLORS['text_primary']};
                font-size: 11px;
                padding: 6px 8px;
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['accent_blue']}60;
                border-radius: 4px;
            """)

            self.file_count_label.setText(f"📄 {self.file_count} files found")
            self.file_count_label.setStyleSheet(f"""
                color: {COLORS['accent_cyan']};
                font-size: 10px;
                font-weight: 600;
                border: none;
                background: transparent;
            """)
            self.file_count_label.show()

            self.folder_selected.emit(folder, self.file_count)

    def get_folder_path(self) -> str:
        """Return the currently selected folder path."""
        return self.folder_path

    def reset(self):
        """Reset the folder selector to its initial state."""
        self.folder_path = ""
        self.file_count = 0
        self.path_label.setText("No folder selected")
        self.path_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 11px;
            padding: 6px 8px;
            background-color: {COLORS['bg_input']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
        """)
        self.file_count_label.hide()
