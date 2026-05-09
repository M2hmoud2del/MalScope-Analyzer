"""
MalScope File Details Widget
==============================
Tabbed detail panel (Static, Dynamic, AI) for inspecting selected file results.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QFrame, QPushButton, QApplication,
    QHeaderView, QAbstractItemView, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor
from gui.theme import COLORS, severity_color, score_color
from .ai_insights import AIInsightsTab


class _SectionHeader(QLabel):
    """Reusable section header inside detail tabs."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:0.5px;padding:4px 0 2px 0;border:none;background:transparent;")


class _InfoRow(QFrame):
    """Key-value row for displaying a single data point."""
    def __init__(self, key, value, value_color=None, copyable=False, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"QFrame{{background:transparent;border:none;}}")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 1, 0, 1)
        layout.setSpacing(6)
        k = QLabel(key + ":")
        k.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;font-weight:600;border:none;background:transparent;")
        k.setFixedWidth(100)
        layout.addWidget(k)
        vc = value_color or COLORS['text_primary']
        v = QLabel(str(value))
        v.setStyleSheet(f"color:{vc};font-size:11px;border:none;background:transparent;")
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(v, 1)
        if copyable:
            btn = QPushButton("📋")
            btn.setFixedSize(22, 22)
            btn.setStyleSheet(f"QPushButton{{border:none;background:transparent;font-size:12px;}}QPushButton:hover{{background:{COLORS['bg_hover']};border-radius:3px;}}")
            btn.setToolTip("Copy to clipboard")
            btn.clicked.connect(lambda: QApplication.clipboard().setText(str(value)))
            layout.addWidget(btn)


class StaticAnalysisTab(QScrollArea):
    """Tab showing static analysis results."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setStyleSheet(f"QScrollArea{{border:none;background:{COLORS['bg_card']};}}")
        self.content = QWidget()
        self.content.setStyleSheet(f"background:{COLORS['bg_card']};")
        self.layout = QVBoxLayout(self.content)
        self.layout.setContentsMargins(12, 10, 12, 10)
        self.layout.setSpacing(4)
        self._show_empty()
        self.setWidget(self.content)

    def _show_empty(self):
        lbl = QLabel("Select a file to view static analysis results")
        lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:11px;font-style:italic;border:none;background:transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(lbl)
        self.layout.addStretch()

    def _clear(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def load_data(self, static_data: dict, sha256: str = ""):
        self._clear()
        if not static_data:
            self._show_empty(); return

        # Hashes
        self.layout.addWidget(_SectionHeader("🔒  FILE HASHES"))
        
        hashes_dict = static_data.get("hashes", {})
        
        md5_val = hashes_dict.get("md5") or static_data.get("md5", "")
        sha1_val = hashes_dict.get("sha1", "")
        sha256_val = hashes_dict.get("sha256") or sha256 or static_data.get("hash", "")
        sha512_val = hashes_dict.get("sha512", "")
        imphash_val = hashes_dict.get("imphash", "")

        self.layout.addWidget(_InfoRow("MD5", md5_val if md5_val else "N/A", copyable=True))
        self.layout.addWidget(_InfoRow("SHA-1", sha1_val if sha1_val else "N/A", copyable=True))
        self.layout.addWidget(_InfoRow("SHA-256", sha256_val if sha256_val else "N/A", copyable=True))
        self.layout.addWidget(_InfoRow("SHA-512", sha512_val if sha512_val else "N/A", copyable=True))
        
        if imphash_val:
            self.layout.addWidget(_InfoRow("IMPHASH", imphash_val, copyable=True))
        else:
            self.layout.addWidget(_InfoRow("IMPHASH", "N/A", copyable=True))

        # VirusTotal
        vt = static_data.get("vt_result", "")
        if vt:
            self.layout.addWidget(_SectionHeader("🛡️  VIRUSTOTAL"))
            vt_color = COLORS['severity_critical'] if "malicious" in str(vt).lower() else COLORS['success']
            self.layout.addWidget(_InfoRow("Detection", vt, value_color=vt_color))

        # Entropy
        if "entropy" in static_data:
            self.layout.addWidget(_SectionHeader("📊  ENTROPY"))
            ent = static_data["entropy"]
            ent_color = COLORS['severity_critical'] if float(ent) > 7.0 else COLORS['severity_low']
            self.layout.addWidget(_InfoRow("Value", f"{ent:.4f}" if isinstance(ent, float) else str(ent), value_color=ent_color))

        # Suspicious strings
        raw_strings = static_data.get("strings", static_data.get("suspicious_strings", []))
        strings = []
        if isinstance(raw_strings, dict):
            pri = raw_strings.get("priority_strings", {})
            if isinstance(pri, dict):
                for items in pri.values():
                    if isinstance(items, list):
                        strings.extend(items)
            gen = raw_strings.get("general_strings", {})
            if isinstance(gen, dict):
                for items in gen.values():
                    if isinstance(items, list):
                        strings.extend(items)
        elif isinstance(raw_strings, list):
            strings = raw_strings
            
        if strings:
            self.layout.addWidget(_SectionHeader("📝  SUSPICIOUS STRINGS"))
            text = QTextEdit()
            text.setReadOnly(True)
            text.setMinimumHeight(150)
            text.setFont(QFont("Consolas", 9))
            text.setStyleSheet(f"QTextEdit{{background:{COLORS['bg_input']};color:{COLORS['warning']};border:1px solid {COLORS['border']};border-radius:4px;padding:4px;}}")
            text.setPlainText("\n".join(str(s) for s in strings[:50]))
            self.layout.addWidget(text)

        # URLs
        urls = static_data.get("urls", [])
        if not urls and "network_geolocation" in static_data:
            urls = static_data["network_geolocation"].get("urls", [])
            
        if urls:
            self.layout.addWidget(_SectionHeader("🌐  EXTRACTED URLs"))
            for url in urls[:20]:
                lbl = QLabel(f"• {url}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;padding-left:8px;border:none;background:transparent;")
                lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self.layout.addWidget(lbl)

        # IPs
        ips = static_data.get("ips", [])
        if not ips and "network_geolocation" in static_data:
            ips = static_data["network_geolocation"].get("ips", [])
            
        if ips:
            self.layout.addWidget(_SectionHeader("📡  EXTRACTED IPs"))
            for ip in ips[:20]:
                lbl = QLabel(f"• {ip}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(f"color:{COLORS['warning']};font-size:10px;padding-left:8px;border:none;background:transparent;")
                lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self.layout.addWidget(lbl)

        self.layout.addStretch()


class DynamicAnalysisTab(QScrollArea):
    """Tab showing dynamic/behavioral analysis results."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setStyleSheet(f"QScrollArea{{border:none;background:{COLORS['bg_card']};}}")
        self.content = QWidget()
        self.content.setStyleSheet(f"background:{COLORS['bg_card']};")
        self.layout = QVBoxLayout(self.content)
        self.layout.setContentsMargins(12, 10, 12, 10)
        self.layout.setSpacing(4)
        self._show_empty()
        self.setWidget(self.content)

    def _show_empty(self):
        lbl = QLabel("Select a file to view dynamic analysis results")
        lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:11px;font-style:italic;border:none;background:transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(lbl)
        self.layout.addStretch()

    def _clear(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def load_data(self, dynamic_data: dict):
        self._clear()
        if not dynamic_data:
            self._show_empty(); return

        # Processes
        procs = dynamic_data.get("processes", [])
        if procs:
            self.layout.addWidget(_SectionHeader("⚙️  SPAWNED PROCESSES"))
            tbl_procs = QTableWidget()
            tbl_procs.setColumnCount(3)
            tbl_procs.setHorizontalHeaderLabels(["Process", "PID", "Action"])
            tbl_procs.verticalHeader().setVisible(False)
            tbl_procs.setWordWrap(True)
            tbl_procs.setStyleSheet(f"""
                QTableWidget {{ background: {COLORS['bg_input']}; color: {COLORS['text_primary']}; border: 1px solid {COLORS['border']}; border-radius: 4px; font-size: 11px; }}
                QHeaderView::section {{ background: {COLORS['bg_secondary']}; color: {COLORS['text_dim']}; border: none; border-bottom: 1px solid {COLORS['border']}; padding: 4px; font-weight: bold; }}
            """)
            tbl_procs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            tbl_procs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            tbl_procs.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            tbl_procs.setEditTriggers(QAbstractItemView.NoEditTriggers)
            tbl_procs.setMinimumHeight(200)
            
            for p in procs[:30]:
                row = tbl_procs.rowCount()
                tbl_procs.insertRow(row)
                if isinstance(p, dict):
                    tbl_procs.setItem(row, 0, QTableWidgetItem(p.get("name","")))
                    tbl_procs.setItem(row, 1, QTableWidgetItem(str(p.get("pid",""))))
                    tbl_procs.setItem(row, 2, QTableWidgetItem(p.get("action","")))
                else:
                    tbl_procs.setItem(row, 0, QTableWidgetItem(str(p)))
                    tbl_procs.setItem(row, 1, QTableWidgetItem(""))
                    tbl_procs.setItem(row, 2, QTableWidgetItem(""))
            tbl_procs.resizeRowsToContents()
            self.layout.addWidget(tbl_procs)

        # Network
        net = dynamic_data.get("network_activity", dynamic_data.get("network", []))
        if net:
            self.layout.addWidget(_SectionHeader("🌐  NETWORK ACTIVITY"))
            tbl = QTableWidget()
            tbl.setColumnCount(4)
            tbl.setHorizontalHeaderLabels(["IP/Host", "Port", "Protocol", "Direction"])
            tbl.verticalHeader().setVisible(False)
            tbl.setWordWrap(True)
            tbl.setStyleSheet(f"""
                QTableWidget {{ background: {COLORS['bg_input']}; color: {COLORS['text_primary']}; border: 1px solid {COLORS['border']}; border-radius: 4px; font-size: 11px; }}
                QHeaderView::section {{ background: {COLORS['bg_secondary']}; color: {COLORS['text_dim']}; border: none; border-bottom: 1px solid {COLORS['border']}; padding: 4px; font-weight: bold; }}
            """)
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
            tbl.setMinimumHeight(200)
            
            for n in net[:30]:
                row = tbl.rowCount(); tbl.insertRow(row)
                if isinstance(n, dict):
                    tbl.setItem(row, 0, QTableWidgetItem(n.get("ip", n.get("host",""))))
                    tbl.setItem(row, 1, QTableWidgetItem(str(n.get("port",""))))
                    tbl.setItem(row, 2, QTableWidgetItem(n.get("protocol","")))
                    tbl.setItem(row, 3, QTableWidgetItem(n.get("direction","")))
                else:
                    tbl.setItem(row, 0, QTableWidgetItem(str(n)))
            tbl.resizeRowsToContents()
            self.layout.addWidget(tbl)

        # Registry
        reg = dynamic_data.get("registry_changes", dynamic_data.get("registry", []))
        if reg:
            self.layout.addWidget(_SectionHeader("📋  REGISTRY CHANGES"))
            reg_text = "\n".join(str(r) for r in reg[:30])
            lbl = QLabel(reg_text)
            lbl.setFont(QFont("Consolas", 9))
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lbl.setStyleSheet(f"QLabel{{background:{COLORS['bg_input']};color:{COLORS['severity_critical']};border:1px solid {COLORS['border']};border-radius:4px;padding:8px;}}")
            self.layout.addWidget(lbl)

        # File system changes
        fs = dynamic_data.get("file_changes", dynamic_data.get("filesystem", []))
        if fs:
            self.layout.addWidget(_SectionHeader("📁  FILE SYSTEM CHANGES"))
            for f in fs[:20]:
                lbl = QLabel(f"• {f}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(f"color:{COLORS['warning']};font-size:10px;padding-left:8px;border:none;background:transparent;")
                lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self.layout.addWidget(lbl)

        self.layout.addStretch()


class FileDetailsTabs(QWidget):
    """Tabbed detail inspector panel for the selected file."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_data = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # File name header
        self.file_header = QLabel("No file selected")
        self.file_header.setStyleSheet(f"color:{COLORS['text_dim']};font-size:12px;font-weight:700;padding:6px 10px;background:{COLORS['bg_secondary']};border:1px solid {COLORS['border']};border-radius:6px;")
        self.file_header.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.file_header)

        # Tabs
        self.tabs = QTabWidget()
        self.static_tab = StaticAnalysisTab()
        self.dynamic_tab = DynamicAnalysisTab()
        self.ai_tab = AIInsightsTab()
        self.tabs.addTab(self.static_tab, "🔬 Static")
        self.tabs.addTab(self.dynamic_tab, "⚡ Dynamic")
        self.tabs.addTab(self.ai_tab, "🤖 AI Insights")
        layout.addWidget(self.tabs)

    def load_data(self, result: dict):
        """Load full result data into the detail tabs."""
        self._current_data = result
        filename = result.get("file", "Unknown")
        verdict = result.get("verdict", "")
        color = severity_color(verdict)

        self.file_header.setText(f"📄 {filename}")
        self.file_header.setStyleSheet(f"color:{color};font-size:12px;font-weight:700;padding:6px 10px;background:{COLORS['bg_secondary']};border:1px solid {color}60;border-radius:6px;")

        self.static_tab.load_data(
            result.get("static", {}),
            sha256=result.get("sha256", "")
        )
        self.dynamic_tab.load_data(result.get("dynamic", {}))
        self.ai_tab.load_data(result.get("ai_explanation", {}), verdict)

    def clear(self):
        self._current_data = None
        self.file_header.setText("No file selected")
        self.file_header.setStyleSheet(f"color:{COLORS['text_dim']};font-size:12px;font-weight:700;padding:6px 10px;background:{COLORS['bg_secondary']};border:1px solid {COLORS['border']};border-radius:6px;")
        self.static_tab.load_data({})
        self.dynamic_tab.load_data({})
        self.ai_tab.load_data({})
