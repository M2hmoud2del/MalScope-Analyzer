"""
MalScope Pipeline Visualizer Widget
=====================================
Vertical pipeline flow visualization with animated stage indicators.
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
from PyQt5.QtCore import Qt
from gui.theme import COLORS


class PipelineNode(QFrame):
    """A single pipeline stage node."""

    def __init__(self, icon, name, parent=None):
        super().__init__(parent)
        self.name = name
        self._state = "idle"
        self.setFixedHeight(32)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)
        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setStyleSheet("font-size:12px;border:none;background:transparent;")
        layout.addWidget(self.icon_lbl)
        self.name_lbl = QLabel(name)
        self.name_lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;font-weight:600;border:none;background:transparent;")
        layout.addWidget(self.name_lbl, 1)
        self.status_lbl = QLabel("●")
        self.status_lbl.setStyleSheet(f"color:{COLORS['pipeline_idle']};font-size:10px;border:none;background:transparent;")
        self.status_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self.status_lbl)
        self._apply_idle()

    def set_state(self, state):
        self._state = state
        if state == "active":
            self.setStyleSheet(f"PipelineNode,QFrame{{background-color:{COLORS['accent_blue']}15;border:1px solid {COLORS['accent_blue']};border-radius:6px;}}")
            self.name_lbl.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;border:none;background:transparent;")
            self.status_lbl.setText("◉"); self.status_lbl.setStyleSheet(f"color:{COLORS['accent_blue']};font-size:12px;border:none;background:transparent;")
        elif state == "completed":
            self.setStyleSheet(f"PipelineNode,QFrame{{background-color:{COLORS['success']}10;border:1px solid {COLORS['success']}60;border-radius:6px;}}")
            self.name_lbl.setStyleSheet(f"color:{COLORS['success']};font-size:10px;font-weight:700;border:none;background:transparent;")
            self.status_lbl.setText("✓"); self.status_lbl.setStyleSheet(f"color:{COLORS['success']};font-size:12px;font-weight:bold;border:none;background:transparent;")
        elif state == "error":
            self.setStyleSheet(f"PipelineNode,QFrame{{background-color:{COLORS['error']}10;border:1px solid {COLORS['error']}60;border-radius:6px;}}")
            self.name_lbl.setStyleSheet(f"color:{COLORS['error']};font-size:10px;font-weight:700;border:none;background:transparent;")
            self.status_lbl.setText("✗"); self.status_lbl.setStyleSheet(f"color:{COLORS['error']};font-size:12px;font-weight:bold;border:none;background:transparent;")
        elif state == "skipped":
            self.setStyleSheet(f"PipelineNode,QFrame{{background-color:{COLORS['bg_elevated']};border:1px solid {COLORS['border_light']};border-radius:6px;}}")
            self.name_lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;font-weight:700;text-decoration:line-through;border:none;background:transparent;")
            self.status_lbl.setText("✗"); self.status_lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:12px;font-weight:bold;border:none;background:transparent;")
        else:
            self._apply_idle()

    def _apply_idle(self):
        self.setStyleSheet(f"PipelineNode,QFrame{{background-color:{COLORS['bg_secondary']};border:1px solid {COLORS['border']};border-radius:6px;}}")
        self.name_lbl.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;font-weight:600;border:none;background:transparent;")
        self.status_lbl.setText("●"); self.status_lbl.setStyleSheet(f"color:{COLORS['pipeline_idle']};font-size:10px;border:none;background:transparent;")


class PipelineVisualizer(QWidget):
    """Vertical pipeline flow chart."""

    STAGES = [
        ("📁", "Input"),
        ("🔬", "Static Analysis"),
        ("⚡", "Dynamic Analysis"),
        ("📊", "Risk Scoring"),
        ("🤖", "AI Explanation"),
        ("📄", "Report"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes = {}
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet(f"PipelineVisualizer{{background-color:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:8px;}}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(0)

        header = QLabel("🔄  PIPELINE STATUS")
        header.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;letter-spacing:1px;border:none;background:transparent;")
        layout.addWidget(header)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet(f"color:{COLORS['border']};"); sep.setFixedHeight(1)
        layout.addWidget(sep)
        layout.addSpacing(6)

        self.current_file_label = QLabel("")
        self.current_file_label.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:10px;font-style:italic;border:none;background:transparent;padding-bottom:4px;")
        self.current_file_label.setWordWrap(True)
        self.current_file_label.hide()
        layout.addWidget(self.current_file_label)

        for i, (icon, name) in enumerate(self.STAGES):
            node = PipelineNode(icon, name)
            self.nodes[name.lower().split()[0] if ' ' in name else name.lower()] = node
            layout.addWidget(node)
            if i < len(self.STAGES) - 1:
                connector = QLabel("  │")
                connector.setStyleSheet(f"color:{COLORS['border_light']};font-size:10px;border:none;background:transparent;")
                connector.setFixedHeight(10)
                layout.addWidget(connector)

        layout.addStretch()

    def set_stage(self, stage_name, state="active"):
        key = stage_name.lower().split()[0] if ' ' in stage_name else stage_name.lower()
        if key in self.nodes:
            self.nodes[key].set_state(state)

    def set_current_file(self, filename):
        self.current_file_label.setText(f"Processing: {filename}")
        self.current_file_label.show()

    def set_active_file(self, filename: str, complete: bool = False, skipped_stages: list = None):
        skipped_stages = skipped_stages or []
        if complete:
            self.current_file_label.setText("Scan Complete")
            self.current_file_label.show()
            for node_name, node in self.nodes.items():
                if node_name in skipped_stages:
                    node.set_state("skipped")
                else:
                    node.set_state("completed")
        else:
            self.set_current_file(filename)
            self.reset()

    def update_stage(self, filename: str, stage: str, skipped_stages: list = None):
        self.set_current_file(filename)
        skipped_stages = skipped_stages or []
        found = False
        for node_name, node in self.nodes.items():
            if node_name == (stage.lower().split()[0] if ' ' in stage else stage.lower()):
                node.set_state("active")
                found = True
            elif not found:
                node.set_state("skipped" if node_name in skipped_stages else "completed")
            else:
                node.set_state("skipped" if node_name in skipped_stages else "idle")

    def reset_all(self):
        for node in self.nodes.values():
            node.set_state("idle")
        self.current_file_label.hide()

    def reset(self):
        self.reset_all()
