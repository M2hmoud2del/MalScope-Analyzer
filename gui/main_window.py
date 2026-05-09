"""
MalScope Main Window Compositor
===============================
Assembles the 3-column enterprise layout and wires all signals.
"""

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QSplitter
)
from PyQt5.QtCore import Qt

from gui.signals import MalScopeSignals
from gui.theme import SIZES, COLORS

from gui.widgets import (
    HeaderBar, FolderSelectorCard, ScanControlPanel, 
    StatsPanel, PipelineVisualizer, ResultsTable, 
    LogConsole, FileDetailsTabs, ReportPanel
)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MalScope - Professional SOC Dashboard")
        self.setMinimumSize(1400, 900)
        
        # Instantiate central signal hub
        self.signals = MalScopeSignals()
        
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        # Main central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout (Vertical: Header + Body)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Header
        self.header = HeaderBar()
        self.main_layout.addWidget(self.header)
        
        # Body (Horizontal: Left, Center, Right)
        self.body_widget = QWidget()
        self.body_widget.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
        self.body_layout = QHBoxLayout(self.body_widget)
        self.body_layout.setContentsMargins(10, 10, 10, 10)
        self.body_layout.setSpacing(10)
        
        # --- LEFT PANEL ---
        self.left_panel = QWidget()
        self.left_panel.setFixedWidth(SIZES['left_panel_w'])
        self.left_layout = QVBoxLayout(self.left_panel)
        self.left_layout.setContentsMargins(0, 0, 0, 0)
        self.left_layout.setSpacing(10)
        
        self.folder_selector = FolderSelectorCard()
        self.scan_controls = ScanControlPanel()
        self.stats_panel = StatsPanel()
        self.pipeline_viz = PipelineVisualizer()
        
        self.left_layout.addWidget(self.folder_selector)
        self.left_layout.addWidget(self.scan_controls)
        self.left_layout.addWidget(self.stats_panel)
        self.left_layout.addWidget(self.pipeline_viz)
        
        # --- CENTER PANEL (Stretchable) ---
        self.center_splitter = QSplitter(Qt.Vertical)
        
        self.results_table = ResultsTable()
        self.log_console = LogConsole()
        
        self.center_splitter.addWidget(self.results_table)
        self.center_splitter.addWidget(self.log_console)
        # Give more space to the table by default
        self.center_splitter.setSizes([600, 200])
        
        # --- RIGHT PANEL ---
        self.right_panel = QWidget()
        self.right_panel.setFixedWidth(SIZES['right_panel_w'])
        self.right_layout = QVBoxLayout(self.right_panel)
        self.right_layout.setContentsMargins(0, 0, 0, 0)
        self.right_layout.setSpacing(10)
        
        self.file_details = FileDetailsTabs()
        self.report_panel = ReportPanel()
        
        self.right_layout.addWidget(self.file_details)
        self.right_layout.addWidget(self.report_panel)
        
        # Add to body layout
        self.body_layout.addWidget(self.left_panel)
        self.body_layout.addWidget(self.center_splitter, 1)  # 1 = stretch
        self.body_layout.addWidget(self.right_panel)
        
        self.main_layout.addWidget(self.body_widget, 1)

    def _connect_signals(self):
        """Strictly connect signals without inline logic."""
        # 1. Widget -> Signal Hub (Requests to Backend)
        self.scan_controls.btn_start.clicked.connect(self._route_start_scan)
        self.scan_controls.btn_stop.clicked.connect(self.signals.request_stop.emit)
        self.report_panel.btn_generate.clicked.connect(self._route_generate_report)
        
        # 2. Signal Hub -> Widgets (Updates from Backend)
        self.signals.scan_started.connect(self._handle_scan_started)
        self.signals.scan_progress.connect(self.stats_panel.update_progress)
        self.signals.file_scan_started.connect(self.pipeline_viz.set_active_file)
        self.signals.pipeline_stage_changed.connect(self._handle_pipeline_stage_changed)
        self.signals.file_result_ready.connect(self._handle_file_result)
        self.signals.scan_completed.connect(self._handle_scan_completed)
        self.signals.log_message.connect(self.log_console.append_log)
        
        self.signals.report_progress.connect(self.report_panel.update_progress)
        self.signals.report_completed.connect(self.report_panel.report_completed)
        self.signals.report_error.connect(self.report_panel.report_error)
        
        # 3. Widget -> MainWindow -> Widget (Local UI Routing, NO direct widget-to-widget)
        self.results_table.row_selected.connect(self._route_row_selection)
        self.scan_controls.btn_clear.clicked.connect(self._route_clear_ui)

    # --- Routing Methods (No Business Logic) ---

    def _route_start_scan(self):
        folder = self.folder_selector.get_folder_path()
        mode = self.scan_controls.get_scan_mode()
        self.current_scan_mode = mode
        if folder:
            self._route_clear_ui()
            self.signals.request_scan.emit(folder, mode)
        else:
            self.signals.log_message.emit("WARN", "Please select a folder before starting the scan.")

    def _route_generate_report(self):
        scope = "current" if self.report_panel.combo_scope.currentIndex() == 0 else "all"
        files = []
        
        if scope == "current":
            row = self.results_table.table.currentRow()
            if row >= 0:
                item = self.results_table.table.item(row, 0)
                if item:
                    filename = item.text()
                    if hasattr(self, 'scan_cache') and filename in self.scan_cache:
                        files = [self.scan_cache[filename]]
                    else:
                        files = [filename] # Safety fallback
        elif scope == "all":
            if hasattr(self, 'scan_cache'):
                files = list(self.scan_cache.values())
                
        self.signals.request_report.emit(scope, files)

    def _route_row_selection(self, file_data: dict):
        # UI routing: table selection updates details panel
        self.file_details.load_data(file_data)

    def _route_clear_ui(self):
        self.results_table.clear_all()
        self.file_details.clear()
        self.pipeline_viz.reset()
        self.stats_panel.reset()
        self.header.update_threat_counts(0, 0, 0)
        self.header.pipeline_indicator.reset_all()
        self.signals.log_message.emit("INFO", "UI Cleared.")

    # --- State Handlers ---

    def _handle_scan_started(self):
        self.scan_controls.set_scanning(True)
        self.pipeline_viz.reset_all()
        self.header.pipeline_indicator.reset_all()

    def _get_skipped_stages(self):
        mode = getattr(self, "current_scan_mode", "Full Analysis")
        if mode == "Quick Scan":
            return ["dynamic"]
        elif mode == "Static Only":
            return ["dynamic", "ai"]
        return []

    def _handle_pipeline_stage_changed(self, filename: str, stage: str):
        skipped = self._get_skipped_stages()
        self.pipeline_viz.update_stage(filename, stage, skipped_stages=skipped)
        self.header.pipeline_indicator.set_stage(stage, "active")
        for s in skipped:
            self.header.pipeline_indicator.set_stage(s, "skipped")

    def _handle_scan_completed(self, summary: dict):
        skipped = self._get_skipped_stages()
        self.scan_controls.set_scanning(False)
        self.pipeline_viz.set_active_file("", complete=True, skipped_stages=skipped)
        for s in ["input", "static", "dynamic", "scoring", "ai", "report"]:
            self.header.pipeline_indicator.set_stage(s, "skipped" if s in skipped else "completed")

    def _handle_file_result(self, result: dict):
        # --- BULLETPROOF FIX: Save the real dictionary to a hidden cache ---
        if not hasattr(self, 'scan_cache'):
            self.scan_cache = {}
        self.scan_cache[result['file']] = result
        # -------------------------------------------------------------------
        
        self.results_table.add_result(result)
        # MainWindow updates the stats panel based on the result, instead of inline logic
        verdict = result.get("verdict", "unknown").lower()
        if "malicious" in verdict:
            self.stats_panel.increment("malicious")
        elif "suspicious" in verdict:
            self.stats_panel.increment("suspicious")
        elif "clean" in verdict:
            self.stats_panel.increment("clean")
            
        counts = self.stats_panel._counts
        self.header.update_threat_counts(counts["malicious"], counts["suspicious"], counts["clean"])

    def _handle_pipeline_stage_changed(self, filename: str, stage: str):
        self.pipeline_viz.update_stage(filename, stage)
        stages_order = ["input", "static", "dynamic", "scoring", "ai", "report"]
        stage_lower = stage.lower()
        if stage_lower in stages_order:
            idx = stages_order.index(stage_lower)
            for i, s in enumerate(stages_order):
                if i < idx:
                    self.header.pipeline_indicator.set_stage(s, "completed")
                elif i == idx:
                    self.header.pipeline_indicator.set_stage(s, "active")
                else:
                    self.header.pipeline_indicator.set_stage(s, "idle")