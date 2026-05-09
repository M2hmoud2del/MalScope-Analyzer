"""
MalScope Signal Hub
====================
Central Qt signals for bidirectional GUI ↔ Orchestrator communication.
All widgets communicate through these signals — no direct module calls.
"""

from PyQt5.QtCore import QObject, pyqtSignal


class MalScopeSignals(QObject):
    """
    Central signal hub for the MalScope application.
    
    This class defines all signals used for communication between
    the GUI layer and the backend orchestrator. Widgets should
    connect to these signals rather than calling backend modules directly.
    """

    # ─── Orchestrator → GUI ───────────────────────────────────────────────

    # Emitted when a scan begins
    scan_started = pyqtSignal()

    # Emitted to update overall progress: (current_file_index, total_files)
    scan_progress = pyqtSignal(int, int)

    # Emitted when a specific file starts being scanned: (filename)
    file_scan_started = pyqtSignal(str)

    # Emitted when full analysis results are ready for a file: (result_dict)
    # Expected dict keys: file, sha256, static, dynamic, score, verdict, ai_explanation
    file_result_ready = pyqtSignal(dict)

    # Emitted when the pipeline stage changes for current file: (filename, stage_name)
    # stage_name is one of: "static", "dynamic", "scoring", "ai", "report"
    pipeline_stage_changed = pyqtSignal(str, str)

    # Emitted when the entire scan completes: (summary_dict)
    # summary_dict contains: total, malicious, suspicious, clean, avg_score
    scan_completed = pyqtSignal(dict)

    # Emitted when a scan encounters an error: (error_message)
    scan_error = pyqtSignal(str)

    # Emitted to send a log message to the log console: (level, message)
    # level is one of: "INFO", "WARN", "ERROR", "CRITICAL", "SUCCESS", "DEBUG"
    log_message = pyqtSignal(str, str)

    # ─── GUI → Orchestrator ───────────────────────────────────────────────

    # User requests to start scanning a folder: (folder_path, scan_mode)
    request_scan = pyqtSignal(str, str)

    # User requests to stop the current scan
    request_stop = pyqtSignal()

    # User requests report generation: (scope, file_list)
    # scope is "current" or "all"
    request_report = pyqtSignal(str, list)

    # ─── Report Signals ──────────────────────────────────────────────────

    # Report generation progress: (percentage)
    report_progress = pyqtSignal(int)

    # Report generation completed: (report_file_path)
    report_completed = pyqtSignal(str)

    # Report generation error: (error_message)
    report_error = pyqtSignal(str)
