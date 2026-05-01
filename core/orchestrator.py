"""
MalScope Backend Orchestrator
=============================
Handles all business logic, manages background tasks, and emits updates.
"""

import os
import time
from PyQt5.QtCore import QObject, QThread, pyqtSlot, pyqtSignal

class Orchestrator(QObject):
    """
    Central Backend Orchestrator.
    Listens to GUI requests via Signal Hub, executes logic in background threads,
    and emits updates back to the Signal Hub.
    """
    def __init__(self, signals):
        super().__init__()
        self.signals = signals
        self.worker_thread = None
        self.worker = None
        self._connect_hub()

    def _connect_hub(self):
        # Listen to requests from UI
        self.signals.request_scan.connect(self.start_scan)
        self.signals.request_stop.connect(self.stop_scan)
        self.signals.request_report.connect(self.generate_report)

    @pyqtSlot(str)
    def start_scan(self, folder_path: str):
        try:
            if self.worker_thread and self.worker_thread.isRunning():
                self.signals.log_message.emit("WARN", "Scan already in progress.")
                return
        except RuntimeError:
            self.worker_thread = None

        self.signals.log_message.emit("INFO", f"Initializing scan for {folder_path}...")
        self.signals.scan_started.emit()
        
        # Instantiate and start the worker thread to prevent UI freezing
        self.worker = ScanWorker(folder_path, self.signals)
        self.worker_thread = QThread()
        self.worker.moveToThread(self.worker_thread)
        
        # Thread management signals
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.finished.connect(self._cleanup_thread)
        
        self.worker_thread.start()

    def _cleanup_thread(self):
        """Nullify references after the thread finishes so we don't access deleted C++ objects."""
        self.worker_thread = None
        self.worker = None

    @pyqtSlot()
    def stop_scan(self):
        try:
            if self.worker:
                self.signals.log_message.emit("WARN", "Stopping scan...")

                # 1. ask worker to stop
                self.worker.stop()

                # 2. force thread to quit event loop
                if self.worker_thread:
                    self.worker_thread.quit()
                    self.worker_thread.wait()

        except RuntimeError:
            pass

    @pyqtSlot(str, list)
    def generate_report(self, scope: str, files: list):
        self.signals.log_message.emit("INFO", f"Generating report for {scope} scope...")
        # Simulate report generation
        self.signals.report_progress.emit(50)
        time.sleep(1) # Note: in real app this should also be a QThread to avoid UI freeze
        
        # Create a mock report file so the UI's 'Open' button doesn't crash
        report_path = os.path.abspath("mock_report.txt")
        with open(report_path, "w") as f:
            f.write(f"MalScope Mock Report\n===================\nScope: {scope}\nFiles Included: {files}\n")
            
        self.signals.report_progress.emit(100)
        self.signals.report_completed.emit(report_path)
        self.signals.log_message.emit("SUCCESS", "Report generated.")

class ScanWorker(QObject):
    """Worker object that runs the actual blocking analysis pipeline."""
    finished = pyqtSignal()
    
    def __init__(self, folder_path, signals):
        super().__init__()
        self.folder_path = folder_path
        self.signals = signals
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        """The main scanning loop."""
        # 1. Discover files
        files = self._get_files(self.folder_path)
        total = len(files)
        
        if total == 0:
            self.signals.log_message.emit("WARN", "No files found in folder.")
            self.signals.scan_completed.emit({"total": 0, "malicious": 0, "suspicious": 0, "clean": 0, "avg_score": 0})
            self.finished.emit()
            return
            
        summary = {"total": total, "malicious": 0, "suspicious": 0, "clean": 0, "avg_score": 0}
        
        for i, file_path in enumerate(files):
            if not self.is_running:
                self.signals.log_message.emit("WARN", "Scan aborted by user.")
                break
                
            filename = os.path.basename(file_path)
            self.signals.file_scan_started.emit(filename)
            
            # --- Pipeline Execution Mock ---
            self.signals.pipeline_stage_changed.emit(filename, "static")
            for _ in range(30):
                if not self.is_running:
                    return
                QThread.msleep(10)
            self.signals.pipeline_stage_changed.emit(filename, "dynamic")
            for _ in range(30):
                if not self.is_running:
                    return
                QThread.msleep(10)
            
            self.signals.pipeline_stage_changed.emit(filename, "ai")
            for _ in range(30):
                if not self.is_running:
                    return
                QThread.msleep(10)
            
            # Mock scoring based on file extension
            verdict = "clean"
            score = 10
            if filename.endswith(".exe") or filename.endswith(".dll"):
                verdict = "malicious"
                score = 95
            elif filename.endswith(".pdf") or filename.endswith(".doc"):
                verdict = "suspicious"
                score = 55
                
            # Combine results
            result = {
                "file": filename,
                "sha256": "abcdef1234567890" + str(i),
                "verdict": verdict,
                "score": score,
                "static": {
                    "entropy": 6.8, 
                    "pe_sections": 5,
                    "urls": ["http://malicious.com/payload.exe", "http://c2-server.net"]
                },
                "dynamic": {
                    "processes": [{"name": "cmd.exe", "pid": 4512, "action": "Spawned shell"}],
                    "network": [{"ip": "192.168.1.100", "port": 443, "protocol": "TCP", "direction": "Outbound"}],
                    "registry": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"],
                    "filesystem": ["C:\\Windows\\Temp\\payload.dll"]
                },
                "ai_explanation": {
                    "classification": verdict.capitalize(),
                    "confidence": "85%" if verdict != "clean" else "99%",
                    "explanation": f"The file {filename} exhibits {verdict} behavior based on its API calls and network activity.",
                    "recommendations": [
                        "Isolate the machine from the network.",
                        "Block the extracted IPs at the firewall."
                    ] if verdict == "malicious" else []
                }
            }
            
            summary[verdict] += 1
            summary["avg_score"] += score
            
            # Emit result
            self.signals.file_result_ready.emit(result)
            self.signals.scan_progress.emit(i + 1, total)
            
        if total > 0:
            summary["avg_score"] = summary["avg_score"] // total
            
        self.signals.scan_completed.emit(summary)
        self.finished.emit()
        
    def _get_files(self, folder_path):
        """Mock file discovery. In reality, use os.walk"""
        # For simulation, just return some mock files if folder is empty or not
        try:
            real_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
            if real_files:
                return real_files
        except Exception:
            pass
        return ["mock_malware.exe", "mock_document.pdf", "mock_library.dll", "mock_image.png"]
