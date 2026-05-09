"""
MalScope Backend Orchestrator
=============================
Handles all business logic, manages background tasks, and emits updates.
"""

import os
import time
from PyQt5.QtCore import QObject, QThread, pyqtSlot, pyqtSignal
from ai.llm_analyzer import LLMAnalyzer
from reports.pdf_generator import ReportGenerator

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

    @pyqtSlot(str, str)
    def start_scan(self, folder_path: str, mode: str = "Full Analysis"):
        try:
            if self.worker_thread and self.worker_thread.isRunning():
                self.signals.log_message.emit("WARN", "Scan already in progress.")
                return
        except RuntimeError:
            self.worker_thread = None

        self.signals.log_message.emit("INFO", f"Initializing {mode} for {folder_path}...")
        self.signals.scan_started.emit()
        
        # Instantiate and start the worker thread to prevent UI freezing
        self.worker = ScanWorker(folder_path, mode, self.signals)
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
        """Professional PDF Report Generation"""
        if not files:
            self.signals.log_message.emit("ERROR", "No file selected for report.")
            return

        self.signals.log_message.emit("INFO", f"Generating PDF report for {scope}...")
        self.signals.report_progress.emit(50)

        try:
            report_gen = ReportGenerator()
            output_paths = []
            
            total_files = len(files)
            for idx, item in enumerate(files):
                if isinstance(item, str):
                    # Fallback presentation mock
                    filename = item
                    target_data = {
                        "file": filename,
                        "verdict": "suspicious" if filename.endswith((".pdf", ".doc")) else "clean",
                        "score": 55 if filename.endswith((".pdf", ".doc")) else 10,
                        "static": {
                            "entropy": 6.8, "pe_sections": 5, "urls": ["http://malicious.com/payload.exe"]
                        },
                        "dynamic": {
                            "processes": ["cmd.exe (PID: 4512)"], "network": ["Outbound to 192.168.1.100:443"]
                        }
                    }
                    from ai.llm_analyzer import LLMAnalyzer
                    ai_text = LLMAnalyzer().analyze(target_data)
                else:
                    # Live Data
                    target_data = item
                    ai_data = target_data.get('ai_explanation', {})
                    ai_text = ai_data.get('explanation', str(ai_data)) if isinstance(ai_data, dict) else str(ai_data)
                
                # Generate PDF for this item
                pdf_path = report_gen.generate_pdf(target_data, ai_text)
                output_paths.append(pdf_path)
                
                # Update progress
                progress = int(((idx + 1) / total_files) * 100)
                self.signals.report_progress.emit(progress)
            
            if len(output_paths) == 1:
                final_path = os.path.abspath(output_paths[0])
                msg = f"PDF Report saved to: {final_path}"
            else:
                final_path = os.path.abspath(report_gen.reports_dir)
                msg = f"Generated {len(output_paths)} PDF Reports in: {final_path}"
                
            self.signals.report_progress.emit(100)
            self.signals.report_completed.emit(final_path)
            self.signals.log_message.emit("SUCCESS", msg)
            
        except Exception as e:
            self.signals.log_message.emit("ERROR", f"PDF Generation failed: {str(e)}")

class ScanWorker(QObject):
    """Worker object that runs the actual blocking analysis pipeline."""
    finished = pyqtSignal()
    
    def __init__(self, folder_path, mode, signals):
        super().__init__()
        self.folder_path = folder_path
        self.mode = mode
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
            for _ in range(10): # Shorter mock delay
                if not self.is_running:
                    return
                QThread.msleep(10)
                
            try:
                from analysis.static.static_analyzer import run_static_analysis 
                static_data = run_static_analysis(file_path)
            except Exception as e:
                self.signals.log_message.emit("ERROR", f"Static module error: {str(e)}")
                static_data = {}

            # Dynamic Analysis (Skipped in Quick Scan and Static Only)
            dynamic_data = {}
            if self.mode == "Full Analysis":
                self.signals.pipeline_stage_changed.emit(filename, "dynamic")
                for _ in range(10):
                    if not self.is_running:
                        return
                    QThread.msleep(10)
                try:
                    from analysis.dynamic.dynamic_analyzer import run_dynamic_analysis
                    dynamic_data = run_dynamic_analysis(file_path) 
                except Exception as e:
                    self.signals.log_message.emit("ERROR", f"Dynamic module error: {str(e)}")

            # Extract static score from VirusTotal malicious detections (Normalized 0-10)
            vt_res = static_data.get("vt_result", {})
            static_score = 0.0
            if isinstance(vt_res, dict):
                detections = vt_res.get("detections", {})
                malicious = detections.get("malicious", 0)
                total = detections.get("total", 0)
                if total > 0:
                    static_score = (malicious / total) * 10.0
                
            # Store rounded static score for GUI consistency
            static_data["score"] = round(static_score, 1)

            # Scoring (Normalized 0-10)
            dynamic_score = 0.0
            if dynamic_data:
                dynamic_score = float(dynamic_data.get("score", 0.0))
                # Store rounded dynamic score for GUI consistency
                dynamic_data["score"] = round(dynamic_score, 1)

            # Final Risk Score (60/40 Weighted)
            score = round((static_score * 0.6) + (dynamic_score * 0.4), 1)

            # Determine verdict (0-10 scale)
            if score >= 7.0:
                verdict = "malicious"
            elif score >= 3.0:
                verdict = "suspicious"
            else:
                verdict = "clean"
                
            # Get real SHA256
            hashes = static_data.get("hashes", {})
            sha256 = hashes.get("sha256", "Unknown")
            
            # AI Analysis (Skipped in Static Only)
            ai_explanation = {}
            if self.mode != "Static Only":
                self.signals.pipeline_stage_changed.emit(filename, "ai")
                for _ in range(10):
                    if not self.is_running:
                        return
                    QThread.msleep(10)
                
                ai_explanation = {
                    "classification": verdict.capitalize(),
                    "confidence": "AI Evaluated",
                    "explanation": LLMAnalyzer().analyze({
                        "file": filename,
                        "verdict": verdict,
                        "score": score,
                        "static": static_data,
                        "dynamic": dynamic_data
                    }),
                    "recommendations": ["Please review the detailed AI Threat Summary above."]
                }

            # Combine results
            result = {
                "file": filename,
                "sha256": sha256,
                "verdict": verdict,
                "score": score,
                "static": static_data,
                "dynamic": dynamic_data,
                "ai_explanation": ai_explanation
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