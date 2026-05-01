"""
MalScope App Entry Point
========================
"""
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFontDatabase
from gui.main_window import MainWindow
from gui.theme import build_global_stylesheet
from core.orchestrator import Orchestrator

def main():
    app = QApplication(sys.argv)
    
    # Apply global stylesheet
    app.setStyleSheet(build_global_stylesheet())
    
    window = MainWindow()
    
    # Instantiate the Orchestrator and wire it to the signal hub
    orchestrator = Orchestrator(window.signals)
    
    # Keep reference to orchestrator to prevent garbage collection
    window._orchestrator = orchestrator
    
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
