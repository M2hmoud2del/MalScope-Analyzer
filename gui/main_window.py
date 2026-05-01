import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QProgressBar, QLabel
)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MalScope - Malware Analysis Tool")
        self.setGeometry(200, 200, 800, 500)

        self.layout = QVBoxLayout()

        self.label = QLabel("Select a folder to scan")
        self.layout.addWidget(self.label)

        self.btn_browse = QPushButton("Browse Folder")
        self.btn_browse.clicked.connect(self.select_folder)
        self.layout.addWidget(self.btn_browse)

        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.clicked.connect(self.scan_files)
        self.layout.addWidget(self.btn_scan)

        self.progress = QProgressBar()
        self.layout.addWidget(self.progress)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File", "Hash", "Status", "Threat"])
        self.layout.addWidget(self.table)

        self.setLayout(self.layout)

        self.folder_path = ""

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.folder_path = folder
            self.label.setText(f"Selected: {folder}")

    def scan_files(self):
        if not self.folder_path:
            self.label.setText("Please select a folder first!")
            return

        files = os.listdir(self.folder_path)
        self.table.setRowCount(len(files))

        for i, file in enumerate(files):
            file_path = os.path.join(self.folder_path, file)

            # Dummy data (هنبدلها بعدين بالـ scanner الحقيقي)
            self.table.setItem(i, 0, QTableWidgetItem(file))
            self.table.setItem(i, 1, QTableWidgetItem("hash_here"))
            self.table.setItem(i, 2, QTableWidgetItem("Scanning..."))
            self.table.setItem(i, 3, QTableWidgetItem("-"))

            self.progress.setValue(int((i + 1) / len(files) * 100))

        self.label.setText("Scan Completed!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())