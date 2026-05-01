"""
MalScope Results Table Widget
===============================
Main data grid with colored verdict badges, score indicators, and row selection.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QLineEdit, QMenu, QAction, QApplication, QFrame,
    QAbstractItemView, QStyledItemDelegate
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPainter, QBrush
from gui.theme import COLORS, severity_color, score_color


class VerdictDelegate(QStyledItemDelegate):
    """Custom delegate that renders verdict cells as colored pills."""

    def paint(self, painter, option, index):
        verdict = index.data(Qt.DisplayRole)
        if not verdict:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)

        # Draw selection background
        if option.state & 0x00000004:  # State_Selected
            painter.fillRect(option.rect, QColor(COLORS['bg_selected']))

        color = severity_color(verdict)
        # Draw pill background
        pill_rect = option.rect.adjusted(8, 4, -8, -4)
        painter.setBrush(QColor(color + "25"))
        painter.setPen(QColor(color + "80"))
        painter.drawRoundedRect(pill_rect, 10, 10)

        # Draw text
        painter.setPen(QColor(color))
        font = QFont("Segoe UI", 9, QFont.Bold)
        painter.setFont(font)
        painter.drawText(pill_rect, Qt.AlignCenter, verdict)
        painter.restore()


class ResultsTable(QWidget):
    """Main results data grid."""

    row_selected = pyqtSignal(dict)  # Emits the full result dict for the selected file

    COLUMNS = ["File Name", "SHA256", "Static Score", "Dynamic Score", "Risk Score", "Verdict"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._results = {}  # filename -> result dict
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Search / filter bar
        filter_bar = QHBoxLayout()
        filter_icon = QLabel("🔍")
        filter_icon.setStyleSheet("border:none;background:transparent;font-size:13px;")
        filter_bar.addWidget(filter_icon)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter results...")
        self.search_input.setFixedHeight(30)
        self.search_input.textChanged.connect(self._filter_rows)
        filter_bar.addWidget(self.search_input)
        self.count_label = QLabel("0 results")
        self.count_label.setStyleSheet(f"color:{COLORS['text_dim']};font-size:10px;border:none;background:transparent;")
        filter_bar.addWidget(self.count_label)
        layout.addLayout(filter_bar)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        # Column sizing
        header = self.table.horizontalHeader()

        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)

        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)

        self.table.setColumnWidth(0, 260)   # File Name
        self.table.setColumnWidth(1, 240)   # SHA256
        self.table.setColumnWidth(2, 120)   # Static
        self.table.setColumnWidth(3, 120)   # Dynamic
        self.table.setColumnWidth(4, 110)   # Risk
        self.table.setColumnWidth(5, 140)   # Verdict
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.table.setStyleSheet("""
        QHeaderView::section {
            padding: 6px;
            font-weight: 600;
        }
        """)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        # Set verdict delegate
        self.table.setItemDelegateForColumn(5, VerdictDelegate())

        layout.addWidget(self.table)

    def add_result(self, result: dict):
        """Add a file analysis result to the table."""
        filename = result.get("file", "unknown")
        self._results[filename] = result

        self.table.setSortingEnabled(False)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # File name
        item_name = QTableWidgetItem(filename)
        item_name.setData(Qt.UserRole, filename)
        self.table.setItem(row, 0, item_name)

        # SHA256
        sha = result.get("sha256", result.get("static", {}).get("hash", "N/A"))
        item_hash = QTableWidgetItem(sha[:16] + "..." if len(str(sha)) > 16 else str(sha))
        item_hash.setToolTip(str(sha))
        self.table.setItem(row, 1, item_hash)

        # Static Score
        static_score = result.get("static", {}).get("score", 0)
        item_static = QTableWidgetItem(f"{static_score:.1f}" if isinstance(static_score, float) else str(static_score))
        item_static.setForeground(QColor(score_color(float(static_score) if static_score else 0)))
        item_static.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 2, item_static)

        # Dynamic Score
        dyn_score = result.get("dynamic", {}).get("score", 0)
        item_dyn = QTableWidgetItem(f"{dyn_score:.1f}" if isinstance(dyn_score, float) else str(dyn_score))
        item_dyn.setForeground(QColor(score_color(float(dyn_score) if dyn_score else 0)))
        item_dyn.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 3, item_dyn)

        # Risk Score
        risk = result.get("score", 0)
        item_risk = QTableWidgetItem(f"{risk:.1f}" if isinstance(risk, float) else str(risk))
        item_risk.setForeground(QColor(score_color(float(risk) if risk else 0)))
        font = QFont(); font.setBold(True); item_risk.setFont(font)
        item_risk.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 4, item_risk)

        # Verdict
        verdict = result.get("verdict", "Unknown")
        item_verdict = QTableWidgetItem(verdict)
        item_verdict.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 5, item_verdict)

        self.table.setSortingEnabled(True)
        self.count_label.setText(f"{self.table.rowCount()} results")

    def _on_selection_changed(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            row = rows[0].row()
            filename = self.table.item(row, 0).data(Qt.UserRole)
            if filename in self._results:
                self.row_selected.emit(self._results[filename])

    def _filter_rows(self, text):
        text = text.lower()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and text in (item.text() or "").lower():
                    match = True; break
            self.table.setRowHidden(row, not match)

    def _show_context_menu(self, pos):
        menu = QMenu(self)
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        act_details = QAction("🔍 View Details", self)
        act_details.triggered.connect(lambda: self._select_row(row))
        menu.addAction(act_details)
        act_copy = QAction("📋 Copy SHA256", self)
        act_copy.triggered.connect(lambda: self._copy_hash(row))
        menu.addAction(act_copy)
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _select_row(self, row):
        self.table.selectRow(row)

    def _copy_hash(self, row):
        item = self.table.item(row, 1)
        if item:
            filename = self.table.item(row, 0).data(Qt.UserRole)
            full_hash = self._results.get(filename, {}).get("sha256", item.text())
            QApplication.clipboard().setText(str(full_hash))

    def clear_all(self):
        self.table.setRowCount(0)
        self._results.clear()
        self.count_label.setText("0 results")

    def get_all_results(self):
        return list(self._results.values())
