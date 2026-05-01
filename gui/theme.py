"""
MalScope Dark Cybersecurity Theme
==================================
Centralized theme system for the SOC dashboard.
All colors, fonts, and global stylesheets are defined here.
"""

# ─── Color Palette ────────────────────────────────────────────────────────────

COLORS = {
    # Backgrounds
    "bg_primary":     "#0a0e17",
    "bg_secondary":   "#111827",
    "bg_card":        "#1a2332",
    "bg_elevated":    "#1f2937",
    "bg_input":       "#0f1623",
    "bg_hover":       "#243047",
    "bg_selected":    "#1e3a5f",

    # Borders
    "border":         "#2a3441",
    "border_light":   "#374151",
    "border_glow":    "#3b82f6",

    # Text
    "text_primary":   "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_dim":       "#64748b",
    "text_bright":    "#f8fafc",

    # Accent
    "accent_blue":    "#3b82f6",
    "accent_cyan":    "#06b6d4",
    "accent_purple":  "#8b5cf6",
    "accent_indigo":  "#6366f1",

    # Severity / Verdict
    "severity_critical": "#ef4444",
    "severity_high":     "#f59e0b",
    "severity_medium":   "#eab308",
    "severity_low":      "#22c55e",
    "severity_info":     "#3b82f6",

    # Semantic
    "success":        "#22c55e",
    "warning":        "#f59e0b",
    "error":          "#ef4444",
    "info":           "#06b6d4",

    # Pipeline
    "pipeline_idle":     "#374151",
    "pipeline_active":   "#3b82f6",
    "pipeline_complete": "#22c55e",
    "pipeline_error":    "#ef4444",
}

# ─── Font Configuration ──────────────────────────────────────────────────────

FONTS = {
    "family_primary":  "Segoe UI, Roboto, Arial, sans-serif",
    "family_mono":     "Consolas, 'JetBrains Mono', 'Courier New', monospace",

    "size_xs":         "15px",
    "size_sm":         "16px",
    "size_base":       "18px",
    "size_md":         "19px",
    "size_lg":         "22px",
    "size_xl":         "26px",
    "size_2xl":        "32px",
    "size_3xl":        "42px",
}
# ─── Spacing & Sizing ────────────────────────────────────────────────────────

SIZES = {
    "radius_sm":    "5px",
    "radius_md":    "8px",
    "radius_lg":    "10px",
    "radius_xl":    "14px",
    "radius_pill":  "24px",

    "padding_sm":   "8px",
    "padding_md":   "12px",
    "padding_lg":   "16px",
    "padding_xl":   "20px",

    "left_panel_w": 290,
    "right_panel_w": 400,
    "header_h":     60,
}


def severity_color(verdict: str) -> str:
    """Map a verdict string to its severity color."""
    v = verdict.lower().strip()
    if v == "malicious":
        return COLORS["severity_critical"]
    elif v == "suspicious":
        return COLORS["severity_high"]
    elif v == "clean":
        return COLORS["severity_low"]
    return COLORS["text_secondary"]


def score_color(score: float) -> str:
    """Map a numeric risk score (0-10) to a color."""
    if score >= 7.0:
        return COLORS["severity_critical"]
    elif score >= 4.0:
        return COLORS["severity_high"]
    else:
        return COLORS["severity_low"]


def build_global_stylesheet() -> str:
    """Build the global QSS stylesheet for the entire application."""
    c = COLORS
    f = FONTS
    s = SIZES

    return f"""
    /* ── Global ──────────────────────────────────────────── */
    QWidget {{
        background-color: {c['bg_primary']};
        color: {c['text_primary']};
        font-family: {f['family_primary']};
        font-size: {f['size_base']};
    }}

    /* ── Scroll Bars ─────────────────────────────────────── */
    QScrollBar:vertical {{
        background: {c['bg_secondary']};
        width: 8px;
        border-radius: 4px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {c['border_light']};
        border-radius: 4px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {c['accent_blue']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: {c['bg_secondary']};
        height: 8px;
        border-radius: 4px;
        margin: 0;
    }}
    QScrollBar::handle:horizontal {{
        background: {c['border_light']};
        border-radius: 4px;
        min-width: 30px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {c['accent_blue']};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    /* ── Push Buttons ────────────────────────────────────── */
    QPushButton {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        padding: 8px 16px;
        font-size: {f['size_base']};
        font-weight: 600;
    }}
    QPushButton:hover {{
        background-color: {c['bg_hover']};
        border-color: {c['accent_blue']};
    }}
    QPushButton:pressed {{
        background-color: {c['bg_selected']};
    }}
    QPushButton:disabled {{
        background-color: {c['bg_card']};
        color: {c['text_dim']};
        border-color: {c['border']};
    }}

    /* ── Labels ──────────────────────────────────────────── */
    QLabel {{
        background-color: transparent;
        border: none;
    }}

    /* ── Line Edit ───────────────────────────────────────── */
    QLineEdit {{
        background-color: {c['bg_input']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        padding: 6px 10px;
        font-size: {f['size_base']};
        selection-background-color: {c['accent_blue']};
    }}
    QLineEdit:focus {{
        border-color: {c['accent_blue']};
    }}

    /* ── Combo Box ───────────────────────────────────────── */
    QComboBox {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        padding: 6px 10px;
        font-size: {f['size_base']};
    }}
    QComboBox:hover {{
        border-color: {c['accent_blue']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        selection-background-color: {c['bg_selected']};
        outline: none;
    }}

    /* ── Tab Widget ──────────────────────────────────────── */
    QTabWidget::pane {{
        background-color: {c['bg_card']};
        border: 1px solid {c['border']};
        border-top: none;
        border-radius: 0 0 {s['radius_md']} {s['radius_md']};
    }}
    QTabBar::tab {{
        background-color: {c['bg_secondary']};
        color: {c['text_secondary']};
        border: 1px solid {c['border']};
        border-bottom: none;
        padding: 8px 18px;
        margin-right: 2px;
        border-radius: {s['radius_md']} {s['radius_md']} 0 0;
        font-weight: 600;
        font-size: {f['size_sm']};
    }}
    QTabBar::tab:selected {{
        background-color: {c['bg_card']};
        color: {c['accent_cyan']};
        border-bottom: 2px solid {c['accent_cyan']};
    }}
    QTabBar::tab:hover:!selected {{
        background-color: {c['bg_hover']};
        color: {c['text_primary']};
    }}

    /* ── Table Widget ────────────────────────────────────── */
    QTableWidget {{
        background-color: {c['bg_card']};
        alternate-background-color: {c['bg_secondary']};
        color: {c['text_primary']};
        gridline-color: {c['border']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        font-size: {f['size_sm']};
        selection-background-color: {c['bg_selected']};
        selection-color: {c['text_bright']};
    }}
    QTableWidget::item {{
        padding: 4px 8px;
        border-bottom: 1px solid {c['border']};
    }}
    QTableWidget::item:selected {{
        background-color: {c['bg_selected']};
    }}
    QHeaderView::section {{
        background-color: {c['bg_secondary']};
        color: {c['text_secondary']};
        border: none;
        border-bottom: 2px solid {c['accent_blue']};
        border-right: 1px solid {c['border']};
        padding: 8px 10px;
        font-size: {f['size_sm']};
        font-weight: 700;
        text-transform: uppercase;
    }}

    /* ── Progress Bar ────────────────────────────────────── */
    QProgressBar {{
        background-color: {c['bg_input']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_sm']};
        height: 8px;
        text-align: center;
        color: transparent;
    }}
    QProgressBar::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 {c['accent_blue']}, stop:1 {c['accent_cyan']});
        border-radius: {s['radius_sm']};
    }}

    /* ── Text Edit / Log Console ─────────────────────────── */
    QTextEdit {{
        background-color: {c['bg_input']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        font-family: {f['family_mono']};
        font-size: {f['size_sm']};
        selection-background-color: {c['accent_blue']};
    }}

    /* ── Tree Widget ─────────────────────────────────────── */
    QTreeWidget {{
        background-color: {c['bg_card']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_md']};
        font-size: {f['size_sm']};
        alternate-background-color: {c['bg_secondary']};
    }}
    QTreeWidget::item {{
        padding: 4px;
    }}
    QTreeWidget::item:selected {{
        background-color: {c['bg_selected']};
    }}

    /* ── Splitter ────────────────────────────────────────── */
    QSplitter::handle {{
        background-color: {c['border']};
    }}
    QSplitter::handle:horizontal {{
        width: 2px;
    }}
    QSplitter::handle:vertical {{
        height: 2px;
    }}

    /* ── Tool Tip ────────────────────────────────────────── */
    QToolTip {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_light']};
        border-radius: {s['radius_sm']};
        padding: 6px 10px;
        font-size: {f['size_sm']};
    }}

    /* ── Group Box ───────────────────────────────────────── */
    QGroupBox {{
        background-color: {c['bg_card']};
        border: 1px solid {c['border']};
        border-radius: {s['radius_lg']};
        margin-top: 12px;
        padding-top: 18px;
        font-size: {f['size_sm']};
        font-weight: 700;
        color: {c['text_secondary']};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 2px 10px;
        color: {c['accent_cyan']};
    }}

    /* ── Menu ────────────────────────────────────────────── */
    QMenu {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_light']};
        border-radius: {s['radius_md']};
        padding: 4px;
    }}
    QMenu::item {{
        padding: 6px 24px 6px 12px;
        border-radius: {s['radius_sm']};
    }}
    QMenu::item:selected {{
        background-color: {c['bg_selected']};
    }}
    QMenu::separator {{
        height: 1px;
        background-color: {c['border']};
        margin: 4px 8px;
    }}
    """
