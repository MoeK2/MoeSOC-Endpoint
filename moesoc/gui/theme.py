"""Design tokens and the application stylesheet.

All colors, spacing and radii live here; widgets reference roles/object names
rather than hard-coding styles. A light palette can be added by defining
another ``Palette`` — nothing else needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

from moesoc.core.enums import HealthState, Severity

# 8 px spacing system
SPACE_1 = 4
SPACE_2 = 8
SPACE_3 = 12
SPACE_4 = 16
SPACE_6 = 24
SPACE_8 = 32
RADIUS = 8
RADIUS_SMALL = 6
SIDEBAR_WIDTH = 220

FONT_CANDIDATES = ("Segoe UI Variable Text", "Segoe UI", "Inter", "Noto Sans", "DejaVu Sans")
BASE_FONT_PT = 10


@dataclass(frozen=True, slots=True)
class Palette:
    window: str
    sidebar: str
    surface: str
    surface_raised: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_text: str
    selection: str
    severity: dict[Severity, str]
    health: dict[HealthState, str]


DARK = Palette(
    window="#0F1115",
    sidebar="#0B0D10",
    surface="#161A20",
    surface_raised="#1C2128",
    border="#242A33",
    border_strong="#323A45",
    text="#E6E8EB",
    text_muted="#9BA3AE",
    text_faint="#6B7480",
    accent="#4C8DFF",
    accent_hover="#6AA0FF",
    accent_text="#FFFFFF",
    selection="#1E3A66",
    severity={
        Severity.LOW: "#7A8899",
        Severity.MEDIUM: "#E0A23B",
        Severity.HIGH: "#E5683C",
        Severity.CRITICAL: "#E5484D",
    },
    health={
        HealthState.AVAILABLE: "#3FB37F",
        HealthState.LIMITED: "#E0A23B",
        HealthState.UNAVAILABLE: "#6B7480",
        HealthState.ERROR: "#E5484D",
    },
)

# Palette used by painted widgets (badges, dots). Light theme: swap this constant.
ACTIVE: Palette = DARK


def pick_font_family() -> str:
    available = set(QFontDatabase.families())
    for family in FONT_CANDIDATES:
        if family in available:
            return family
    return QApplication.font().family()


def build_stylesheet(p: Palette) -> str:
    return f"""
    QWidget {{ color: {p.text}; }}
    QMainWindow, QDialog, #Root {{ background: {p.window}; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QStackedWidget {{ background: transparent; }}
    QToolTip {{ background: {p.surface_raised}; color: {p.text};
                border: 1px solid {p.border_strong}; padding: 4px 8px; }}

    /* ---------- sidebar ---------- */
    #Sidebar {{ background: {p.sidebar}; border-right: 1px solid {p.border}; }}
    #BrandName {{ font-size: 15pt; font-weight: 600; }}
    #BrandSub {{ color: {p.text_faint}; font-size: 9pt; letter-spacing: 1px; }}
    QPushButton#NavButton {{
        text-align: left; padding: 8px 12px; border: none; border-radius: {RADIUS_SMALL}px;
        color: {p.text_muted}; font-size: 10pt;
    }}
    QPushButton#NavButton:hover {{ background: {p.surface}; color: {p.text}; }}
    QPushButton#NavButton:checked {{ background: {p.surface_raised}; color: {p.text};
                                     font-weight: 600; }}
    #PrivacyNote {{ color: {p.text_faint}; font-size: 8.5pt; }}

    /* ---------- header ---------- */
    #Header {{ border-bottom: 1px solid {p.border}; }}
    #PageTitle {{ font-size: 16pt; font-weight: 600; }}
    #HeaderMeta {{ color: {p.text_muted}; font-size: 9pt; }}
    #DemoBadge {{
        color: {p.severity[Severity.MEDIUM]}; border: 1px solid {p.severity[Severity.MEDIUM]};
        border-radius: {RADIUS_SMALL}px; padding: 4px 10px; font-weight: 600;
    }}

    /* ---------- buttons ---------- */
    QPushButton {{
        background: {p.surface_raised}; border: 1px solid {p.border_strong};
        border-radius: {RADIUS_SMALL}px; padding: 7px 14px; color: {p.text};
    }}
    QPushButton:hover {{ border-color: {p.text_faint}; }}
    QPushButton:disabled {{ color: {p.text_faint}; border-color: {p.border}; }}
    QPushButton[variant="primary"] {{
        background: {p.accent}; border: 1px solid {p.accent}; color: {p.accent_text};
        font-weight: 600;
    }}
    QPushButton[variant="primary"]:hover {{ background: {p.accent_hover}; }}
    QPushButton[variant="primary"]:disabled {{
        background: {p.surface_raised}; border-color: {p.border}; color: {p.text_faint};
    }}
    QPushButton[variant="danger"] {{
        border: 1px solid {p.health[HealthState.ERROR]}; color: {p.health[HealthState.ERROR]};
    }}

    /* ---------- cards & text roles ---------- */
    #Card {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px; }}
    QLabel[role="cardTitle"] {{ color: {p.text_muted}; font-size: 9pt; font-weight: 600; }}
    QLabel[role="metric"] {{ font-size: 24pt; font-weight: 600; }}
    QLabel[role="caption"] {{ color: {p.text_faint}; font-size: 8.5pt; }}
    QLabel[role="body"] {{ color: {p.text_muted}; }}
    QLabel[role="emptyTitle"] {{ font-size: 11pt; font-weight: 600; }}
    QLabel[role="banner"] {{ font-size: 11pt; font-weight: 600; }}
    QLabel[role="error"] {{ color: {p.health[HealthState.ERROR]}; }}
    #Banner {{ background: {p.surface}; border: 1px solid {p.border};
               border-radius: {RADIUS}px; }}

    /* ---------- tables ---------- */
    QTableView {{
        background: {p.surface}; border: none; gridline-color: transparent;
        selection-background-color: {p.selection}; selection-color: {p.text};
        alternate-background-color: {p.surface};
    }}
    QTableView::item {{ padding: 0 8px; border-bottom: 1px solid {p.border}; }}
    QHeaderView::section {{
        background: {p.surface}; color: {p.text_faint}; border: none;
        border-bottom: 1px solid {p.border_strong}; padding: 8px; font-size: 8.5pt;
        font-weight: 600;
    }}
    QTableCornerButton::section {{ background: {p.surface}; border: none; }}

    QTextBrowser {{ background: {p.surface}; border: none; color: {p.text}; }}
    QPlainTextEdit {{
        background: {p.surface}; border: 1px solid {p.border}; border-radius: {RADIUS}px;
        color: {p.text_muted}; padding: 8px;
    }}
    QLineEdit {{
        background: {p.surface_raised}; border: 1px solid {p.border_strong};
        border-radius: {RADIUS_SMALL}px; padding: 6px 10px;
    }}
    QLineEdit:focus {{ border-color: {p.accent}; }}
    QComboBox {{
        background: {p.surface_raised}; border: 1px solid {p.border_strong};
        border-radius: {RADIUS_SMALL}px; padding: 5px 10px; min-width: 90px;
    }}
    QComboBox:focus {{ border-color: {p.accent}; }}
    QComboBox QAbstractItemView {{
        background: {p.surface_raised}; border: 1px solid {p.border_strong};
        selection-background-color: {p.selection}; outline: none;
    }}
    QSplitter::handle {{ background: {p.border}; }}
    QProgressBar {{ background: {p.surface_raised}; border: none; border-radius: 2px;
                    max-height: 3px; }}
    QProgressBar::chunk {{ background: {p.accent}; border-radius: 2px; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {p.border_strong}; border-radius: 3px;
                                   min-height: 24px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {p.border_strong}; border-radius: 3px;
                                     min-width: 24px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
    """


def build_qpalette(p: Palette) -> QPalette:
    """Native palette so widgets not covered by the stylesheet are also dark."""
    qp = QPalette()
    role = QPalette.ColorRole
    for color_role, value in (
        (role.Window, p.window),
        (role.WindowText, p.text),
        (role.Base, p.surface),
        (role.AlternateBase, p.surface_raised),
        (role.Text, p.text),
        (role.Button, p.surface_raised),
        (role.ButtonText, p.text),
        (role.Highlight, p.selection),
        (role.HighlightedText, p.text),
        (role.ToolTipBase, p.surface_raised),
        (role.ToolTipText, p.text),
        (role.PlaceholderText, p.text_faint),
        (role.Link, p.accent),
    ):
        qp.setColor(color_role, QColor(value))
    return qp


def apply_theme(app: QApplication, palette: Palette = ACTIVE) -> None:
    font = QFont(pick_font_family(), BASE_FONT_PT)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    app.setFont(font)
    app.setStyle("Fusion")  # consistent rendering base for the stylesheet
    app.setPalette(build_qpalette(palette))
    app.setStyleSheet(build_stylesheet(palette))
