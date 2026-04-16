"""
gui.py - Main PyQt5 Graphical User Interface
=============================================
Two-tab interface:

Tab 1 — Live Scan: scan table + detail panel + connect button
Tab 2 — Known Networks: saved profiles, highlighted if currently visible,
         with connect / remove / trust actions

Changes vs original:
 • Dark-mode palette refined with gradient header & accent borders
 • Summary stat cards use colored left-border accent strips
 • Table rows have tighter, richer status colouring
 • Export dialog now saves PDF (via export_pdf_report) instead of HTML
 • Progress bar styled to match accent colour
"""

import os
import subprocess
import platform
from datetime import datetime
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QTextEdit, QGroupBox, QSplitter, QHeaderView,
    QStatusBar, QProgressBar, QFileDialog, QMessageBox,
    QAbstractItemView, QFrame, QTabWidget, QInputDialog,
    QLineEdit, QDialog, QDialogButtonBox, QFormLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush, QPalette, QLinearGradient, QGradient

from scanner import scan_networks
from analyzer import analyze_all_networks
from known_networks import (
    load_known_networks,
    import_from_windows_profiles,
    add_trusted_network,
    remove_trusted_network,
    save_known_networks,
)
from database import export_json_report, export_pdf_report

# ─────────────────────────────────────────────────────────────────────────────
# Global stylesheet
# ─────────────────────────────────────────────────────────────────────────────

APP_STYLESHEET = """
/* ── Base ───────────────────────────────────────────────────────── */
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 12px;
}

/* ── Buttons ────────────────────────────────────────────────────── */
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 7px;
    padding: 6px 16px;
    font-size: 12px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #45475a;
    border-color: #89b4fa;
    color: #e6e9f8;
}
QPushButton:pressed {
    background-color: #89b4fa;
    color: #1e1e2e;
    border-color: #89b4fa;
}
QPushButton:disabled {
    background-color: #262637;
    color: #585b70;
    border-color: #313244;
}

/* ── Primary action button (Scan WiFi) ──────────────────────────── */
QPushButton#btn_scan_primary {
    background-color: #1e3a5f;
    color: #89b4fa;
    border: 1.5px solid #89b4fa;
    font-weight: bold;
}
QPushButton#btn_scan_primary:hover {
    background-color: #89b4fa;
    color: #1e1e2e;
}

/* ── Group boxes ────────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #313244;
    border-radius: 8px;
    margin-top: 12px;
    font-weight: bold;
    color: #89b4fa;
    font-size: 12px;
    padding-top: 6px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}

/* ── Tables ─────────────────────────────────────────────────────── */
QTableWidget {
    background-color: #181825;
    alternate-background-color: #1e1e2e;
    border: 1px solid #313244;
    border-radius: 6px;
    gridline-color: #2a2a3d;
    selection-background-color: #313254;
    selection-color: #cdd6f4;
    outline: none;
}
QTableWidget::item {
    padding: 4px 8px;
    border: none;
}
QHeaderView::section {
    background-color: #313244;
    color: #89b4fa;
    font-weight: bold;
    font-size: 11px;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #45475a;
    border-bottom: 1px solid #45475a;
}
QHeaderView::section:last {
    border-right: none;
}

/* ── Scrollbars ─────────────────────────────────────────────────── */
QScrollBar:vertical {
    background: #1e1e2e;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #45475a;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #89b4fa; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #1e1e2e;
    height: 8px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #45475a;
    border-radius: 4px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #89b4fa; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Text / input ───────────────────────────────────────────────── */
QTextEdit, QLineEdit {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #313244;
    border-radius: 5px;
    padding: 6px;
    font-size: 12px;
}
QTextEdit:focus, QLineEdit:focus {
    border-color: #89b4fa;
}

/* ── Status bar ─────────────────────────────────────────────────── */
QStatusBar {
    background-color: #181825;
    color: #a6adc8;
    border-top: 1px solid #313244;
    font-size: 11px;
}

/* ── Progress bar ───────────────────────────────────────────────── */
QProgressBar {
    background-color: #313244;
    border: none;
    border-radius: 3px;
    height: 6px;
}
QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 3px;
}

/* ── Splitter ───────────────────────────────────────────────────── */
QSplitter::handle {
    background-color: #313244;
    width: 2px;
}
QSplitter::handle:hover {
    background-color: #89b4fa;
}

/* ── Message boxes ──────────────────────────────────────────────── */
QMessageBox {
    background-color: #1e1e2e;
    color: #cdd6f4;
}
QMessageBox QLabel {
    color: #cdd6f4;
}

/* ── File dialog ────────────────────────────────────────────────── */
QFileDialog {
    background-color: #1e1e2e;
    color: #cdd6f4;
}

/* ── Tab widget ─────────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #313244;
    border-radius: 6px;
    background: #1e1e2e;
    top: -1px;
}
QTabBar::tab {
    background: #262637;
    color: #a6adc8;
    padding: 8px 22px;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    margin-right: 3px;
    font-weight: bold;
    font-size: 12px;
    border: 1px solid #313244;
    border-bottom: none;
}
QTabBar::tab:selected {
    background: #313254;
    color: #89b4fa;
    border-bottom-color: #313254;
}
QTabBar::tab:hover:!selected {
    background: #313244;
    color: #cdd6f4;
}

/* ── Tooltip ────────────────────────────────────────────────────── */
QToolTip {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Background workers
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    finished = pyqtSignal(list)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, known):
        super().__init__()
        self.known = known

    def run(self):
        try:
            self.progress.emit("Triggering fresh WiFi radio scan (takes ~2s)...")
            networks = scan_networks()
            if not networks:
                self.error.emit("No WiFi networks found. Ensure WiFi is enabled.")
                return
            self.progress.emit(f"Analyzing {len(networks)} networks for phishing indicators...")
            enriched = analyze_all_networks(networks, self.known)
            self.finished.emit(enriched)
        except Exception as e:
            self.error.emit(f"Scan failed: {str(e)}")


class ImportWorker(QThread):
    finished = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def run(self):
        try:
            self.progress.emit("Importing Windows WiFi profiles...")
            known = import_from_windows_profiles()
            self.finished.emit(known)
        except Exception as e:
            self.error.emit(f"Import failed: {str(e)}")


class ConnectWorker(QThread):
    """Connects to a WiFi network via netsh in the background."""
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(str)

    def __init__(self, ssid: str, password: str = ""):
        super().__init__()
        self.ssid     = ssid
        self.password = password

    def run(self):
        if platform.system() != "Windows":
            self.finished.emit(True, f"[Demo] Would connect to '{self.ssid}' on Windows.")
            return

        try:
            self.progress.emit(f"Connecting to '{self.ssid}'...")
            check = subprocess.run(
                ["netsh", "wlan", "show", "profile", f'name={self.ssid}'],
                capture_output=True, text=True, timeout=10
            )
            has_profile = "Profile information" in check.stdout or self.ssid in check.stdout

            if has_profile:
                result = subprocess.run(
                    ["netsh", "wlan", "connect", f'name={self.ssid}'],
                    capture_output=True, text=True, timeout=15
                )
                if "Connection request was completed successfully" in result.stdout:
                    self.finished.emit(True, f"Successfully connected to '{self.ssid}'.")
                else:
                    out = result.stdout.strip() or result.stderr.strip()
                    self.finished.emit(False, f"Connection failed: {out}")
            else:
                if not self.password:
                    self.finished.emit(False, "NO_PROFILE")
                    return

                xml      = self._build_profile_xml(self.ssid, self.password)
                xml_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "tmp_wifi_profile.xml")
                with open(xml_path, "w", encoding="utf-8") as f:
                    f.write(xml)

                subprocess.run(
                    ["netsh", "wlan", "add", "profile", f'filename={xml_path}'],
                    capture_output=True, text=True, timeout=10
                )
                connect_result = subprocess.run(
                    ["netsh", "wlan", "connect", f'name={self.ssid}'],
                    capture_output=True, text=True, timeout=15
                )
                try:
                    os.remove(xml_path)
                except OSError:
                    pass

                if "Connection request was completed successfully" in connect_result.stdout:
                    self.finished.emit(True, f"Successfully connected to '{self.ssid}'.")
                else:
                    out = connect_result.stdout.strip() or connect_result.stderr.strip()
                    self.finished.emit(False, f"Connection failed: {out}")

        except Exception as e:
            self.finished.emit(False, str(e))

    def _build_profile_xml(self, ssid: str, password: str) -> str:
        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig>
    <SSID>
      <name>{ssid}</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{password}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>"""


# ─────────────────────────────────────────────────────────────────────────────
# Password dialog
# ─────────────────────────────────────────────────────────────────────────────

class PasswordDialog(QDialog):
    def __init__(self, ssid: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Connect to '{ssid}'")
        self.setFixedWidth(380)
        self.setStyleSheet(APP_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        info = QLabel(f"Enter the password for <b>{ssid}</b>:")
        info.setStyleSheet("color:#cdd6f4; font-size:13px;")
        layout.addWidget(info)

        form = QFormLayout()
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.Password)
        self.pw_edit.setPlaceholderText("WiFi password")
        form.addRow("Password:", self.pw_edit)
        layout.addLayout(form)

        show_btn = QPushButton("👁  Show / Hide Password")
        show_btn.setCheckable(True)
        show_btn.clicked.connect(self._toggle_visibility)
        layout.addWidget(show_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _toggle_visibility(self, checked):
        self.pw_edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def password(self) -> str:
        return self.pw_edit.text()


# ─────────────────────────────────────────────────────────────────────────────
# Numeric-sort table item
# ─────────────────────────────────────────────────────────────────────────────

class NumericTableItem(QTableWidgetItem):
    def __lt__(self, other):
        try:
            return float(self.text().replace(" dBm", "")) < float(other.text().replace(" dBm", ""))
        except ValueError:
            return super().__lt__(other)


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    STATUS_BG = {
        "PHISHING":   QColor("#3a0f1f"),
        "SUSPICIOUS": QColor("#312a0c"),
        "SAFE":       QColor("#0d2018"),
    }
    STATUS_FG = {
        "PHISHING":   QColor("#f38ba8"),
        "SUSPICIOUS": QColor("#f9e2af"),
        "SAFE":       QColor("#a6e3a1"),
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️  WiFi Phishing Detector v1.0")
        self.resize(1360, 840)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(APP_STYLESHEET)

        self.networks: list[dict] = []
        self.known:    dict       = load_known_networks()
        self.scan_worker    = None
        self.import_worker  = None
        self.connect_worker = None

        self._build_ui()
        self._update_summary()

    # ─────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)
        root.setSpacing(8)

        root.addWidget(self._build_header())
        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_summary_bar())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_scan_tab(),  "🔍  Live Scan")
        self.tabs.addTab(self._build_known_tab(), "📋  Known Networks")
        root.addWidget(self.tabs, stretch=1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(180)
        self.progress_bar.setMaximumHeight(6)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready — click  🔍 Scan WiFi  to begin.")

    # ── Header ──────────────────────────────────────────────────────────

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setFixedHeight(52)
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a2744, stop:0.5 #242438, stop:1 #1e1e2e);
                border: 1px solid #313244;
                border-radius: 8px;
            }
        """)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("🛡️")
        icon.setStyleSheet("font-size:22px; background:transparent; border:none;")

        title = QLabel("WiFi Phishing Detector")
        title.setStyleSheet("""
            font-size:16px; font-weight:bold; color:#89b4fa;
            background:transparent; border:none;
        """)

        sub = QLabel("Evil Twin Attack Detection System  ·  v1.0")
        sub.setStyleSheet("""
            font-size:11px; color:#585b70;
            background:transparent; border:none;
        """)

        layout.addWidget(icon)
        layout.addWidget(title)
        layout.addSpacing(8)
        layout.addWidget(sub)
        layout.addStretch()

        badge = QLabel("🔒 EDUCATIONAL USE ONLY")
        badge.setStyleSheet("""
            background:#2a1a1a; color:#f38ba8;
            border:1px solid #f38ba830; border-radius:4px;
            padding:3px 10px; font-size:10px; font-weight:bold;
        """)
        layout.addWidget(badge)

        return frame

    # ── Toolbar ─────────────────────────────────────────────────────────

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet("QWidget { background: transparent; }")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.btn_scan = QPushButton("🔍  Scan WiFi")
        self.btn_scan.setObjectName("btn_scan_primary")
        self.btn_scan.setToolTip("Scan all nearby WiFi networks and analyze for phishing indicators")
        self.btn_scan.setMinimumWidth(130)
        self.btn_scan.clicked.connect(self.on_scan)
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background-color: #1e3a5f;
                color: #89b4fa;
                border: 1.5px solid #89b4fa;
                border-radius: 7px;
                padding: 6px 18px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
        """)

        self.btn_load = QPushButton("📂  Load Known Networks")
        self.btn_load.setToolTip("Import trusted WiFi profiles from Windows — opens Known Networks tab")
        self.btn_load.clicked.connect(self.on_load_known)

        self.btn_trust = QPushButton("✅  Trust Selected")
        self.btn_trust.setToolTip("Mark the selected network as trusted")
        self.btn_trust.clicked.connect(self.on_trust_selected)

        self.btn_connect = QPushButton("📶  Connect")
        self.btn_connect.setToolTip("Connect to the selected WiFi network")
        self.btn_connect.clicked.connect(self.on_connect_selected)
        self.btn_connect.setStyleSheet("""
            QPushButton {
                background-color: #1a3520;
                color: #a6e3a1;
                border: 1.5px solid #a6e3a1;
                border-radius: 7px;
                padding: 6px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #a6e3a1;
                color: #1e1e2e;
            }
            QPushButton:disabled {
                background-color: #262637;
                color: #585b70;
                border-color: #313244;
            }
        """)

        self.btn_export = QPushButton("💾  Export PDF Report")
        self.btn_export.setToolTip("Save scan results as a PDF or JSON report")
        self.btn_export.clicked.connect(self.on_export)

        for btn in [self.btn_scan, self.btn_load, self.btn_trust,
                    self.btn_connect, self.btn_export]:
            layout.addWidget(btn)

        layout.addStretch()
        return bar

    # ── Summary bar ─────────────────────────────────────────────────────

    def _build_summary_bar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet("QWidget { background: transparent; }")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        def stat(label_text, accent, border_color):
            frame = QFrame()
            frame.setFixedHeight(54)
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #262637;
                    border: 1px solid #313244;
                    border-left: 4px solid {border_color};
                    border-radius: 6px;
                    min-width: 110px;
                }}
            """)
            fl = QHBoxLayout(frame)
            fl.setContentsMargins(10, 4, 10, 4)
            fl.setSpacing(8)

            num = QLabel("0")
            num.setStyleSheet(f"""
                color: {accent};
                font-size: 22px;
                font-weight: bold;
                background: transparent;
                border: none;
            """)
            lbl = QLabel(label_text)
            lbl.setStyleSheet("""
                color: #6c7086;
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 0.5px;
                background: transparent;
                border: none;
            """)
            lbl.setWordWrap(False)

            vl = QVBoxLayout()
            vl.setSpacing(0)
            vl.addWidget(num)
            vl.addWidget(lbl)

            fl.addLayout(vl)
            layout.addWidget(frame)
            return num

        self.lbl_phishing_count   = stat("PHISHING",        "#f38ba8", "#f38ba8")
        self.lbl_suspicious_count = stat("SUSPICIOUS",       "#f9e2af", "#f9e2af")
        self.lbl_safe_count       = stat("SAFE",             "#a6e3a1", "#a6e3a1")
        self.lbl_total_count      = stat("TOTAL",            "#89b4fa", "#89b4fa")
        self.lbl_known_count      = stat("KNOWN NETWORKS",   "#cba6f7", "#cba6f7")
        self.lbl_available_count  = stat("AVAILABLE NOW",    "#94e2d5", "#94e2d5")
        layout.addStretch()
        return bar

    # ── Tab 1: Live Scan ─────────────────────────────────────────────────

    def _build_scan_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_scan_table())
        splitter.addWidget(self._build_detail_panel())
        splitter.setSizes([870, 460])

        layout.addWidget(splitter)
        return widget

    def _build_scan_table(self) -> QWidget:
        group = QGroupBox("Nearby WiFi Networks")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(6, 12, 6, 6)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Signal (dBm)", "Ch", "Security", "Vendor", "Score", "Status"
        ])
        self._style_table(self.table)
        self.table.selectionModel().selectionChanged.connect(self.on_row_selected)
        layout.addWidget(self.table)
        return group

    def _build_detail_panel(self) -> QWidget:
        group = QGroupBox("Network Analysis Details")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        self.detail_header = QLabel("Select a network to view details.")
        self.detail_header.setStyleSheet("""
            font-weight: bold;
            font-size: 13px;
            color: #89b4fa;
            background: transparent;
        """)
        self.detail_header.setWordWrap(True)
        layout.addWidget(self.detail_header)

        self.detail_connect_btn = QPushButton("📶  Connect to This Network")
        self.detail_connect_btn.setEnabled(False)
        self.detail_connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #1a3520;
                color: #a6e3a1;
                border: 1px solid #a6e3a1;
                border-radius: 7px;
                padding: 8px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #a6e3a1; color: #1e1e2e; }
            QPushButton:disabled {
                background-color: #262637;
                color: #585b70;
                border-color: #45475a;
            }
        """)
        self.detail_connect_btn.clicked.connect(self.on_connect_from_detail)
        layout.addWidget(self.detail_connect_btn)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet("""
            QTextEdit {
                background-color: #181825;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11.5px;
                padding: 10px;
                line-height: 1.5;
            }
        """)
        layout.addWidget(self.detail_text, stretch=1)
        return group

    # ── Tab 2: Known Networks ────────────────────────────────────────────

    def _build_known_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        info = QLabel(
            "  💡  Networks highlighted in "
            "<span style='color:#94e2d5; font-weight:bold;'>teal</span>"
            " are currently visible in the scan. "
            "Select a row to connect, remove, or manage."
        )
        info.setStyleSheet("""
            QLabel {
                background-color: #262637;
                color: #cdd6f4;
                padding: 8px 14px;
                border-radius: 6px;
                font-size: 12px;
                border-left: 4px solid #94e2d5;
            }
        """)
        info.setWordWrap(True)
        layout.addWidget(info)

        self.known_table = QTableWidget()
        self.known_table.setColumnCount(6)
        self.known_table.setHorizontalHeaderLabels([
            "SSID", "Security", "Trusted BSSIDs", "Known Channels", "Available Now", "Actions"
        ])
        self._style_table(self.known_table)
        self.known_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in [1, 2, 3, 4, 5]:
            self.known_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeToContents)
        layout.addWidget(self.known_table, stretch=1)

        btn_row = QWidget()
        btn_row.setStyleSheet("background: transparent;")
        btn_layout = QHBoxLayout(btn_row)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(8)

        self.btn_known_connect = QPushButton("📶  Connect to Selected")
        self.btn_known_connect.setStyleSheet("""
            QPushButton {
                background-color: #1a3520;
                color: #a6e3a1;
                border: 1.5px solid #a6e3a1;
                border-radius: 7px;
                padding: 6px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #a6e3a1; color: #1e1e2e; }
        """)
        self.btn_known_connect.clicked.connect(self.on_connect_known_selected)

        self.btn_known_remove = QPushButton("🗑️  Remove from Known")
        self.btn_known_remove.setStyleSheet("""
            QPushButton {
                background-color: #3a1a1a;
                color: #f38ba8;
                border: 1.5px solid #f38ba8;
                border-radius: 7px;
                padding: 6px 14px;
            }
            QPushButton:hover { background-color: #f38ba8; color: #1e1e2e; }
        """)
        self.btn_known_remove.clicked.connect(self.on_remove_known)

        self.btn_known_refresh = QPushButton("🔄  Refresh")
        self.btn_known_refresh.clicked.connect(self._populate_known_table)

        for b in [self.btn_known_connect, self.btn_known_remove, self.btn_known_refresh]:
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addWidget(btn_row)
        return widget

    # ── Shared table styling ─────────────────────────────────────────────

    def _style_table(self, table: QTableWidget):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(True)
        table.setShowGrid(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.verticalHeader().setDefaultSectionSize(30)

    # ─────────────────────────────────────────────────────────────────────
    # Data population
    # ─────────────────────────────────────────────────────────────────────

    def populate_scan_table(self, networks: list[dict]):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(networks))

        for row, net in enumerate(networks):
            status = net.get("status", "SAFE")
            bg     = self.STATUS_BG.get(status, QColor("#1e1e2e"))
            fg_s   = self.STATUS_FG.get(status, QColor("#cdd6f4"))

            cells = [
                QTableWidgetItem(net.get("ssid",     "")),
                QTableWidgetItem(net.get("bssid",    "")),
                NumericTableItem(f"{net.get('signal', -100)} dBm"),
                NumericTableItem(str(net.get("channel", 0))),
                QTableWidgetItem(net.get("security", "Unknown")),
                QTableWidgetItem(net.get("vendor",   "Unknown")),
                NumericTableItem(str(net.get("score", 0))),
                QTableWidgetItem(status),
            ]

            for col, item in enumerate(cells):
                item.setBackground(QBrush(bg))
                if col == 7:
                    item.setForeground(QBrush(fg_s))
                    f = QFont(); f.setBold(True); item.setFont(f)
                else:
                    item.setForeground(QBrush(QColor("#cdd6f4")))
                self.table.setItem(row, col, item)

        self.table.setSortingEnabled(True)
        self.table.sortByColumn(6, Qt.DescendingOrder)
        self._update_summary()

    def _populate_known_table(self):
        live_ssids = {n.get("ssid", "") for n in self.networks}

        self.known_table.setSortingEnabled(False)
        self.known_table.setRowCount(0)

        rows = list(self.known.items())
        rows.sort(key=lambda kv: (kv[0] not in live_ssids, kv[0].lower()))
        self.known_table.setRowCount(len(rows))

        available_teal = QColor("#0d2e2e")
        normal_bg      = QColor("#1e1e2e")

        for row, (ssid, info) in enumerate(rows):
            is_live = ssid in live_ssids
            bg      = available_teal if is_live else normal_bg

            if not isinstance(info, dict):
                info = {"security": str(info), "trusted_bssids": [], "channels": []}

            bssids   = ", ".join(info.get("trusted_bssids", [])) or "—"
            channels = ", ".join(str(c) for c in info.get("channels", [])) or "—"
            security = info.get("security", "Unknown")
            avail_txt = "✅ Yes" if is_live else "—"

            cells = [
                QTableWidgetItem(ssid),
                QTableWidgetItem(security),
                QTableWidgetItem(bssids),
                QTableWidgetItem(channels),
                QTableWidgetItem(avail_txt),
                QTableWidgetItem(""),
            ]

            for col, item in enumerate(cells):
                item.setBackground(QBrush(bg))
                if is_live and col in (0, 4):
                    item.setForeground(QBrush(QColor("#94e2d5")))
                    f = QFont(); f.setBold(True); item.setFont(f)
                elif is_live:
                    item.setForeground(QBrush(QColor("#cdd6f4")))
                else:
                    item.setForeground(QBrush(QColor("#585b70")))
                self.known_table.setItem(row, col, item)

        self.known_table.setSortingEnabled(True)
        self._update_summary()

    def _update_summary(self):
        live_ssids      = {n.get("ssid", "") for n in self.networks}
        available_known = sum(1 for s in self.known if s in live_ssids)

        self.lbl_phishing_count.setText(  str(sum(1 for n in self.networks if n.get("status") == "PHISHING")))
        self.lbl_suspicious_count.setText(str(sum(1 for n in self.networks if n.get("status") == "SUSPICIOUS")))
        self.lbl_safe_count.setText(      str(sum(1 for n in self.networks if n.get("status") == "SAFE")))
        self.lbl_total_count.setText(     str(len(self.networks)))
        self.lbl_known_count.setText(     str(len(self.known)))
        self.lbl_available_count.setText( str(available_known))

    # ─────────────────────────────────────────────────────────────────────
    # Toolbar handlers
    # ─────────────────────────────────────────────────────────────────────

    def on_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            return
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("⏳  Scanning…")
        self.progress_bar.show()
        self.status_bar.showMessage("Scanning WiFi networks…")

        self.scan_worker = ScanWorker(self.known)
        self.scan_worker.finished.connect(self._on_scan_done)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.progress.connect(self.status_bar.showMessage)
        self.scan_worker.start()

    def _on_scan_done(self, networks: list[dict]):
        self.networks = networks
        self.populate_scan_table(networks)
        self._populate_known_table()
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍  Scan WiFi")
        self.progress_bar.hide()

        phishing   = sum(1 for n in networks if n.get("status") == "PHISHING")
        suspicious = sum(1 for n in networks if n.get("status") == "SUSPICIOUS")

        if phishing:
            self.status_bar.showMessage(f"⚠️  ALERT: {phishing} PHISHING network(s) detected!")
        elif suspicious:
            self.status_bar.showMessage(f"⚠️  {suspicious} SUSPICIOUS network(s) found.")
        else:
            self.status_bar.showMessage(f"✅  Scan complete — {len(networks)} networks found. All appear safe.")

    def _on_scan_error(self, msg: str):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍  Scan WiFi")
        self.progress_bar.hide()
        self.status_bar.showMessage(f"Error: {msg}")
        QMessageBox.warning(self, "Scan Error", msg)

    def on_load_known(self):
        if self.import_worker and self.import_worker.isRunning():
            return
        self.btn_load.setEnabled(False)
        self.btn_load.setText("⏳  Loading…")
        self.progress_bar.show()

        self.import_worker = ImportWorker()
        self.import_worker.finished.connect(self._on_import_done)
        self.import_worker.error.connect(self._on_import_error)
        self.import_worker.progress.connect(self.status_bar.showMessage)
        self.import_worker.start()

    def _on_import_done(self, known: dict):
        self.known = known
        self.btn_load.setEnabled(True)
        self.btn_load.setText("📂  Load Known Networks")
        self.progress_bar.hide()
        self._populate_known_table()
        self._update_summary()
        self.status_bar.showMessage(f"Imported {len(known)} trusted network profiles.")
        self.tabs.setCurrentIndex(1)

    def _on_import_error(self, msg: str):
        self.btn_load.setEnabled(True)
        self.btn_load.setText("📂  Load Known Networks")
        self.progress_bar.hide()
        QMessageBox.warning(self, "Import Error", msg)

    def on_trust_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection",
                                    "Select a network in the Live Scan tab first.")
            return
        ssid  = self.table.item(row, 0).text()
        bssid = self.table.item(row, 1).text()
        net   = self._find_network(ssid, bssid)
        if not net:
            return

        reply = QMessageBox.question(
            self, "Trust Network",
            f"Mark '{ssid}' ({bssid}) as trusted?\n"
            f"This adds it to your known networks baseline.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.known = add_trusted_network(
                ssid, bssid, net.get("security", "Unknown"), net.get("channel", 0), self.known
            )
            self._populate_known_table()
            self._update_summary()
            self.status_bar.showMessage(f"'{ssid}' added to trusted networks.")

    # ── Export — now PDF ────────────────────────────────────────────────

    def on_export(self):
        if not self.networks:
            QMessageBox.information(self, "No Data", "Please run a scan first.")
            return

        path, filt = QFileDialog.getSaveFileName(
            self,
            "Export Scan Report",
            f"wifi_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "PDF Report (*.pdf);;JSON Report (*.json)"
        )
        if not path:
            return

        try:
            if "JSON" in filt or path.endswith(".json"):
                out = export_json_report(
                    self.networks,
                    path if path.endswith(".json") else path + ".json"
                )
            else:
                out = export_pdf_report(
                    self.networks,
                    path if path.endswith(".pdf") else path + ".pdf"
                )
            self.status_bar.showMessage(f"Report saved: {out}")
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{out}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ─────────────────────────────────────────────────────────────────────
    # Connect handlers
    # ─────────────────────────────────────────────────────────────────────

    def on_connect_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection",
                                    "Select a network in the Live Scan tab first.")
            return
        ssid     = self.table.item(row, 0).text()
        security = self.table.item(row, 4).text()
        self._initiate_connect(ssid, security)

    def on_connect_from_detail(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ssid     = self.table.item(row, 0).text()
        security = self.table.item(row, 4).text()
        self._initiate_connect(ssid, security)

    def on_connect_known_selected(self):
        row = self.known_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection",
                                    "Select a network in the Known Networks tab.")
            return
        ssid_item = self.known_table.item(row, 0)
        sec_item  = self.known_table.item(row, 1)
        if not ssid_item:
            return
        ssid     = ssid_item.text()
        security = sec_item.text() if sec_item else "Unknown"
        self._initiate_connect(ssid, security)

    def _initiate_connect(self, ssid: str, security: str):
        if not ssid:
            return
        net = next((n for n in self.networks if n.get("ssid") == ssid), None)
        if net:
            status = net.get("status", "SAFE")
            if status == "PHISHING":
                reply = QMessageBox.warning(
                    self, "⚠️ PHISHING WARNING",
                    f"'{ssid}' has been flagged as a PHISHING network!\n\n"
                    f"Connecting may expose your credentials to attackers.\n\n"
                    f"Are you absolutely sure you want to connect?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return
            elif status == "SUSPICIOUS":
                reply = QMessageBox.question(
                    self, "⚠️ Suspicious Network",
                    f"'{ssid}' is flagged as SUSPICIOUS.\n\nProceed with caution. Connect anyway?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return

        has_profile = self._has_windows_profile(ssid)
        if has_profile or security in ("Open", ""):
            self._run_connect(ssid, "")
        else:
            dlg = PasswordDialog(ssid, self)
            if dlg.exec_() == QDialog.Accepted:
                pw = dlg.password()
                if not pw and security not in ("Open",):
                    QMessageBox.warning(self, "No Password",
                                        "Please enter the network password.")
                    return
                self._run_connect(ssid, pw)

    def _has_windows_profile(self, ssid: str) -> bool:
        if platform.system() != "Windows":
            return ssid in self.known
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "profile", f'name={ssid}'],
                capture_output=True, text=True, timeout=8
            )
            return "Profile information" in result.stdout or ssid in result.stdout
        except Exception:
            return False

    def _run_connect(self, ssid: str, password: str):
        if self.connect_worker and self.connect_worker.isRunning():
            QMessageBox.information(self, "Busy",
                                    "A connection attempt is already in progress.")
            return
        self.btn_connect.setEnabled(False)
        self.btn_connect.setText("⏳  Connecting…")
        self.detail_connect_btn.setEnabled(False)
        self.progress_bar.show()
        self.status_bar.showMessage(f"Connecting to '{ssid}'…")

        self.connect_worker = ConnectWorker(ssid, password)
        self.connect_worker.finished.connect(self._on_connect_done)
        self.connect_worker.progress.connect(self.status_bar.showMessage)
        self.connect_worker.start()

    def _on_connect_done(self, success: bool, message: str):
        self.btn_connect.setEnabled(True)
        self.btn_connect.setText("📶  Connect")
        self.detail_connect_btn.setEnabled(True)
        self.progress_bar.hide()

        if message == "NO_PROFILE":
            self.status_bar.showMessage("Password required.")
            return
        if success:
            self.status_bar.showMessage(f"✅  {message}")
            QMessageBox.information(self, "Connected", message)
        else:
            self.status_bar.showMessage(f"❌  {message}")
            QMessageBox.warning(self, "Connection Failed", message)

    # ─────────────────────────────────────────────────────────────────────
    # Known Networks tab handlers
    # ─────────────────────────────────────────────────────────────────────

    def on_remove_known(self):
        row = self.known_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection", "Select a network to remove.")
            return
        ssid_item = self.known_table.item(row, 0)
        if not ssid_item:
            return
        ssid  = ssid_item.text()
        reply = QMessageBox.question(
            self, "Remove Network",
            f"Remove '{ssid}' from known networks?\n"
            f"It will no longer be used as a trusted baseline.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.known = remove_trusted_network(ssid, self.known)
            self._populate_known_table()
            self._update_summary()
            self.status_bar.showMessage(f"'{ssid}' removed from known networks.")

    # ─────────────────────────────────────────────────────────────────────
    # Row selection → detail panel
    # ─────────────────────────────────────────────────────────────────────

    def on_row_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ssid_item  = self.table.item(row, 0)
        bssid_item = self.table.item(row, 1)
        if not ssid_item or not bssid_item:
            return
        net = self._find_network(ssid_item.text(), bssid_item.text())
        if net:
            self._show_detail(net)
            self.detail_connect_btn.setEnabled(True)

    def on_analyze_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ssid_item  = self.table.item(row, 0)
        bssid_item = self.table.item(row, 1)
        if not ssid_item or not bssid_item:
            return
        net = self._find_network(ssid_item.text(), bssid_item.text())
        if net:
            self._show_detail(net)

    # ─────────────────────────────────────────────────────────────────────
    # Detail panel
    # ─────────────────────────────────────────────────────────────────────

    def _show_detail(self, net: dict):
        ssid     = net.get("ssid",     "N/A")
        bssid    = net.get("bssid",    "N/A")
        signal   = net.get("signal",   "N/A")
        channel  = net.get("channel",  "N/A")
        security = net.get("security", "N/A")
        vendor   = net.get("vendor",   "Unknown")
        score    = net.get("score",    0)
        status   = net.get("status",   "SAFE")
        reasons  = net.get("reasons",  [])

        emoji  = {"PHISHING": "🔴", "SUSPICIOUS": "🟡", "SAFE": "🟢"}.get(status, "⚪")
        colour = {"PHISHING": "#f38ba8", "SUSPICIOUS": "#f9e2af", "SAFE": "#a6e3a1"}.get(
            status, "#cdd6f4"
        )

        self.detail_header.setText(f"{emoji}  {ssid} — {status}  (Score: {score}/100)")

        # Tint connect button to match status
        if status == "PHISHING":
            self.detail_connect_btn.setStyleSheet("""
                QPushButton { background-color:#3a1525; color:#f38ba8;
                              border:1px solid #f38ba8; border-radius:7px;
                              padding:8px; font-weight:bold; }
                QPushButton:hover { background-color:#f38ba8; color:#1e1e2e; }
            """)
        elif status == "SUSPICIOUS":
            self.detail_connect_btn.setStyleSheet("""
                QPushButton { background-color:#312a0c; color:#f9e2af;
                              border:1px solid #f9e2af; border-radius:7px;
                              padding:8px; font-weight:bold; }
                QPushButton:hover { background-color:#f9e2af; color:#1e1e2e; }
            """)
        else:
            self.detail_connect_btn.setStyleSheet("""
                QPushButton { background-color:#1a3520; color:#a6e3a1;
                              border:1px solid #a6e3a1; border-radius:7px;
                              padding:8px; font-weight:bold; }
                QPushButton:hover { background-color:#a6e3a1; color:#1e1e2e; }
            """)

        # Score bar (ASCII)
        bar_filled = int(score / 5)
        bar_empty  = 20 - bar_filled
        score_bar  = "█" * bar_filled + "░" * bar_empty

        reasons_block = "\n".join(f"  ⚑  {r}" for r in reasons) if reasons \
            else "  ✔  No issues detected."

        self.detail_text.setHtml(f"""
<style>
  body   {{ background:#181825; color:#cdd6f4; font-family:'Consolas','Courier New',monospace;
            font-size:11.5px; line-height:1.55; margin:0; padding:0; }}
  .hdr   {{ color:#585b70; font-size:10px; letter-spacing:1px; }}
  .val   {{ color:#cdd6f4; }}
  .mono  {{ color:#a6adc8; }}
  .score {{ color:{colour}; font-weight:bold; }}
  .bar   {{ color:{colour}; letter-spacing:1px; }}
  .sec   {{ color:#89b4fa; font-weight:bold; margin-top:10px; }}
  .reason{{ color:#f9e2af; }}
  hr     {{ border:none; border-top:1px solid #313244; margin:8px 0; }}
</style>
<span class="hdr">SSID</span><br>
<span class="val">&nbsp;&nbsp;{ssid}</span><br><br>

<span class="hdr">BSSID / VENDOR</span><br>
<span class="mono">&nbsp;&nbsp;{bssid}</span><br>
<span class="val">&nbsp;&nbsp;{vendor}</span><br><br>

<span class="hdr">SIGNAL / CHANNEL / SECURITY</span><br>
<span class="val">&nbsp;&nbsp;{signal} dBm &nbsp;·&nbsp; Ch {channel} &nbsp;·&nbsp; {security}</span>
<hr>
<span class="hdr">RISK SCORE</span><br>
<span class="score">&nbsp;&nbsp;{score} / 100</span><br>
<span class="bar">&nbsp;&nbsp;[{score_bar}]</span><br>
<span class="score">&nbsp;&nbsp;► {status}</span>
<hr>
<span class="sec">DETECTION FINDINGS</span><br>
<span class="reason">{reasons_block.replace(chr(10), '<br>')}</span>
""")

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _find_network(self, ssid: str, bssid: str) -> dict | None:
        for n in self.networks:
            if n.get("ssid") == ssid and n.get("bssid") == bssid:
                return n
        return None
