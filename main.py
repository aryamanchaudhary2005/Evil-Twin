"""
WiFi Phishing Detector - Main Entry Point
==========================================
Launches the PyQt5 GUI application for detecting Evil Twin / phishing WiFi networks.

Usage:
    python main.py

Requirements:
    pip install PyQt5 scapy requests
    (Npcap optional for advanced packet capture)
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon
from gui import MainWindow


def main():
    """Initialize and launch the application."""
    app = QApplication(sys.argv)
    app.setApplicationName("WiFi Phishing Detector")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CyberSec Tools")

    # Apply a dark stylesheet for a professional cybersecurity look
    app.setStyleSheet("""
        QMainWindow {
            background-color: #1e1e2e;
        }
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }
        QPushButton {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 6px;
            padding: 6px 14px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #45475a;
            border: 1px solid #89b4fa;
        }
        QPushButton:pressed {
            background-color: #89b4fa;
            color: #1e1e2e;
        }
        QTableWidget {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            gridline-color: #313244;
            border: 1px solid #313244;
            border-radius: 4px;
        }
        QTableWidget::item {
            padding: 4px 8px;
        }
        QTableWidget::item:selected {
            background-color: #313244;
            color: #89b4fa;
        }
        QHeaderView::section {
            background-color: #313244;
            color: #89b4fa;
            padding: 6px;
            border: none;
            font-weight: bold;
        }
        QTextEdit {
            background-color: #181825;
            border: 1px solid #313244;
            border-radius: 4px;
            padding: 6px;
        }
        QLabel {
            color: #cdd6f4;
        }
        QStatusBar {
            background-color: #313244;
            color: #a6adc8;
        }
        QGroupBox {
            border: 1px solid #313244;
            border-radius: 6px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
            color: #89b4fa;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QProgressBar {
            border: 1px solid #45475a;
            border-radius: 4px;
            text-align: center;
            background-color: #181825;
        }
        QProgressBar::chunk {
            background-color: #89b4fa;
            border-radius: 3px;
        }
    """)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
