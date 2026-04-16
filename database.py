"""
database.py - Report Export and Session Management
===================================================
Handles exporting scan results to JSON and PDF reports,
and managing application session state.
"""

import json
import os
from datetime import datetime

# ── reportlab imports ────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable


# ── Color palette (Catppuccin Mocha – matches the PyQt5 GUI) ────────────────
C_BASE      = colors.HexColor("#1e1e2e")
C_MANTLE    = colors.HexColor("#181825")
C_SURFACE0  = colors.HexColor("#313244")
C_SURFACE1  = colors.HexColor("#45475a")
C_TEXT      = colors.HexColor("#cdd6f4")
C_SUBTEXT   = colors.HexColor("#a6adc8")
C_BLUE      = colors.HexColor("#89b4fa")
C_LAVENDER  = colors.HexColor("#b4befe")
C_GREEN     = colors.HexColor("#a6e3a1")
C_YELLOW    = colors.HexColor("#f9e2af")
C_RED       = colors.HexColor("#f38ba8")
C_TEAL      = colors.HexColor("#94e2d5")
C_MAUVE     = colors.HexColor("#cba6f7")

STATUS_COLORS = {
    "PHISHING":   C_RED,
    "SUSPICIOUS": C_YELLOW,
    "SAFE":       C_GREEN,
}
STATUS_BG = {
    "PHISHING":   colors.HexColor("#2e1020"),
    "SUSPICIOUS": colors.HexColor("#2b2510"),
    "SAFE":       colors.HexColor("#0e2218"),
}


# ─────────────────────────────────────────────────────────────────────────────
# JSON export (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def export_json_report(networks: list[dict], output_path: str = None) -> str:
    """
    Export the current scan results to a JSON file.

    Args:
        networks: List of analyzed network dicts.
        output_path: Optional file path. Defaults to 'report_<timestamp>.json'.

    Returns:
        Path to the written file.
    """
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"report_{timestamp}.json"
        )

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_networks": len(networks),
        "phishing_count":  sum(1 for n in networks if n.get("status") == "PHISHING"),
        "suspicious_count": sum(1 for n in networks if n.get("status") == "SUSPICIOUS"),
        "safe_count":      sum(1 for n in networks if n.get("status") == "SAFE"),
        "networks": networks,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[Database] JSON report saved: {output_path}")
    return output_path


# ─────────────────────────────────────────────────────────────────────────────
# PDF export (replaces HTML)
# ─────────────────────────────────────────────────────────────────────────────

def export_pdf_report(networks: list[dict], output_path: str = None) -> str:
    """
    Export the current scan results to a styled PDF report.

    Args:
        networks: List of analyzed network dicts.
        output_path: Optional file path. Defaults to 'report_<timestamp>.pdf'.

    Returns:
        Path to the written file.
    """
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"report_{timestamp}.pdf"
        )

    if not output_path.endswith(".pdf"):
        output_path += ".pdf"

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="WiFi Phishing Detector – Scan Report",
        author="WiFi Phishing Detector v1.0",
    )

    styles = getSampleStyleSheet()

    # ── Custom paragraph styles ──────────────────────────────────────────────
    s_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=C_BLUE,
        fontName="Helvetica-Bold",
        spaceAfter=2 * mm,
        alignment=TA_LEFT,
    )
    s_subtitle = ParagraphStyle(
        "ReportSubtitle",
        fontSize=9,
        textColor=C_SUBTEXT,
        fontName="Helvetica",
        spaceAfter=4 * mm,
        alignment=TA_LEFT,
    )
    s_section = ParagraphStyle(
        "SectionHead",
        fontSize=11,
        textColor=C_LAVENDER,
        fontName="Helvetica-Bold",
        spaceBefore=5 * mm,
        spaceAfter=2 * mm,
    )
    s_cell_bold = ParagraphStyle(
        "CellBold",
        fontSize=8,
        fontName="Helvetica-Bold",
        textColor=C_TEXT,
        leading=10,
    )
    s_cell = ParagraphStyle(
        "Cell",
        fontSize=7.5,
        fontName="Helvetica",
        textColor=C_TEXT,
        leading=10,
    )
    s_cell_mono = ParagraphStyle(
        "CellMono",
        fontSize=7,
        fontName="Courier",
        textColor=C_SUBTEXT,
        leading=10,
    )
    s_reason = ParagraphStyle(
        "Reason",
        fontSize=7,
        fontName="Helvetica",
        textColor=C_SUBTEXT,
        leading=9,
    )
    s_footer = ParagraphStyle(
        "Footer",
        fontSize=7.5,
        textColor=C_SUBTEXT,
        fontName="Helvetica",
        alignment=TA_CENTER,
    )

    # ── Counts ───────────────────────────────────────────────────────────────
    phishing_count   = sum(1 for n in networks if n.get("status") == "PHISHING")
    suspicious_count = sum(1 for n in networks if n.get("status") == "SUSPICIOUS")
    safe_count       = sum(1 for n in networks if n.get("status") == "SAFE")
    total            = len(networks)
    timestamp_str    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    story = []

    # ── Header ───────────────────────────────────────────────────────────────
    story.append(Paragraph("🛡  WiFi Phishing Detector", s_title))
    story.append(Paragraph(
        f"Evil Twin Attack Detection  ·  Scan Report  ·  Generated: <b>{timestamp_str}</b>",
        s_subtitle
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C_SURFACE1, spaceAfter=4 * mm))

    # ── Summary stat boxes ───────────────────────────────────────────────────
    def stat_cell(label: str, value: int, fg: colors.HexColor, hex_str: str) -> Table:
        t = Table(
            [[Paragraph(f'<font color="{hex_str}"><b>{value}</b></font>', ParagraphStyle(
                "Num", fontSize=22, fontName="Helvetica-Bold", alignment=TA_CENTER,
                textColor=fg, leading=26,
            ))],
             [Paragraph(label, ParagraphStyle(
                "StatLbl", fontSize=8, fontName="Helvetica", alignment=TA_CENTER,
                textColor=C_SUBTEXT, leading=10,
             ))]],
            colWidths=[35 * mm],
        )
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), C_SURFACE0),
            ("ROUNDEDCORNERS", [4]),
            ("BOX",          (0, 0), (-1, -1), 0.5, C_SURFACE1),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ]))
        return t

    summary_row = [[
        stat_cell("PHISHING",   phishing_count,   C_RED,    "#f38ba8"),
        stat_cell("SUSPICIOUS", suspicious_count, C_YELLOW, "#f9e2af"),
        stat_cell("SAFE",       safe_count,       C_GREEN,  "#a6e3a1"),
        stat_cell("TOTAL",      total,            C_BLUE,   "#89b4fa"),
    ]]
    summary_table = Table(summary_row, colWidths=[40 * mm] * 4, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 5 * mm))

    # ── Risk score legend bar ────────────────────────────────────────────────
    legend_data = [[
        Paragraph('<font color="#f38ba8">● PHISHING  ≥50 pts</font>', ParagraphStyle(
            "Leg", fontSize=8, fontName="Helvetica", textColor=C_RED)),
        Paragraph('<font color="#f9e2af">● SUSPICIOUS  25–49 pts</font>', ParagraphStyle(
            "Leg", fontSize=8, fontName="Helvetica", textColor=C_YELLOW)),
        Paragraph('<font color="#a6e3a1">● SAFE  &lt;25 pts</font>', ParagraphStyle(
            "Leg", fontSize=8, fontName="Helvetica", textColor=C_GREEN)),
    ]]
    legend = Table(legend_data, colWidths=[55 * mm, 60 * mm, 55 * mm])
    legend.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_MANTLE),
        ("BOX",        (0, 0), (-1, -1), 0.5, C_SURFACE1),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(legend)
    story.append(Spacer(1, 5 * mm))

    # ── Networks table ───────────────────────────────────────────────────────
    story.append(Paragraph("Detected Networks", s_section))

    W = A4[0] - 30 * mm  # usable width
    col_widths = [
        35 * mm,   # SSID
        30 * mm,   # BSSID
        14 * mm,   # Signal
        10 * mm,   # Ch
        22 * mm,   # Security
        22 * mm,   # Vendor
        12 * mm,   # Score
        17 * mm,   # Status
        W - 162 * mm,  # Reasons (remainder)
    ]

    header_style = ParagraphStyle(
        "TH", fontSize=8, fontName="Helvetica-Bold",
        textColor=C_BLUE, leading=10, alignment=TA_LEFT
    )
    headers = [
        Paragraph(h, header_style)
        for h in ["SSID", "BSSID", "Signal", "Ch", "Security",
                  "Vendor", "Score", "Status", "Detection Reasons"]
    ]

    table_data = [headers]
    table_style_cmds = [
        # Header row
        ("BACKGROUND",    (0, 0), (-1, 0), C_SURFACE0),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_MANTLE, C_BASE]),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, C_SURFACE1),
        ("LINEBELOW",     (0, 1), (-1, -1), 0.3, C_SURFACE0),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_SURFACE1),
    ]

    for i, net in enumerate(sorted(networks, key=lambda n: -n.get("score", 0))):
        row_num = i + 1
        status = net.get("status", "SAFE")
        fg     = STATUS_COLORS.get(status, C_TEXT)
        bg     = STATUS_BG.get(status, C_BASE)

        reasons_text = "\n".join(
            f"• {r}" for r in net.get("reasons", ["No issues detected."])
        )

        def cp(txt, bold=False, mono=False, color=C_TEXT):
            st = ParagraphStyle(
                f"c_{i}_{id(txt)}", fontSize=7.5 if not mono else 7,
                fontName=("Courier" if mono else ("Helvetica-Bold" if bold else "Helvetica")),
                textColor=color, leading=10,
            )
            return Paragraph(str(txt), st)

        row = [
            cp(net.get("ssid", ""), bold=True),
            cp(net.get("bssid", ""), mono=True),
            cp(f"{net.get('signal', '')} dBm"),
            cp(str(net.get("channel", ""))),
            cp(net.get("security", "")),
            cp(net.get("vendor", "Unknown")),
            cp(str(net.get("score", 0)), bold=True, color=fg),
            Paragraph(
                f'<b>{status}</b>',
                ParagraphStyle(f"st_{i}", fontSize=7.5, fontName="Helvetica-Bold",
                               textColor=fg, leading=10)
            ),
            Paragraph(
                reasons_text.replace("\n", "<br/>"),
                ParagraphStyle(f"rs_{i}", fontSize=6.5, fontName="Helvetica",
                               textColor=C_SUBTEXT, leading=9)
            ),
        ]
        table_data.append(row)

        # Tint the status row background
        if status != "SAFE":
            table_style_cmds.append(
                ("BACKGROUND", (0, row_num), (-1, row_num), bg)
            )

    net_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    net_table.setStyle(TableStyle(table_style_cmds))
    story.append(net_table)

    # ── Detection technique key ──────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_SURFACE1, spaceAfter=3 * mm))
    story.append(Paragraph("Detection Techniques & Scoring", s_section))

    scoring = [
        ["Duplicate SSID / Evil Twin",   "+40 pts", "Same SSID with multiple BSSIDs — strong Evil Twin indicator"],
        ["Security Protocol Downgrade",  "+30 pts", "Known WPA2 network appearing as Open or WPA"],
        ["Untrusted BSSID",              "+25 pts", "BSSID not matching any known trusted record"],
        ["Unknown / Spoofed Vendor",     "+20 pts", "OUI not in database or locally-administered MAC"],
        ["WEP Encryption",               "+20 pts", "WEP was broken in 2001; may indicate rogue AP"],
        ["Open Network",                 "+15 pts", "No encryption — trivial to intercept traffic"],
        ["Channel Mismatch",             "+10 pts", "Network appearing on unexpected channel"],
        ["Signal Strength Anomaly",      "+10 pts", "One instance ≥15 dBm stronger than others"],
    ]

    scoring_header = [
        Paragraph("Detection Check",      header_style),
        Paragraph("Points",               header_style),
        Paragraph("Description",          header_style),
    ]
    scoring_data = [scoring_header] + [
        [
            Paragraph(row[0], ParagraphStyle("sc", fontSize=7.5, fontName="Helvetica-Bold",
                                             textColor=C_TEXT, leading=10)),
            Paragraph(row[1], ParagraphStyle("scp", fontSize=7.5, fontName="Helvetica-Bold",
                                             textColor=C_YELLOW, leading=10)),
            Paragraph(row[2], ParagraphStyle("scd", fontSize=7.5, fontName="Helvetica",
                                             textColor=C_SUBTEXT, leading=10)),
        ]
        for row in scoring
    ]

    scoring_table = Table(scoring_data, colWidths=[55 * mm, 20 * mm, W - 75 * mm])
    scoring_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_SURFACE0),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_MANTLE, C_BASE]),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, C_SURFACE1),
        ("LINEBELOW",     (0, 1), (-1, -1), 0.3, C_SURFACE0),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_SURFACE1),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(scoring_table)

    # ── Footer ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_SURFACE1, spaceAfter=3 * mm))
    story.append(Paragraph(
        "WiFi Phishing Detector v1.0  ·  For cybersecurity research and educational purposes only.  "
        "Do not use to attack or interfere with networks you do not own.",
        s_footer
    ))

    # ── Page background via canvas callback ──────────────────────────────────
    def dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BASE)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    print(f"[Database] PDF report saved: {output_path}")
    return output_path


# ── Backward-compat alias so old code calling export_html_report still works ─
def export_html_report(networks: list[dict], output_path: str = None) -> str:
    """Deprecated: redirects to export_pdf_report."""
    if output_path and output_path.endswith(".html"):
        output_path = output_path[:-5] + ".pdf"
    return export_pdf_report(networks, output_path)
