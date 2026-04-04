"""
database.py - Report Export and Session Management
===================================================
Handles exporting scan results to JSON and HTML reports,
and managing application session state.
"""

import json
import os
from datetime import datetime


def export_json_report(networks: list[dict], output_path: str = None) -> str:
    """
    Export the current scan results to a JSON file.

    Args:
        networks:    List of analyzed network dicts.
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
        "phishing_count": sum(1 for n in networks if n.get("status") == "PHISHING"),
        "suspicious_count": sum(1 for n in networks if n.get("status") == "SUSPICIOUS"),
        "safe_count": sum(1 for n in networks if n.get("status") == "SAFE"),
        "networks": networks,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[Database] JSON report saved: {output_path}")
    return output_path


def export_html_report(networks: list[dict], output_path: str = None) -> str:
    """
    Export the current scan results to a styled HTML report.

    Args:
        networks:    List of analyzed network dicts.
        output_path: Optional file path. Defaults to 'report_<timestamp>.html'.

    Returns:
        Path to the written file.
    """
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"report_{timestamp}.html"
        )

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    status_colors = {
        "PHISHING":   "#f38ba8",
        "SUSPICIOUS": "#f9e2af",
        "SAFE":       "#a6e3a1",
    }

    rows = ""
    for net in sorted(networks, key=lambda n: -n.get("score", 0)):
        status = net.get("status", "SAFE")
        color = status_colors.get(status, "#cdd6f4")
        reasons_html = "<br>".join(
            f"• {r}" for r in net.get("reasons", ["No issues detected."])
        )
        rows += f"""
        <tr style="background-color: {color}20; color: #cdd6f4;">
            <td><strong>{net.get('ssid','')}</strong></td>
            <td style="font-family:monospace;">{net.get('bssid','')}</td>
            <td>{net.get('signal','')} dBm</td>
            <td>{net.get('channel','')}</td>
            <td>{net.get('security','')}</td>
            <td>{net.get('vendor','Unknown')}</td>
            <td><strong>{net.get('score', 0)}</strong></td>
            <td style="color:{color}; font-weight:bold;">{status}</td>
            <td style="font-size:11px; max-width:300px;">{reasons_html}</td>
        </tr>
        """

    phishing_count  = sum(1 for n in networks if n.get("status") == "PHISHING")
    suspicious_count = sum(1 for n in networks if n.get("status") == "SUSPICIOUS")
    safe_count      = sum(1 for n in networks if n.get("status") == "SAFE")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Phishing Detector Report</title>
    <style>
        body {{
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}
        h1 {{ color: #89b4fa; border-bottom: 2px solid #313244; padding-bottom: 10px; }}
        .summary {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            background-color: #313244;
            border-radius: 8px;
            padding: 16px 24px;
            text-align: center;
            min-width: 120px;
        }}
        .stat-box .number {{
            font-size: 2em;
            font-weight: bold;
        }}
        .phishing-num {{ color: #f38ba8; }}
        .suspicious-num {{ color: #f9e2af; }}
        .safe-num {{ color: #a6e3a1; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #181825;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background-color: #313244;
            color: #89b4fa;
            padding: 10px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #313244;
            vertical-align: top;
        }}
        .footer {{
            margin-top: 20px;
            color: #6c7086;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <h1>🛡️ WiFi Phishing Detector — Scan Report</h1>
    <p>Generated: <strong>{timestamp_str}</strong></p>

    <div class="summary">
        <div class="stat-box">
            <div class="number phishing-num">{phishing_count}</div>
            <div>PHISHING</div>
        </div>
        <div class="stat-box">
            <div class="number suspicious-num">{suspicious_count}</div>
            <div>SUSPICIOUS</div>
        </div>
        <div class="stat-box">
            <div class="number safe-num">{safe_count}</div>
            <div>SAFE</div>
        </div>
        <div class="stat-box">
            <div class="number">{len(networks)}</div>
            <div>TOTAL</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Signal</th>
                <th>Channel</th>
                <th>Security</th>
                <th>Vendor</th>
                <th>Score</th>
                <th>Status</th>
                <th>Detection Reasons</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <div class="footer">
        <p>WiFi Phishing Detector v1.0 | For cybersecurity research and educational purposes only.</p>
        <p>Detection techniques: Evil Twin / Duplicate SSID, Signal Anomaly, Security Mismatch,
        Unknown Vendor, Channel Inconsistency, Open/WEP Network, Untrusted BSSID.</p>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[Database] HTML report saved: {output_path}")
    return output_path
