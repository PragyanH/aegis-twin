"""Automated Forensic Incident Report Generator for Aegis-Twin.

This module generates a structured forensic report as a PDF and sends it over email.

Requirements:
- reportlab

Usage:
    from forensics import generate_and_send_report
    generate_and_send_report(device_data)

The caller is responsible for providing a `device_data` dict with the following keys:
- device_id
- device_name
- sector
- timestamp
- trust_score
- reconstruction_error
- jsd_value
- baseline_features
- current_features
- packet_history
- threat_log

The recipient email address can be provided via the `recipient_email` argument or via environment variables.

SMTP Configuration (environment variables):
- SMTP_SERVER
- SMTP_PORT
- SMTP_EMAIL
- SMTP_PASSWORD
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import statistics
import streamlit as st
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import reportlab.lib.colors as colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (  # type: ignore[import]
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError as exc:
    raise ImportError(
        "Missing dependency: reportlab is required for PDF report generation. "
        "Install it with `pip install reportlab`."
    ) from exc

import smtplib


LOGGER = logging.getLogger(__name__)


@dataclass
class ForensicReportData:
    device_id: str
    device_name: str
    sector: str
    timestamp: str
    trust_score: float
    reconstruction_error: float
    jsd_value: float
    baseline_features: List[float]
    current_features: List[float]
    packet_history: List[Dict[str, Any]]
    threat_log: List[Dict[str, Any]]

    # Fields that are computed/derived
    severity: str = field(default="UNKNOWN")
    attack_pattern: str = field(default="UNKNOWN")
    top_anomalies: List[Tuple[str, float]] = field(default_factory=list)
    incident_signature: str = field(default="")


def _format_timestamp(ts: str) -> str:
    """Normalize timestamps into a human-readable format."""
    try:
        dt = datetime.datetime.fromisoformat(ts)
    except Exception:
        try:
            dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _compute_severity(trust_score: float, jsd_value: float, mse: float) -> str:
    """Determine severity level based on scoring metrics."""
    if trust_score < 25 or jsd_value > 0.7 or mse > 0.5:
        return "CRITICAL"
    if trust_score < 40 or jsd_value > 0.5 or mse > 0.35:
        return "HIGH"
    if trust_score < 60 or jsd_value > 0.3 or mse > 0.2:
        return "MEDIUM"
    return "LOW"


def _compute_attack_pattern(
    baseline: List[float],
    current: List[float],
    packet_history: List[Dict[str, Any]],
) -> str:
    """Guess a likely attack pattern based on simple heuristics."""

    deltas = [abs(c - b) for b, c in zip(baseline, current)]
    if not deltas:
        return "Unknown"

    packet_size_delta, iat_delta, entropy_delta, symmetry_delta = deltas

    if packet_size_delta > 0.35 and entropy_delta > 0.25:
        return "Data Exfiltration (large payloads + high entropy)"

    if iat_delta > 0.4 and symmetry_delta > 0.3:
        return "Botnet / Mass Scanning (burst traffic with irregular timing)"

    if packet_history:
        recent = packet_history[:8]
        iat_list = [entry.get("IAT") for entry in recent if isinstance(entry.get("IAT"), (int, float))]
        if iat_list and statistics.pstdev(iat_list) < 0.005 and max(iat_list) < 0.05:
            return "Command & Control (consistent beaconing)"

    if entropy_delta > 0.25:
        return "Suspicious Payloads / Obfuscation"

    return "Unknown"


def _top_anomalous_features(
    baseline: List[float], current: List[float], feature_names: List[str]
) -> List[Tuple[str, float]]:
    """Return the top anomaly contributing features sorted by delta."""
    if not baseline or not current or len(baseline) != len(current):
        return []

    deltas = [(name, abs(c - b)) for name, b, c in zip(feature_names, baseline, current)]
    deltas.sort(key=lambda x: x[1], reverse=True)
    return deltas[:3]


def _incident_signature(data: ForensicReportData) -> str:
    """Generate a deterministic signature for this incident."""
    payload = (
        f"{data.device_id}|{data.timestamp}|{data.trust_score:.3f}|{data.reconstruction_error:.6f}|{data.jsd_value:.6f}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _render_report_pdf(report: ForensicReportData, output_path: str) -> str:
    """Render a forensic PDF report and return the file path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=inch * 0.7,
        leftMargin=inch * 0.7,
        topMargin=inch * 0.7,
        bottomMargin=inch * 0.7,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="SectionHeader",
            parent=styles["Heading2"],
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor("#0B5394"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["BodyText"],
            spaceAfter=6,
            leading=14,
        )
    )

    story = []

    story.append(Paragraph("Incident Report", styles["Title"]))
    story.append(Spacer(1, 8))

    info_table_data = [
        ["Device ID:", report.device_id, "Sector:", report.sector],
        ["Device Name:", report.device_name, "Timestamp:", _format_timestamp(report.timestamp)],
        ["Incident Signature:", report.incident_signature, "Severity:", report.severity],
        ["Trust Score:", f"{report.trust_score:.1f}%", "Attack Pattern:", report.attack_pattern],
    ]

    info_table = Table(info_table_data, colWidths=[90, 160, 90, 160])
    info_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F2F2")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(info_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    story.append(
        Paragraph(
            (
                "A critical anomaly was detected on the digital twin for the device. "
                "The system automatically generated this report to capture a snapshot of the observed behavior, "
                "analysis results, and recommended next steps for investigation and remediation."
            ),
            styles["Body"],
        )
    )

    story.append(Paragraph("Digital Twin Analysis", styles["SectionHeader"]))
    story.append(
        Paragraph(
            (
                "The LSTM autoencoder measured the reconstruction error and compared the incoming traffic "
                "features to the expected baseline. These discrepancies were used to compute a Trust Score "
                "and to highlight the most anomalous data attributes."
            ),
            styles["Body"],
        )
    )

    metrics_table_data = [
        ["Metric", "Value"],
        ["Trust Score", f"{report.trust_score:.1f}%"],
        ["Reconstruction Error (MSE)", f"{report.reconstruction_error:.5f}"],
        ["Jensen-Shannon Divergence", f"{report.jsd_value:.5f}"],
    ]
    metrics_table = Table(metrics_table_data, colWidths=[200, 220])
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9ead3")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(metrics_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Top Anomaly Contributing Features", styles["SectionHeader"]))
    if report.top_anomalies:
        anomalies_data = [["Feature", "Delta"]] + [[k, f"{v:.3f}"] for k, v in report.top_anomalies]
        anomalies_table = Table(anomalies_data, colWidths=[200, 220])
        anomalies_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4cccc")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        story.append(anomalies_table)
    else:
        story.append(
            Paragraph(
                "No feature drift could be computed due to missing or invalid baseline/current feature vectors.",
                styles["Body"],
            )
        )

    story.append(Spacer(1, 10))
    story.append(Paragraph("Behavioral Timeline", styles["SectionHeader"]))
    if report.threat_log:
        for entry in report.threat_log[:10]:
            timestamp = entry.get("time", "?")
            msg = entry.get("msg", "(no message)")
            story.append(Paragraph(f"<b>{timestamp}</b>: {msg}", styles["Body"]))
    else:
        story.append(Paragraph("No threat log entries were present at the time of report generation.", styles["Body"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Possible Attack Pattern", styles["SectionHeader"]))
    story.append(Paragraph(report.attack_pattern, styles["Body"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Risk Assessment", styles["SectionHeader"]))
    story.append(
        Paragraph(
            (
                "Based on the observed anomaly magnitude and the estimated severity, this incident is considered "
                f"<b>{report.severity}</b>. The device should be treated as compromised until a full investigation confirms otherwise."
            ),
            styles["Body"],
        )
    )

    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommended Remediation Actions", styles["SectionHeader"]))
    remediation_steps = [
        "Isolate the device from the network (quarantine).",
        "Collect full packet captures and system logs for post-incident analysis.",
        "Perform a firmware integrity check and verify configuration drift.",
        "Rotate credentials and revoke all active sessions for the device.",
        "Update IDS/IPS rules to detect similar behavior in the future.",
    ]
    for step in remediation_steps:
        story.append(Paragraph(f"• {step}", styles["Body"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Digital Evidence Snapshot", styles["SectionHeader"]))
    snap_data = [
        ["Baseline Features", "Current Features"],
        [
            ", ".join([f"{v:.3f}" for v in report.baseline_features]),
            ", ".join([f"{v:.3f}" for v in report.current_features]),
        ],
    ]
    snap_table = Table(snap_data, colWidths=[260, 260])
    snap_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9ead3")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(snap_table)

    story.append(Spacer(1, 10))
    story.append(Paragraph("Incident Signature", styles["SectionHeader"]))
    story.append(Paragraph(report.incident_signature, styles["Body"]))

    doc.build(story)

    return str(output_path)


def _get_cfg(key, default=None):
    """Read config from st.secrets (Streamlit Cloud) or os.environ (local)."""
    try:
        # Pass 1: flat key lookup
        if key in st.secrets:
            return st.secrets[key]
        # Pass 2: search inside nested sections e.g. [smtp], [aegis], [forensics]
        for section in st.secrets:
            try:
                section_data = st.secrets[section]
                if hasattr(section_data, "__getitem__") and key in section_data:
                    return section_data[key]
            except Exception:
                continue
    except Exception:
        pass
    # Pass 3: fall back to environment variable (local .env via load_dotenv)
    return os.environ.get(key, default)


def send_forensic_report(
    recipient_email: str,
    report_pdf_path: str,
    device_name: str,
    severity: str,
    trust_score: float,
    smtp_host: Optional[str] = None,
    smtp_port: Optional[int] = None,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
) -> bool:
    """Send the generated PDF report via SMTP (TLS). Returns True on success."""
    smtp_host     = smtp_host     or _get_cfg("SMTP_SERVER")
    smtp_port     = smtp_port     or int(_get_cfg("SMTP_PORT", 587))
    smtp_user     = smtp_user     or _get_cfg("SMTP_EMAIL")
    smtp_password = smtp_password or _get_cfg("SMTP_PASSWORD")

    if not smtp_host or not smtp_user or not smtp_password:
        raise ValueError(
            "SMTP configuration is incomplete. "
            "Set SMTP_SERVER, SMTP_PORT, SMTP_EMAIL, and SMTP_PASSWORD."
        )

    subject = "🚨 Aegis-Twin Critical Security Alert"
    body = (
        f"Device: {device_name}\n"
        f"Severity: {severity}\n"
        f"Trust Score: {trust_score:.1f}%\n\n"
        "A critical anomaly has been detected by the Aegis-Twin digital twin engine. "
        "The attached forensic report contains a detailed breakdown of the observed behavior "
        "and suggested remediation actions."
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_user
    message["To"] = recipient_email
    message.set_content(body)

    with open(report_pdf_path, "rb") as f:
        report_bytes = f.read()

    message.add_attachment(
        report_bytes,
        maintype="application",
        subtype="pdf",
        filename=os.path.basename(report_pdf_path),
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(message)
        return True
    except Exception as exc:
        LOGGER.exception(
            "Failed to send forensic report email to %s via %s:%s",
            recipient_email,
            smtp_host,
            smtp_port,
        )
        raise


def generate_and_send_report(
    device_data: Dict[str, Any],
    output_dir: Optional[str] = None,
    recipient_email: Optional[str] = None,
    smtp_config: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a forensic report PDF and send it via email.

    Returns the path to the generated PDF.
    """
    report = ForensicReportData(
        device_id=str(device_data.get("device_id", "UNKNOWN")),
        device_name=str(device_data.get("device_name", "UNKNOWN")),
        sector=str(device_data.get("sector", "UNKNOWN")),
        timestamp=str(device_data.get("timestamp", datetime.datetime.utcnow().isoformat())),
        trust_score=float(device_data.get("trust_score", 0.0)),
        reconstruction_error=float(device_data.get("reconstruction_error", 0.0)),
        jsd_value=float(device_data.get("jsd_value", 0.0)),
        baseline_features=list(device_data.get("baseline_features", [])),
        current_features=list(device_data.get("current_features", [])),
        packet_history=list(device_data.get("packet_history", [])),
        threat_log=list(device_data.get("threat_log", [])),
    )

    report.severity = _compute_severity(report.trust_score, report.jsd_value, report.reconstruction_error)
    report.attack_pattern = _compute_attack_pattern(
        report.baseline_features, report.current_features, report.packet_history
    )
    report.top_anomalies = _top_anomalous_features(
        report.baseline_features,
        report.current_features,
        ["Packet Size", "IAT", "Entropy", "Symmetry"],
    )
    report.incident_signature = _incident_signature(report)

    now = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_device_name = report.device_name.replace(" ", "_").replace("/", "_")
    output_dir = output_dir or _get_cfg(
        "FORENSICS_OUTPUT_DIR",
        _get_cfg("AEGIS_FORENSICS_OUT", "./reports"),
    )
    output_path = os.path.join(
        output_dir,
        f"forensic_report_{report.device_id}_{safe_device_name}_{now}.pdf",
    )

    pdf_path = _render_report_pdf(report, output_path)

    recipient_email = recipient_email or _get_cfg("AEGIS_ALERT_RECIPIENT")
    if recipient_email:
        send_forensic_report(
            recipient_email=recipient_email,
            report_pdf_path=pdf_path,
            device_name=report.device_name,
            severity=report.severity,
            trust_score=report.trust_score,
            smtp_host=(smtp_config or {}).get("host"),
            smtp_port=(smtp_config or {}).get("port"),
            smtp_user=(smtp_config or {}).get("user"),
            smtp_password=(smtp_config or {}).get("password"),
        )
    else:
        LOGGER.warning(
            "No recipient email provided for forensic report (AEGIS_ALERT_RECIPIENT unset). PDF generated at %s",
            pdf_path,
        )

    return pdf_path