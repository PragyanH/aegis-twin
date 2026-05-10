"""Automated Forensic Incident Report Generator for Aegis-Twin.

This module generates a structured, professional-grade forensic report as a PDF
and optionally sends it via email.

Requirements:
    pip install reportlab

Usage:
    from forensics import generate_and_send_report
    generate_and_send_report(device_data)

device_data keys
----------------
device_id             str
device_name           str
sector                str
timestamp             str   (ISO-8601 or "%Y-%m-%d %H:%M:%S")
trust_score           float (0–100)
reconstruction_error  float (MSE)
jsd_value             float (Jensen-Shannon divergence)
baseline_features     list[float]
current_features      list[float]
packet_history        list[dict]   – each entry may contain "IAT", "size", "proto", "src", "dst"
threat_log            list[dict]   – each entry may contain "time", "msg", "level"

SMTP environment variables (optional – needed only for email delivery)
----------------------------------------------------------------------
SMTP_SERVER, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import smtplib
import statistics
import streamlit as st
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import reportlab.lib.colors as colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        NextPageTemplate,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.frames import Frame
    from reportlab.platypus.doctemplate import PageTemplate
except ImportError as exc:
    raise ImportError(
        "reportlab is required: pip install reportlab"
    ) from exc


LOGGER = logging.getLogger(__name__)

# ── Colour palette ─────────────────────────────────────────────────────────────
NAVY       = colors.HexColor("#0D2137")
BLUE_DARK  = colors.HexColor("#0B5394")
BLUE_MID   = colors.HexColor("#1A73C1")
BLUE_LIGHT = colors.HexColor("#D6E8F7")
GREY_LIGHT = colors.HexColor("#F4F6F9")
GREY_MID   = colors.HexColor("#C8CDD4")
WHITE      = colors.white
BLACK      = colors.black

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH":     colors.HexColor("#E67E22"),
    "MEDIUM":   colors.HexColor("#F1C40F"),
    "LOW":      colors.HexColor("#27AE60"),
    "UNKNOWN":  colors.HexColor("#7F8C8D"),
}
SEV_TEXT = {
    "CRITICAL": WHITE,
    "HIGH":     WHITE,
    "MEDIUM":   BLACK,
    "LOW":      WHITE,
    "UNKNOWN":  WHITE,
}

PAGE_W, PAGE_H = letter


# ── Data model ─────────────────────────────────────────────────────────────────
@dataclass
class ForensicReportData:
    device_id:            str
    device_name:          str
    sector:               str
    timestamp:            str
    trust_score:          float
    reconstruction_error: float
    jsd_value:            float
    baseline_features:    List[float]
    current_features:     List[float]
    packet_history:       List[Dict[str, Any]]
    threat_log:           List[Dict[str, Any]]

    severity:          str                    = field(default="UNKNOWN")
    attack_pattern:    str                    = field(default="UNKNOWN")
    top_anomalies:     List[Tuple[str, float]] = field(default_factory=list)
    incident_signature: str                   = field(default="")


# ── Helpers ────────────────────────────────────────────────────────────────────
def _format_timestamp(ts: str) -> str:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.datetime.strptime(ts, fmt).strftime("%d %b %Y  %H:%M:%S UTC")
        except ValueError:
            pass
    try:
        return datetime.datetime.fromisoformat(ts).strftime("%d %b %Y  %H:%M:%S UTC")
    except Exception:
        return ts


def _compute_severity(trust_score: float, jsd_value: float, mse: float) -> str:
    if trust_score < 25 or jsd_value > 0.70 or mse > 0.50:
        return "CRITICAL"
    if trust_score < 40 or jsd_value > 0.50 or mse > 0.35:
        return "HIGH"
    if trust_score < 60 or jsd_value > 0.30 or mse > 0.20:
        return "MEDIUM"
    return "LOW"


def _compute_attack_pattern(
    baseline: List[float],
    current:  List[float],
    packet_history: List[Dict[str, Any]],
) -> str:
    deltas = [abs(c - b) for b, c in zip(baseline, current)]
    if not deltas:
        return "Undetermined"

    packet_size_delta, iat_delta, entropy_delta, symmetry_delta = (deltas + [0] * 4)[:4]

    if packet_size_delta > 0.35 and entropy_delta > 0.25:
        return "Data Exfiltration — large payloads with elevated entropy"
    if iat_delta > 0.40 and symmetry_delta > 0.30:
        return "Botnet / Mass Scanning — burst traffic with irregular inter-arrival timing"
    if packet_history:
        iat_list = [e.get("IAT") for e in packet_history[:8] if isinstance(e.get("IAT"), (int, float))]
        if iat_list and statistics.pstdev(iat_list) < 0.005 and max(iat_list) < 0.05:
            return "Command & Control — consistent low-jitter beaconing"
    if entropy_delta > 0.25:
        return "Suspicious Payloads / Obfuscation — abnormally high payload entropy"
    return "Undetermined — insufficient distinguishing indicators"


def _top_anomalous_features(
    baseline: List[float],
    current:  List[float],
    feature_names: List[str],
) -> List[Tuple[str, float]]:
    if not baseline or not current or len(baseline) != len(current):
        return []
    deltas = sorted(
        [(n, abs(c - b)) for n, b, c in zip(feature_names, baseline, current)],
        key=lambda x: x[1],
        reverse=True,
    )
    return deltas[:3]


def _incident_signature(data: ForensicReportData) -> str:
    payload = (
        f"{data.device_id}|{data.timestamp}|"
        f"{data.trust_score:.3f}|{data.reconstruction_error:.6f}|{data.jsd_value:.6f}"
    )
    return hashlib.sha256(payload.encode()).hexdigest().upper()


# ── Style factory ──────────────────────────────────────────────────────────────
def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    def s(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "cover_title": s(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=26,
            textColor=WHITE,
            alignment=TA_CENTER,
            leading=32,
            spaceAfter=6,
        ),
        "cover_sub": s(
            "cover_sub",
            fontName="Helvetica",
            fontSize=11,
            textColor=colors.HexColor("#BDD7EE"),
            alignment=TA_CENTER,
            leading=16,
        ),
        "cover_meta": s(
            "cover_meta",
            fontName="Helvetica",
            fontSize=10,
            textColor=WHITE,
            alignment=TA_CENTER,
            leading=14,
        ),
        "section": s(
            "section",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=BLUE_DARK,
            spaceBefore=14,
            spaceAfter=5,
            leading=16,
            borderPad=0,
        ),
        "body": s(
            "body",
            fontName="Helvetica",
            fontSize=9.5,
            textColor=BLACK,
            leading=14,
            spaceAfter=5,
        ),
        "caption": s(
            "caption",
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            textColor=colors.HexColor("#555555"),
            leading=12,
            spaceAfter=4,
        ),
        "footer": s(
            "footer",
            fontName="Helvetica",
            fontSize=7.5,
            textColor=colors.HexColor("#888888"),
            alignment=TA_CENTER,
        ),
        "mono": s(
            "mono",
            fontName="Courier",
            fontSize=8.5,
            textColor=BLACK,
            leading=12,
            spaceAfter=4,
        ),
    }


# ── Page callbacks ─────────────────────────────────────────────────────────────
def _make_page_callbacks(report: ForensicReportData, styles: Dict):
    generated = datetime.datetime.utcnow().strftime("%d %b %Y %H:%M UTC")

    def _header_footer(canvas, doc):
        canvas.saveState()
        page_num = doc.page

        # ── Top bar ──
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H - 36, PAGE_W, 36, fill=1, stroke=0)

        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(0.55 * inch, PAGE_H - 24, "AEGIS-TWIN  //  FORENSIC INCIDENT REPORT")

        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#BDD7EE"))
        canvas.drawRightString(PAGE_W - 0.55 * inch, PAGE_H - 24, f"CONFIDENTIAL")

        # ── Severity pill ──
        sev = report.severity
        sc = SEV_COLORS.get(sev, GREY_MID)
        pill_x = PAGE_W - 1.7 * inch
        pill_y = PAGE_H - 33
        canvas.setFillColor(sc)
        canvas.roundRect(pill_x, pill_y, 1.1 * inch, 14, 4, fill=1, stroke=0)
        canvas.setFillColor(SEV_TEXT.get(sev, WHITE))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(pill_x + 0.55 * inch, pill_y + 3.5, sev)

        # ── Bottom bar ──
        canvas.setFillColor(GREY_LIGHT)
        canvas.rect(0, 0, PAGE_W, 28, fill=1, stroke=0)
        canvas.setStrokeColor(GREY_MID)
        canvas.setLineWidth(0.5)
        canvas.line(0, 28, PAGE_W, 28)

        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(0.55 * inch, 10,
                          f"Device: {report.device_name}  |  ID: {report.device_id}  |  Generated: {generated}")
        canvas.drawRightString(PAGE_W - 0.55 * inch, 10, f"Page {page_num}")

        canvas.restoreState()

    return _header_footer


# ── Table helpers ──────────────────────────────────────────────────────────────
def _kv_table(rows: List[List], col_widths, header_bg=BLUE_LIGHT, alt_bg=GREY_LIGHT):
    t = Table(rows, colWidths=col_widths)
    style_cmds = [
        ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",(0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("GRID",      (0, 0), (-1, -1), 0.35, GREY_MID),
    ]
    for i, _ in enumerate(rows):
        bg = header_bg if i == 0 else (GREY_LIGHT if i % 2 == 0 else WHITE)
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
    t.setStyle(TableStyle(style_cmds))
    return t


def _data_table(header: List[str], rows: List[List], col_widths,
                header_bg=BLUE_DARK, header_fg=WHITE):
    all_rows = [header] + rows
    t = Table(all_rows, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTNAME",       (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("BACKGROUND",     (0, 0), (-1,  0), header_bg),
        ("TEXTCOLOR",      (0, 0), (-1,  0), header_fg),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("GRID",           (0, 0), (-1, -1), 0.35, GREY_MID),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GREY_LIGHT]),
    ]
    t.setStyle(TableStyle(style_cmds))
    return t


def _section_rule(styles):
    return HRFlowable(width="100%", thickness=1, color=BLUE_LIGHT, spaceAfter=4)


# ── Cover page ─────────────────────────────────────────────────────────────────
def _cover_page(report: ForensicReportData, styles: Dict) -> List:
    story = []

    # Dark background panel
    sev = report.severity
    sc  = SEV_COLORS.get(sev, GREY_MID)

    # Big blue header block via table trick
    cover_data = [[
        Paragraph("AEGIS-TWIN", ParagraphStyle(
            "ct2", fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#BDD7EE"),
            alignment=TA_CENTER)),
    ]]
    cover_hdr = Table(cover_data, colWidths=[PAGE_W - 1.4 * inch])
    cover_hdr.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",     (0, 0), (-1, -1), 22),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    story.append(Spacer(1, 0.6 * inch))
    story.append(cover_hdr)

    title_block_data = [[
        Paragraph("Forensic Incident Report", styles["cover_title"]),
    ]]
    title_block = Table(title_block_data, colWidths=[PAGE_W - 1.4 * inch])
    title_block.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(title_block)

    # Severity badge block
    badge_data = [[
        Paragraph(
            f"<b>SEVERITY: {sev}</b>",
            ParagraphStyle(
                "badge", fontName="Helvetica-Bold", fontSize=13,
                textColor=SEV_TEXT.get(sev, WHITE), alignment=TA_CENTER,
            ),
        )
    ]]
    badge = Table(badge_data, colWidths=[PAGE_W - 1.4 * inch])
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sc),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(badge)
    story.append(Spacer(1, 0.3 * inch))

    # Meta table
    meta = [
        ["Device Name",       report.device_name,      "Device ID",     report.device_id],
        ["Sector / Zone",     report.sector,           "Timestamp",     _format_timestamp(report.timestamp)],
        ["Trust Score",       f"{report.trust_score:.1f} / 100",
         "Reconstruction MSE", f"{report.reconstruction_error:.5f}"],
        ["Jensen-Shannon Div", f"{report.jsd_value:.5f}",
         "Attack Pattern",    report.attack_pattern],
    ]
    col_w = (PAGE_W - 1.4 * inch) / 4
    meta_t = Table(meta, colWidths=[col_w * 1.0, col_w * 1.4, col_w * 1.0, col_w * 1.6])
    style_cmds = [
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.35, GREY_MID),
    ]
    for r in range(len(meta)):
        for c in (0, 2):
            style_cmds.append(("FONTNAME",   (c, r), (c, r), "Helvetica-Bold"))
            style_cmds.append(("BACKGROUND", (c, r), (c, r), BLUE_LIGHT))
        for c in (1, 3):
            style_cmds.append(("FONTNAME",   (c, r), (c, r), "Helvetica"))
            style_cmds.append(("BACKGROUND", (c, r), (c, r), WHITE))
    meta_t.setStyle(TableStyle(style_cmds))
    story.append(meta_t)
    story.append(Spacer(1, 0.25 * inch))

    # Incident signature
    sig_data = [[
        Paragraph("<b>Incident Signature (SHA-256)</b>", ParagraphStyle(
            "sh", fontName="Helvetica-Bold", fontSize=8.5, textColor=BLUE_DARK)),
        Paragraph(
            f'<font name="Courier">{report.incident_signature}</font>',
            ParagraphStyle("sv", fontName="Courier", fontSize=8, textColor=BLACK, wordWrap="CJK"),
        ),
    ]]
    sig_t = Table(sig_data, colWidths=[1.6 * inch, PAGE_W - 1.4 * inch - 1.6 * inch])
    sig_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), GREY_LIGHT),
        ("GRID",          (0, 0), (-1, -1), 0.35, GREY_MID),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(sig_t)
    story.append(PageBreak())
    return story


# ── Main render ────────────────────────────────────────────────────────────────
def _render_report_pdf(report: ForensicReportData, output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    styles = _build_styles()

    doc = SimpleDocTemplate(
        str(out),
        pagesize=letter,
        rightMargin=0.70 * inch,
        leftMargin=0.70 * inch,
        topMargin=0.80 * inch,
        bottomMargin=0.55 * inch,
        title=f"Forensic Report – {report.device_name}",
        author="Aegis-Twin Automated Analysis Engine",
        subject="Cybersecurity Incident Report",
    )

    cb = _make_page_callbacks(report, styles)
    story = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story += _cover_page(report, styles)

    # ── Helper shortcuts ───────────────────────────────────────────────────────
    def sec(title):
        story.append(Paragraph(f"▌ {title}", styles["section"]))
        story.append(_section_rule(styles))

    def body(text):
        story.append(Paragraph(text, styles["body"]))

    usable_w = PAGE_W - 1.40 * inch

    # ── 1. Executive Summary ───────────────────────────────────────────────────
    sec("1 — Executive Summary")
    sev_desc = {
        "CRITICAL": (
            "A <b>CRITICAL</b> severity anomaly was detected. The device exhibits behaviour "
            "strongly inconsistent with its established baseline and must be treated as "
            "actively compromised. Immediate isolation and incident response are required."
        ),
        "HIGH": (
            "A <b>HIGH</b> severity anomaly was detected. Significant deviations from the "
            "baseline indicate a high probability of malicious activity. Escalation and "
            "investigation are strongly recommended."
        ),
        "MEDIUM": (
            "A <b>MEDIUM</b> severity anomaly was detected. Behavioural drift is notable "
            "but may have benign explanations. Further investigation is advised."
        ),
        "LOW": (
            "A <b>LOW</b> severity anomaly was recorded. Minor deviations from baseline "
            "were observed; routine monitoring should continue."
        ),
    }.get(report.severity, "An anomaly of unknown severity was detected.")

    body(sev_desc)
    body(
        f"The Aegis-Twin digital twin engine, using an LSTM autoencoder, observed device "
        f"<b>{report.device_name}</b> (ID: <b>{report.device_id}</b>) in sector "
        f"<b>{report.sector}</b> at <b>{_format_timestamp(report.timestamp)}</b>. "
        f"The trust score fell to <b>{report.trust_score:.1f} / 100</b> and reconstruction "
        f"error rose to <b>{report.reconstruction_error:.5f}</b>, triggering automated "
        f"forensic collection and report generation."
    )
    story.append(Spacer(1, 8))

    # ── 2. Digital Twin Analysis Metrics ──────────────────────────────────────
    sec("2 — Digital Twin Analysis Metrics")
    body(
        "The following metrics were recorded by the autoencoder at the time of detection. "
        "Elevated MSE and JSD values indicate that the observed traffic distribution "
        "diverges significantly from the trained baseline."
    )

    def _trust_bar(score):
        """Return coloured label based on trust score."""
        if score >= 75:
            colour = "#27AE60"
        elif score >= 50:
            colour = "#F39C12"
        elif score >= 25:
            colour = "#E67E22"
        else:
            colour = "#C0392B"
        return f'<font color="{colour}"><b>{score:.1f}</b></font> / 100'

    metrics_rows = [
        ["Trust Score",               _trust_bar(report.trust_score),
         "Healthy range: ≥ 75"],
        ["Reconstruction Error (MSE)", f"{report.reconstruction_error:.6f}",
         "Threshold: 0.20 (medium) / 0.35 (high) / 0.50 (critical)"],
        ["Jensen-Shannon Divergence",  f"{report.jsd_value:.6f}",
         "Threshold: 0.30 / 0.50 / 0.70"],
        ["Derived Severity",           f"<b>{report.severity}</b>",
         "Computed from the above three metrics"],
    ]

    m_table = _data_table(
        ["Metric", "Observed Value", "Reference / Threshold"],
        [[Paragraph(r[0], styles["body"]),
          Paragraph(r[1], styles["body"]),
          Paragraph(r[2], styles["caption"])]
         for r in metrics_rows],
        [usable_w * 0.30, usable_w * 0.22, usable_w * 0.48],
    )
    story.append(m_table)
    story.append(Spacer(1, 8))

    # ── 3. Top Anomaly Contributing Features ───────────────────────────────────
    sec("3 — Top Anomaly Contributing Features")
    FEATURE_NAMES = ["Packet Size", "Inter-Arrival Time (IAT)", "Payload Entropy", "Flow Symmetry"]
    if report.top_anomalies:
        body(
            "The features below showed the largest deviation between the observed traffic "
            "and the trained baseline. Higher delta values indicate greater anomaly contribution."
        )
        all_features = {n: (b, c) for n, b, c in
                        zip(FEATURE_NAMES, report.baseline_features, report.current_features)}
        anom_rows = []
        for feat_name, delta in report.top_anomalies:
            b_val = all_features.get(feat_name, (0, 0))[0]
            c_val = all_features.get(feat_name, (0, 0))[1]
            direction = "↑ Increased" if c_val > b_val else "↓ Decreased"
            pct = (delta / b_val * 100) if b_val else 0
            anom_rows.append([
                feat_name,
                f"{b_val:.4f}",
                f"{c_val:.4f}",
                f"{delta:.4f}",
                f"{pct:.1f}%",
                direction,
            ])

        a_table = _data_table(
            ["Feature", "Baseline", "Observed", "Delta", "% Change", "Direction"],
            anom_rows,
            [usable_w * 0.28, usable_w * 0.12, usable_w * 0.12,
             usable_w * 0.12, usable_w * 0.12, usable_w * 0.24],
        )
        story.append(a_table)
    else:
        body("No feature drift data available — baseline or current feature vectors are missing.")
    story.append(Spacer(1, 8))

    # ── 4. Digital Evidence Snapshot ──────────────────────────────────────────
    sec("4 — Digital Evidence Snapshot")
    body("Raw feature vectors captured at detection time for archival and chain-of-custody purposes.")

    snap_rows = []
    for name, b, c in zip(FEATURE_NAMES,
                           report.baseline_features or [],
                           report.current_features or []):
        snap_rows.append([name, f"{b:.5f}", f"{c:.5f}", f"{abs(c - b):.5f}"])

    if snap_rows:
        s_table = _data_table(
            ["Feature", "Baseline", "Current", "Abs. Delta"],
            snap_rows,
            [usable_w * 0.35, usable_w * 0.22, usable_w * 0.22, usable_w * 0.21],
        )
        story.append(s_table)
    else:
        body("Feature snapshot unavailable.")
    story.append(Spacer(1, 8))

    # ── 5. Identified Attack Pattern ──────────────────────────────────────────
    sec("5 — Identified Attack Pattern")
    body(f"<b>Classified pattern:</b>  {report.attack_pattern}")
    body(
        "The classification is derived from heuristic analysis of feature deltas and "
        "packet inter-arrival timing distributions. It should be treated as an investigative "
        "hypothesis and validated by a human analyst."
    )
    story.append(Spacer(1, 8))

    # ── 6. Packet Traffic Summary ─────────────────────────────────────────────
    sec("6 — Packet Traffic Summary")
    if report.packet_history:
        shown = report.packet_history[:12]
        pkt_rows = []
        for i, pkt in enumerate(shown, 1):
            pkt_rows.append([
                str(i),
                str(pkt.get("src", "—")),
                str(pkt.get("dst", "—")),
                str(pkt.get("proto", "—")),
                f"{pkt.get('size', '—')}",
                f"{pkt.get('IAT', '—')}",
            ])
        p_table = _data_table(
            ["#", "Source", "Destination", "Protocol", "Size (B)", "IAT (s)"],
            pkt_rows,
            [usable_w * 0.06, usable_w * 0.22, usable_w * 0.22,
             usable_w * 0.12, usable_w * 0.16, usable_w * 0.22],
        )
        story.append(p_table)
        if len(report.packet_history) > 12:
            story.append(Paragraph(
                f"  …and {len(report.packet_history) - 12} additional packets not shown.",
                styles["caption"],
            ))
    else:
        body("No packet history records were present at the time of report generation.")
    story.append(Spacer(1, 8))

    # ── 7. Behavioural Timeline ────────────────────────────────────────────────
    sec("7 — Behavioural Timeline")
    if report.threat_log:
        tl_rows = []
        for entry in report.threat_log[:15]:
            ts  = entry.get("time", "—")
            msg = entry.get("msg", "(no message)")
            lvl = str(entry.get("level", "INFO")).upper()
            lvl_color = {
                "CRITICAL": "#C0392B", "HIGH": "#E67E22",
                "MEDIUM": "#F39C12",   "LOW":  "#27AE60",
                "INFO": "#2980B9",     "WARN": "#E67E22",
                "WARNING": "#E67E22",  "ERROR": "#C0392B",
            }.get(lvl, "#555555")
            tl_rows.append([
                Paragraph(str(ts), styles["caption"]),
                Paragraph(f'<font color="{lvl_color}"><b>{lvl}</b></font>', styles["body"]),
                Paragraph(msg, styles["body"]),
            ])
        tl_table = _data_table(
            ["Timestamp", "Level", "Event Description"],
            tl_rows,
            [usable_w * 0.26, usable_w * 0.12, usable_w * 0.62],
        )
        story.append(tl_table)
    else:
        body("No threat log entries were recorded at the time of report generation.")
    story.append(Spacer(1, 8))

    # ── 8. Risk Assessment ────────────────────────────────────────────────────
    sec("8 — Risk Assessment")
    risk_text = {
        "CRITICAL": (
            "This incident is rated <b>CRITICAL</b>. The combination of very low trust score, "
            "high reconstruction error, and significant distribution divergence indicates a "
            "strong likelihood of active exploitation or data exfiltration. The device "
            "should be treated as <b>fully compromised</b> until cleared by forensic investigation."
        ),
        "HIGH": (
            "This incident is rated <b>HIGH</b>. The observed metrics indicate a high probability "
            "of malicious activity. Rapid containment is advised."
        ),
        "MEDIUM": (
            "This incident is rated <b>MEDIUM</b>. Anomalies are notable but may have a benign "
            "cause (e.g. firmware update, configuration change). A prompt review is recommended."
        ),
        "LOW": (
            "This incident is rated <b>LOW</b>. Minor deviations were recorded. "
            "Standard monitoring procedures are sufficient."
        ),
    }.get(report.severity, "Risk level could not be determined.")
    body(risk_text)
    story.append(Spacer(1, 8))

    # ── 9. Recommended Remediation Actions ────────────────────────────────────
    sec("9 — Recommended Remediation Actions")
    steps = [
        ("Immediate",  "Isolate the device from the network (quarantine VLAN or physical disconnect)."),
        ("Immediate",  "Preserve volatile memory: capture a RAM image before any reboot."),
        ("Short-term", "Collect full packet captures and system/application logs for post-incident analysis."),
        ("Short-term", "Perform a firmware integrity check and compare against known-good hash."),
        ("Short-term", "Rotate all credentials, API keys, and revoke active sessions associated with the device."),
        ("Long-term",  "Update IDS/IPS signatures to detect similar behavioural patterns."),
        ("Long-term",  "Review and tighten network segmentation and access-control lists for this sector."),
        ("Long-term",  "Schedule a post-incident review and update the Aegis-Twin baseline after remediation."),
    ]
    r_table = _data_table(
        ["Priority", "Remediation Action"],
        steps,
        [usable_w * 0.16, usable_w * 0.84],
        header_bg=BLUE_MID,
    )
    story.append(r_table)
    story.append(Spacer(1, 14))

    # ── Classification footer ──────────────────────────────────────────────────
    cls_data = [[
        Paragraph(
            "CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY  |  "
            "This report was generated automatically by the Aegis-Twin Forensic Engine. "
            "All findings should be reviewed by a qualified security analyst before action is taken.",
            ParagraphStyle("clf", fontName="Helvetica-Oblique", fontSize=7.5,
                           textColor=WHITE, alignment=TA_CENTER),
        )
    ]]
    cls_t = Table(cls_data, colWidths=[usable_w])
    cls_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(cls_t)

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return str(out)


# ── Config helper ──────────────────────────────────────────────────────────────
def _get_cfg(key: str, default=None):
    """Read from st.secrets (Streamlit Cloud) or os.environ (local)."""
    try:
        if key in st.secrets:
            return st.secrets[key]
        for section in st.secrets:
            try:
                section_data = st.secrets[section]
                if hasattr(section_data, "__getitem__") and key in section_data:
                    return section_data[key]
            except Exception:
                continue
    except Exception:
        pass
    return os.environ.get(key, default)


# ── Email delivery ─────────────────────────────────────────────────────────────
def send_forensic_report(
    recipient_email: str,
    report_pdf_path: str,
    device_name: str,
    severity: str,
    trust_score: float,
    smtp_host:     Optional[str] = None,
    smtp_port:     Optional[int] = None,
    smtp_user:     Optional[str] = None,
    smtp_password: Optional[str] = None,
) -> bool:
    """Send the generated PDF report via SMTP (STARTTLS). Returns True on success."""
    smtp_host     = smtp_host     or _get_cfg("SMTP_SERVER")
    smtp_port     = smtp_port     or int(_get_cfg("SMTP_PORT", 587))
    smtp_user     = smtp_user     or _get_cfg("SMTP_EMAIL")
    smtp_password = smtp_password or _get_cfg("SMTP_PASSWORD")

    if not smtp_host or not smtp_user or not smtp_password:
        raise ValueError(
            "Incomplete SMTP configuration. "
            "Ensure SMTP_SERVER, SMTP_PORT, SMTP_EMAIL, and SMTP_PASSWORD are set."
        )

    subject = f"[Aegis-Twin] {severity} Security Alert — {device_name}"
    body = (
        f"Aegis-Twin Automated Forensic Alert\n"
        f"{'─' * 40}\n"
        f"Device      : {device_name}\n"
        f"Severity    : {severity}\n"
        f"Trust Score : {trust_score:.1f} / 100\n\n"
        f"A {severity.lower()} anomaly has been detected by the Aegis-Twin digital twin engine.\n"
        f"The attached forensic report contains a full breakdown of the observed behaviour\n"
        f"and recommended remediation actions.\n\n"
        f"This message was generated automatically. Do not reply to this address.\n"
        f"For questions, contact your SOC team.\n"
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"]    = smtp_user
    message["To"]      = recipient_email
    message.set_content(body)

    with open(report_pdf_path, "rb") as f:
        message.add_attachment(
            f.read(),
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
        LOGGER.info("Forensic report sent to %s", recipient_email)
        return True
    except Exception:
        LOGGER.exception(
            "Failed to send forensic report to %s via %s:%s",
            recipient_email, smtp_host, smtp_port,
        )
        raise


# ── Public API ─────────────────────────────────────────────────────────────────
def generate_and_send_report(
    device_data:     Dict[str, Any],
    output_dir:      Optional[str]       = None,
    recipient_email: Optional[str]       = None,
    smtp_config:     Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a professional forensic PDF report and optionally send it via email.

    Returns the path to the generated PDF file.
    """
    report = ForensicReportData(
        device_id            = str(device_data.get("device_id",            "UNKNOWN")),
        device_name          = str(device_data.get("device_name",          "UNKNOWN")),
        sector               = str(device_data.get("sector",               "UNKNOWN")),
        timestamp            = str(device_data.get("timestamp",            datetime.datetime.utcnow().isoformat())),
        trust_score          = float(device_data.get("trust_score",        0.0)),
        reconstruction_error = float(device_data.get("reconstruction_error", 0.0)),
        jsd_value            = float(device_data.get("jsd_value",          0.0)),
        baseline_features    = list(device_data.get("baseline_features",   [])),
        current_features     = list(device_data.get("current_features",    [])),
        packet_history       = list(device_data.get("packet_history",      [])),
        threat_log           = list(device_data.get("threat_log",          [])),
    )

    report.severity         = _compute_severity(report.trust_score, report.jsd_value, report.reconstruction_error)
    report.attack_pattern   = _compute_attack_pattern(
        report.baseline_features, report.current_features, report.packet_history
    )
    report.top_anomalies    = _top_anomalous_features(
        report.baseline_features,
        report.current_features,
        ["Packet Size", "Inter-Arrival Time (IAT)", "Payload Entropy", "Flow Symmetry"],
    )
    report.incident_signature = _incident_signature(report)

    now              = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name        = report.device_name.replace(" ", "_").replace("/", "_")
    output_dir       = output_dir or _get_cfg(
        "FORENSICS_OUTPUT_DIR",
        _get_cfg("AEGIS_FORENSICS_OUT", "./reports"),
    )
    output_path = os.path.join(
        output_dir,
        f"forensic_report_{report.device_id}_{safe_name}_{now}.pdf",
    )

    pdf_path = _render_report_pdf(report, output_path)
    LOGGER.info("Forensic report written to %s", pdf_path)

    recipient_email = recipient_email or _get_cfg("AEGIS_ALERT_RECIPIENT")
    if recipient_email:
        send_forensic_report(
            recipient_email = recipient_email,
            report_pdf_path = pdf_path,
            device_name     = report.device_name,
            severity        = report.severity,
            trust_score     = report.trust_score,
            smtp_host       = (smtp_config or {}).get("host"),
            smtp_port       = (smtp_config or {}).get("port"),
            smtp_user       = (smtp_config or {}).get("user"),
            smtp_password   = (smtp_config or {}).get("password"),
        )
    else:
        LOGGER.warning(
            "No recipient email configured (AEGIS_ALERT_RECIPIENT unset). "
            "PDF saved at: %s",
            pdf_path,
        )

    return pdf_path