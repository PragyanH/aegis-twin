"""hardware_dashboard.py — Live hardware device dashboard for Aegis-Twin.

Mirrors dashboard.py but drives inference from live Scapy features instead of
manual sliders.  No attack simulation, no manual traffic injection.

Key differences vs dashboard.py
---------------------------------
- Features come from sniffer.get_features(mac) — live, auto-updating.
- A st.metric() row shows the four raw normalized feature values.
- A "📡 Calibrate Baseline" button runs calibrate_baseline() in a thread
  and shows a 30-second st.status() progress banner.
- Scan is always active; the page re-runs every 1.5 s via time.sleep + st.rerun().
- Sidebar shows device info, MAC, interface, live packet count, and nav buttons.
- Trust score reaches 100 when features match baseline; real deviations lower it.
"""

from __future__ import annotations

import datetime
import threading
import time

import numpy as np
import plotly.graph_objects as go
import streamlit as st
import torch

from engine import calculate_jsd, calculate_trust_score
from hardware_registry import CALIBRATION_WINDOW, HARDWARE_REGISTRY, calibrate_baseline
from sniffer import get_features, get_packet_count
from ui import NEON_BLUE, NEON_GREEN, NEON_RED, glass_card, section_header

# ---------------------------------------------------------------------------
# Re-use chart builders from dashboard.py (copy to stay self-contained)
# ---------------------------------------------------------------------------

def _gauge_chart(trust_score: float, status_color: str) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=trust_score,
        number={"font": {"color": "white", "size": 75}, "suffix": "%"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "white"},
            "bar": {"color": status_color, "thickness": 0.8},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
            "steps": [
                {"range": [0,  50], "color": "rgba(255,0,127,0.15)"},
                {"range": [50, 100], "color": "rgba(0,255,242,0.15)"},
            ],
            "threshold": {"line": {"color": "white", "width": 3}, "thickness": 0.9, "value": trust_score},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "white", "family": "Source Code Pro"},
        height=260, margin=dict(l=20, r=20, t=10, b=10),
    )
    return fig


def _sparkline_chart(jsd_history: list[float]) -> go.Figure:
    fig = go.Figure(go.Scatter(
        y=jsd_history, mode="lines",
        line={"color": NEON_GREEN, "width": 3, "shape": "spline"},
        fill="tozeroy", fillcolor="rgba(0,255,242,0.15)",
    ))
    fig.update_layout(
        height=50, margin={"l": 0, "r": 0, "t": 0, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False}, yaxis={"visible": False, "range": [0, 1]},
    )
    return fig


def _radar_chart(
    dev_baseline: list[float],
    current_features: np.ndarray,
    categories: list[str],
    status_color: str,
    is_safe: bool,
) -> go.Figure:
    fill = "rgba(0, 255, 136, 0.3)" if is_safe else "rgba(255, 45, 85, 0.3)"
    fig  = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=dev_baseline, theta=categories, fill="toself",
        name="Baseline", line_color=NEON_BLUE, fillcolor="rgba(0,207,255,0.2)",
    ))
    fig.add_trace(go.Scatterpolar(
        r=list(current_features), theta=categories, fill="toself",
        name="Live Traffic", line_color=status_color, fillcolor=fill,
    ))
    fig.update_layout(
        polar={
            "radialaxis": {"visible": True, "range": [0, 1], "gridcolor": "rgba(255,255,255,0.1)"},
            "angularaxis": {"gridcolor": "rgba(255,255,255,0.1)"},
            "bgcolor": "rgba(0,0,0,0)",
        },
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "white"}, height=360,
        margin={"l": 40, "r": 40, "t": 10, "b": 10}, hovermode="closest",
    )
    return fig


def _pulse_chart(pulse_mse: list[float], pulse_jsd: list[float]) -> go.Figure:
    fig = go.Figure()
    fig.add_hline(y=0.15, line_dash="dot", line_color="white", line_width=1,
                  annotation_text="ALERT BOUNDARY", annotation_position="top left",
                  annotation_font={"size": 10, "color": "white"})
    fig.add_trace(go.Scatter(y=pulse_mse, name="MSE",
                             line={"color": "#ff007f", "width": 3}, mode="lines",
                             hovertemplate="MSE: %{y:.4f}<extra></extra>"))
    fig.add_trace(go.Scatter(y=pulse_jsd, name="JSD",
                             line={"color": "#00fff2", "width": 3}, mode="lines",
                             hovertemplate="JSD: %{y:.4f}<extra></extra>"))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "white", "family": "Source Code Pro"},
        height=360, margin={"l": 30, "r": 30, "t": 10, "b": 10},
        xaxis={"showgrid": True, "gridcolor": "rgba(0,255,242,0.05)",
               "zeroline": False, "showticklabels": False},
        yaxis={"showgrid": True, "gridcolor": "rgba(0,255,242,0.05)", "zeroline": False},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
        hovermode="x unified",
    )
    return fig


# ---------------------------------------------------------------------------
# Status resolver (mirror of dashboard.py)
# ---------------------------------------------------------------------------

def _resolve_status(trust_score: float):
    is_safe     = trust_score >= 50
    is_critical = trust_score < 30

    if is_safe:
        return True, False, NEON_GREEN, "neon-safe", f"<span style='color:{NEON_GREEN};'>● ONLINE</span>"
    if is_critical:
        return False, True, NEON_RED, "neon-compromised pulse-red", (
            f"<span style='color:{NEON_RED};animation:blinker 1s linear infinite;'>● CRITICAL</span>"
        )
    return False, False, "#ffb300", "neon-compromised", "<span style='color:#ffb300;'>● COMPROMISED</span>"


# ---------------------------------------------------------------------------
# Hardware session-state helpers
# ---------------------------------------------------------------------------

_HW_JSD_BUF     = "hw_jsd_history"
_HW_MSE_BUF     = "hw_pulse_mse_history"
_HW_JSD_PUL_BUF = "hw_pulse_jsd_history"
_HW_PKT_HIS     = "hw_packet_history"
_HW_THREAT_LOG  = "hw_threat_log"
_HW_RE_HIST     = "hw_reconstruction_errors_history"
_HW_MATH_MODE   = "hw_math_mode_active"


def _init_hw_session() -> None:
    """Ensure all hardware-specific session-state keys exist."""
    import pandas as pd
    defaults = {
        _HW_JSD_BUF:     [0.0] * 10,
        _HW_MSE_BUF:     [0.0] * 30,
        _HW_JSD_PUL_BUF: [0.0] * 30,
        _HW_PKT_HIS:     pd.DataFrame(columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"]),
        _HW_THREAT_LOG:  [],
        _HW_RE_HIST:     [[0.0] * 20 for _ in range(4)],
        _HW_MATH_MODE:   False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ---------------------------------------------------------------------------
# Calibration helper (runs in a background thread)
# ---------------------------------------------------------------------------

def _start_calibration_thread(mac: str) -> None:
    def _run() -> None:
        calibrate_baseline(mac)
        st.session_state["hw_calibrating"] = False

    t = threading.Thread(target=_run, name="aegis-calibration", daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_hw_sidebar(hw_id: str, device_info: dict, mac: str, iface: str) -> None:
    with st.sidebar:
        st.markdown(
            f"<h1 style='text-align:center;color:{NEON_BLUE} !important;'>🛡️ Aegis Control</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<p style='text-align:center;color:#aaa;margin-top:-10px;'>"
            f"Logged in as <strong>{st.session_state.get('user_email', 'Unknown')}</strong></p>",
            unsafe_allow_html=True,
        )

        if st.button("Log out", width="stretch", key="hw_logout"):
            st.session_state.authenticated = False
            st.session_state.user_email    = None
            st.session_state.page          = "fleet"
            st.rerun()

        st.divider()

        if st.button("← Back to Fleet", width="stretch", key="hw_back_fleet"):
            st.session_state.page = "fleet"
            st.rerun()

        # Device info card
        st.markdown(f"""
        <div style="background:rgba(0,207,255,0.05);padding:15px;border-radius:8px;
                    border-left:4px solid #00cfff;margin:16px 0;">
            <small style="color:#00cfff;font-weight:bold;">[ LIVE HARDWARE ]</small><br>
            <div style="display:flex;align-items:center;gap:10px;margin-top:5px;">
                <span style="font-size:2em;">{device_info['icon']}</span>
                <div>
                    <strong style="color:white;">{device_info['name']}</strong><br>
                    <span style="color:#aaa;font-size:0.9em;">ID: {hw_id}</span><br>
                    <span style="color:#aaa;font-size:0.9em;">Sector: {device_info['sector']}</span>
                </div>
            </div>
        </div>""", unsafe_allow_html=True)

        # Live telemetry
        pkt_count = get_packet_count(mac)
        st.markdown(f"""
        <div style="background:rgba(0,255,136,0.05);padding:12px;border-radius:8px;
                    border:1px solid rgba(0,255,136,0.2);margin-bottom:12px;">
            <small style="color:{NEON_GREEN};font-weight:bold;">CAPTURE TELEMETRY</small><br>
            <span style="color:#aaa;font-size:0.85em;">MAC:</span>
            <span style="color:white;font-family:monospace;font-size:0.85em;"> {mac or '—'}</span><br>
            <span style="color:#aaa;font-size:0.85em;">Interface:</span>
            <span style="color:white;font-size:0.85em;"> {iface or '—'}</span><br>
            <span style="color:#aaa;font-size:0.85em;">Packets captured:</span>
            <span style="color:{NEON_GREEN};font-weight:bold;font-size:0.95em;"> {pkt_count:,}</span>
        </div>""", unsafe_allow_html=True)

        # Live scan indicator (always on)
        st.markdown(
            f"<div style='color:{NEON_GREEN};font-weight:bold;'>📡 Live Scan — ACTIVE</div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render_hardware_dashboard(autoencoder) -> None:
    """Entry point called from app.py router."""
    import pandas as pd

    # Hard stop if page state is wrong — prevents render bleed from fleet page
    if st.session_state.get("page") != "hardware_dashboard":
        st.session_state.page = "fleet"
        st.rerun()
        return

    mac = st.session_state.get("hw_mac", "")
    if not mac:
        st.error("No MAC address configured. Go back to fleet and set up the device.")
        if st.button("← Back to Fleet"):
            st.session_state.page = "fleet"
            st.rerun()
        st.stop()
        return

    hw_id = st.session_state.get("hw_active_device")
    if not hw_id or hw_id not in HARDWARE_REGISTRY:
        st.error("No hardware device selected.")
        st.stop()

    device_info  = HARDWARE_REGISTRY[hw_id]
    mac          = device_info.get("mac", "")
    iface        = device_info.get("iface", "")
    dev_baseline = device_info["baseline"]

    _init_hw_session()

    # --- Sidebar ---
    _render_hw_sidebar(hw_id, device_info, mac, iface)

    # ── Calibration banner ────────────────────────────────────────────────────
    calibrating = st.session_state.get("hw_calibrating", False)

    if calibrating:
        st.warning(
            "⚙️  **Calibrating baseline…** Trust score is suppressed during this window. "
            f"Sampling live traffic for {CALIBRATION_WINDOW} seconds.",
            icon="📡",
        )
        with st.status("📡 Calibrating baseline...", expanded=True) as cal_status:
            for i in range(CALIBRATION_WINDOW):
                st.write(f"Sampling ({i + 1}/{CALIBRATION_WINDOW}s)…")
                time.sleep(1.0)
                remaining = CALIBRATION_WINDOW - i - 1
                if not st.session_state.get("hw_calibrating", False):
                    break  # calibration finished
                if remaining == 0:
                    cal_status.update(label="✅ Baseline calibrated!", state="complete")
            else:
                cal_status.update(label="✅ Baseline calibrated!", state="complete")
        st.rerun()

    # --- Live feature pull ---
    raw_features = get_features(mac)
    current_features = np.array(raw_features)

    # ── Top header ────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:rgba(0,255,136,0.05);border:1px solid rgba(0,255,136,0.3);
                border-radius:4px;padding:5px;margin-bottom:15px;box-shadow:0 0 10px rgba(0,255,136,0.1);">
        <marquee scrollamount="5" style="color:#00ff88;font-family:'Source Code Pro',monospace;font-size:14px;letter-spacing:2px;">
            // LIVE CAPTURE: ACTIVE &nbsp;&nbsp;&nbsp;&nbsp;
            // HARDWARE INTEGRATION: SCAPY &nbsp;&nbsp;&nbsp;&nbsp;
            // FEATURE ENGINE: REAL-TIME &nbsp;&nbsp;&nbsp;&nbsp;
            // NORMALIZATION: ROLLING MIN-MAX
        </marquee>
    </div>""", unsafe_allow_html=True)

    # ── Inference ─────────────────────────────────────────────────────────────
    feature_seq  = np.tile(current_features, (10, 1))[np.newaxis, :, :]
    tensor_input = torch.tensor(feature_seq, dtype=torch.float32)

    with torch.no_grad():
        mse       = float(autoencoder.reconstruction_error(tensor_input).item())
        output    = autoencoder(tensor_input)
        mse_per_f = torch.mean((tensor_input - output) ** 2, dim=1).squeeze().tolist()

    for i in range(4):
        st.session_state[_HW_RE_HIST][i].append(mse_per_f[i])
        st.session_state[_HW_RE_HIST][i].pop(0)

    jsd = calculate_jsd(current_features, dev_baseline)
    for buf, val in [(_HW_MSE_BUF, mse), (_HW_JSD_PUL_BUF, jsd), (_HW_JSD_BUF, jsd)]:
        st.session_state[buf].append(val)
        st.session_state[buf].pop(0)

    trust_score = calculate_trust_score(mse, jsd)
    if np.allclose(current_features, dev_baseline, atol=1e-6):
        mse, trust_score = 0.0, 100.0

    # Suppress trust score during calibration
    if calibrating:
        trust_score = 100.0
        mse         = 0.0

    is_safe, is_critical, status_color, card_class, indicator_html = _resolve_status(trust_score)

    # ── Page header ───────────────────────────────────────────────────────────
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <h1 style="margin:0;">{device_info['icon']} Live Twin: {device_info['name']}</h1>
        <h3 style="margin:0;color:{status_color} !important;border:1px solid {status_color};
                   padding:8px 16px;border-radius:8px;box-shadow:0 0 15px {status_color}40;">
            {indicator_html}
        </h3>
    </div>""", unsafe_allow_html=True)

    # ── Alert ─────────────────────────────────────────────────────────────────
    if not is_safe:
        st.error(
            f"CRITICAL: ANOMALOUS TRAFFIC detected from {device_info['name']} "
            f"(MAC: {mac}). Trust Score: {trust_score:.1f}%. MSE: {mse:.4f}",
            icon="🚨",
        )

    # ── Live feature metrics row ───────────────────────────────────────────────
    with glass_card():
        section_header("📶 Live Normalized Features (Real-Time)")
        c1, c2, c3, c4 = st.columns(4)
        labels = ["Packet Size", "IAT", "Entropy", "Symmetry"]
        icons  = ["📦", "⏱️", "🔀", "⚖️"]
        for col, label, icon, val in zip([c1, c2, c3, c4], labels, icons, raw_features):
            col.metric(f"{icon} {label}", f"{val:.4f}", help=f"Normalized {label} ∈ [0, 1]")

        # Calibrate button
        _, calib_col = st.columns([3, 1])
        with calib_col:
            if st.button("📡 Calibrate Baseline", key="hw_calibrate_btn", width="stretch"):
                st.session_state["hw_calibrating"] = True
                _start_calibration_thread(mac)
                st.rerun()

    # ── Top row: Gauge | Packet Stream ────────────────────────────────────────
    now_str = datetime.datetime.now().strftime("%H:%M:%S")

    # Build live packet history entry
    new_pkt = {
        "Time":     now_str,
        "Pkt Size": round(raw_features[0], 4),
        "IAT":      round(raw_features[1], 4),
        "Entropy":  round(raw_features[2], 4),
        "Symmetry": round(raw_features[3], 4),
        "Status":   "Safe" if is_safe else "Alert",
    }
    existing = st.session_state[_HW_PKT_HIS].dropna(axis=1, how="all")
    new_df   = pd.DataFrame([new_pkt])
    st.session_state[_HW_PKT_HIS] = pd.concat(
        [new_df, existing],
        ignore_index=True,
    ).head(12)
    if not is_safe:
        log = st.session_state[_HW_THREAT_LOG]
        if not log or log[0]["time"] != now_str:
            log.insert(0, {
                "time": now_str,
                "msg":  f"Anomalous live traffic! Trust: {trust_score:.1f}%. JSD: {jsd:.3f} MSE: {mse:.4f}",
            })
            st.session_state[_HW_THREAT_LOG] = log[:20]

    col_gauge, col_stream = st.columns([1, 1.5])

    with col_gauge:
        with glass_card(card_class):
            section_header("System Trust Gauge")
            st.plotly_chart(_gauge_chart(trust_score, status_color), width="stretch")
            st.plotly_chart(_sparkline_chart(st.session_state[_HW_JSD_BUF]), width="stretch")
            st.markdown(
                "<div style='text-align:center;font-family:\"Source Code Pro\",monospace;"
                "font-size:12px;color:#00fff2;text-shadow:0 0 5px #00fff2;margin-top:-10px;'>"
                "FEATURE CONTRIBUTION (JSD)</div>", unsafe_allow_html=True,
            )

    with col_stream:
        with glass_card():
            section_header("Live Packet Stream")
            def _color_status(val):
                return f'color: {NEON_RED if val == "Alert" else NEON_GREEN}'
            st.dataframe(
                st.session_state[_HW_PKT_HIS].style.map(_color_status, subset=["Status"]),
                width="stretch", hide_index=True, height=320,
            )

    # ── Radar + Pulse ─────────────────────────────────────────────────────────
    stress_alert = mse > 0.15
    stress_extra = (
        "pulse-stress",
        "border:1px solid #ff007f;",
    ) if stress_alert else ("", "border:1px solid rgba(0,255,242,0.2);")

    right_html = (
        '<span style="color:#ff007f;font-size:0.8em;animation:blinker 0.8s infinite;">NEURAL STRESS DETECTED</span>'
        if stress_alert else ""
    )

    with glass_card(stress_extra[0], f"box-shadow:0 0 15px rgba(0,255,242,0.2);{stress_extra[1]}"):
        section_header("Feature Drift Analysis", right_html)

        categories = ["Packet Size", "IAT", "Payload Entropy", "Flow Symmetry"]
        col_radar, col_pulse = st.columns(2)

        with col_radar:
            st.plotly_chart(
                _radar_chart(dev_baseline, current_features, categories, status_color, is_safe),
                width="stretch", config={"displayModeBar": False},
            )

        with col_pulse:
            st.markdown(
                "<div style='text-align:center;color:#00fff2;font-weight:600;margin-bottom:5px;"
                "font-family:\"Source Code Pro\",monospace;font-size:0.9em;'>"
                "Neural Health Monitor (Live Pulse)</div>", unsafe_allow_html=True,
            )
            st.plotly_chart(
                _pulse_chart(
                    st.session_state[_HW_MSE_BUF],
                    st.session_state[_HW_JSD_PUL_BUF],
                ),
                width="stretch", config={"displayModeBar": False},
            )

        st.caption(
            "Dual-Sync Visualization: Mapping live hardware traffic against the calibrated "
            "baseline for real-time anomaly explainability."
        )

    # ── Math engine ───────────────────────────────────────────────────────────
    def _toggle_math():
        st.session_state[_HW_MATH_MODE] = not st.session_state[_HW_MATH_MODE]

    label = "⏸️ Terminate Live Feed" if st.session_state[_HW_MATH_MODE] else "▶️ Initialize Live Math Engine"
    st.button(label, key="hw_math_toggle", on_click=_toggle_math, width="stretch")

    if st.session_state[_HW_MATH_MODE]:
        with glass_card(extra_style="border:1px solid #00fff2;box-shadow:0 0 15px rgba(0,255,242,0.2);"):
            section_header("Neural Engine & Mathematics (Live Computing)")
            col_math, col_neural = st.columns(2)

            with col_math:
                st.markdown(
                    "<div style='text-align:center;color:white;font-weight:600;margin-bottom:10px;'>"
                    "The JSD Logic (Mathematical Engine)</div>", unsafe_allow_html=True
                )
                live_jsd = calculate_jsd(current_features, dev_baseline)
                st.latex(rf"JSD(P \| Q) \approx {live_jsd:.4f}")
                st.markdown(
                    f"<div style='color:#00ff88;font-weight:bold;text-align:center;padding:10px;"
                    f"border:1px solid #00ff88;border-radius:8px;margin-top:10px;"
                    f"box-shadow:0 0 10px rgba(0,255,136,0.2);'>"
                    f"Current Statistical Friction: {live_jsd:.4f}</div>",
                    unsafe_allow_html=True,
                )

            with col_neural:
                st.markdown(
                    "<div style='text-align:center;color:white;font-weight:600;margin-bottom:10px;'>"
                    "The LSTM Encoder (Neural Architecture)</div>", unsafe_allow_html=True
                )
                with torch.no_grad():
                    mse_calc = float(torch.mean((tensor_input - autoencoder(tensor_input)) ** 2).item())
                st.latex(rf"f_t = \sigma(W_f \cdot [h_{{t-1}}, x_t] + b_f) \implies MSE \approx {mse_calc:.4f}")
                st.progress(min(max(mse_calc, 0.0), 1.0), text=f"Reconstruction Error (MSE): {mse_calc:.4f}")
                st.caption("If MSE > 0.1, the Twin is drifting from the Physical Device.")

    # ── Threat log ────────────────────────────────────────────────────────────
    with glass_card():
        section_header("Threat Log")
        if not st.session_state[_HW_THREAT_LOG]:
            st.write("✅ System is secure. No recent threats logged.")
        else:
            for alert in st.session_state[_HW_THREAT_LOG]:
                st.markdown(
                    f'<div style="border-left:4px solid {NEON_RED};padding:8px 12px;'
                    f'margin-bottom:8px;background:rgba(255,0,127,0.08);border-radius:4px;">'
                    f'<span style="color:#888;font-size:0.85em;">{alert["time"]}</span>'
                    f'&nbsp;&nbsp;<span style="color:white;">{alert["msg"]}</span></div>',
                    unsafe_allow_html=True,
                )

    # ── Auto-rerun loop ───────────────────────────────────────────────────────
    time.sleep(1.5)
    st.rerun()
