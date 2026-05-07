"""dashboard.py — Device drill-down dashboard page."""

import datetime
import time

import numpy as np
import plotly.graph_objects as go
import streamlit as st
import torch

from engine import calculate_jsd, calculate_trust_score
from forensics import generate_and_send_report
from registry import IOT_REGISTRY
from ui import NEON_BLUE, NEON_GREEN, NEON_RED, glass_card, section_header


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_status(trust_score: float):
    """Return (is_safe, is_critical, status_color, card_class, indicator_html)."""
    is_safe     = trust_score >= 50
    is_critical = trust_score < 30

    if is_safe:
        return True, False, NEON_GREEN, "neon-safe", f"<span style='color:{NEON_GREEN};'>● ONLINE</span>"
    if is_critical:
        return False, True, NEON_RED, "neon-compromised pulse-red", (
            f"<span style='color:{NEON_RED};animation:blinker 1s linear infinite;'>● CRITICAL</span>"
        )
    return False, False, "#ffb300", "neon-compromised", "<span style='color:#ffb300;'>● COMPROMISED</span>"


def _try_send_forensic_report(dev_id, device_info, trust_score, mse, jsd,
                               dev_baseline, current_features):
    last_sent = st.session_state.last_alert_sent.get(dev_id)
    now_utc   = datetime.datetime.utcnow()
    if last_sent and (now_utc - last_sent) < datetime.timedelta(minutes=10):
        return
    try:
        generate_and_send_report(
            recipient_email=st.session_state.user_email,
            device_data={
                "device_id": dev_id, "device_name": device_info["name"],
                "sector": device_info["sector"], "timestamp": now_utc.isoformat(),
                "trust_score": trust_score, "reconstruction_error": mse,
                "jsd_value": jsd, "baseline_features": dev_baseline,
                "current_features": current_features.tolist(),
                "packet_history": st.session_state.packet_history[dev_id].to_dict("records"),
                "threat_log": st.session_state.threat_log[dev_id],
            },
        )
        st.success("Forensic report generated and emailed to your account.")
        st.session_state.last_alert_sent[dev_id] = now_utc
    except Exception as exc:
        st.warning(f"Failed to send forensic report: {exc}")


def _run_remediation(dev_id, device_info):
    st.session_state.remediation_locked = True
    now_str     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prev_status = st.session_state.device_health.get(dev_id, "Unknown")

    st.session_state.remediation_log[dev_id].append({
        "Timestamp": now_str, "Device ID": dev_id,
        "Device Name": device_info["name"], "Sector": device_info["sector"],
        "Action Taken": "Quarantine Lifted & Params Reset",
    })
    st.session_state.audit_logs.insert(0, {
        "device": dev_id, "timestamp": now_str,
        "event": "Remediation Success", "previous_status": prev_status,
    })

    with st.status("Running remediation protocol...", expanded=True) as rem:
        st.write("Resetting device parameters...")
        time.sleep(0.8)
        st.session_state.device_health[dev_id] = "Healthy"
        st.session_state.remediation_reset      = dev_id
        st.session_state.threat_log[dev_id]     = []
        st.write("Flushing network buffers...")
        time.sleep(0.7)
        st.write("Re-synchronizing digital twin...")
        time.sleep(0.7)
        rem.update(label="✅ Device restored to safe baseline", state="complete")
        time.sleep(0.4)
        st.session_state.remediation_locked = False
    st.rerun()


# ---------------------------------------------------------------------------
# Chart builders
# ---------------------------------------------------------------------------

def _gauge_chart(trust_score, status_color):
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


def _sparkline_chart(jsd_history):
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


def _radar_chart(dev_baseline, current_features, categories, status_color, is_safe):
    fill = "rgba(0, 255, 136, 0.3)" if is_safe else "rgba(255, 45, 85, 0.3)"
    fig  = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=dev_baseline, theta=categories, fill="toself",
        name="Baseline", line_color=NEON_BLUE, fillcolor="rgba(0,207,255,0.2)",
    ))
    fig.add_trace(go.Scatterpolar(
        r=current_features, theta=categories, fill="toself",
        name="Current Traffic", line_color=status_color, fillcolor=fill,
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


def _pulse_chart(pulse_mse, pulse_jsd):
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
# Main render
# ---------------------------------------------------------------------------

def render_device_dashboard(autoencoder):
    dev_id = st.session_state.active_device
    if not isinstance(dev_id, str) or dev_id not in IOT_REGISTRY:
        st.error("No device selected or invalid device ID.")
        st.stop()

    device_info  = IOT_REGISTRY[dev_id]
    dev_baseline = device_info["baseline"]
    disabled     = st.session_state.remediation_locked

    # --- Deferred state updates (before any widget) ---
    if st.session_state.get("remediation_reset") == dev_id:
        for key, i in [("pkt", 0), ("iat", 1), ("ent", 2), ("sym", 3)]:
            st.session_state[f"{key}_{dev_id}"] = float(dev_baseline[i])
        st.session_state.attack_step[dev_id] = 0
        st.session_state.threat_log[dev_id]  = []
        st.session_state.remediation_locked  = False
        del st.session_state["remediation_reset"]

    if st.session_state.get("attack_trigger") == dev_id:
        st.session_state.pop("attack_trigger")
        for k, v in st.session_state.pop("attack_values", {}).items():
            st.session_state[k] = v

    # --- Per-Device Session State Initialization ---
    if dev_id not in st.session_state.trust_scores:
        st.session_state.trust_scores[dev_id] = 100.0
    if dev_id not in st.session_state.device_health:
        st.session_state.device_health[dev_id] = "Healthy"
    if dev_id not in st.session_state.threat_log:
        st.session_state.threat_log[dev_id] = []
    import pandas as pd
    if dev_id not in st.session_state.packet_history:
        st.session_state.packet_history[dev_id] = pd.DataFrame(
            columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"])
    if dev_id not in st.session_state.attack_step:
        st.session_state.attack_step[dev_id] = 0
    if dev_id not in st.session_state.remediation_log:
        st.session_state.remediation_log[dev_id] = []
    
    # Histories for charts
    if dev_id not in st.session_state.jsd_history:
        st.session_state.jsd_history[dev_id] = [0.0] * 10
    if dev_id not in st.session_state.pulse_mse_history:
        st.session_state.pulse_mse_history[dev_id] = [0.0] * 30
    if dev_id not in st.session_state.pulse_jsd_history:
        st.session_state.pulse_jsd_history[dev_id] = [0.0] * 30
    if dev_id not in st.session_state.reconstruction_errors_history:
        st.session_state.reconstruction_errors_history[dev_id] = [[0.0] * 20 for _ in range(4)]

    for key, i in [("pkt", 0), ("iat", 1), ("ent", 2), ("sym", 3)]:
        st.session_state.setdefault(f"{key}_{dev_id}", float(dev_baseline[i]))
    st.session_state.attack_step.setdefault(dev_id, 0)

    # Initialize per-device health only if this device has never been seen
    if dev_id not in st.session_state.device_health:
        st.session_state.device_health[dev_id] = "Healthy"

    # Initialize packet history and threat log only if absent
    import pandas as pd
    if "packet_history" not in st.session_state:
        st.session_state.packet_history = pd.DataFrame(
            columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"]
        )
    if "threat_log" not in st.session_state:
        st.session_state.threat_log = []

    # --- Sidebar ---
    _render_sidebar(dev_id, device_info, dev_baseline, disabled)

    # Read slider values after sidebar renders them
    val_pkt_size = st.session_state[f"pkt_{dev_id}"]
    val_iat      = st.session_state[f"iat_{dev_id}"]
    val_entropy  = st.session_state[f"ent_{dev_id}"]
    val_symmetry = st.session_state[f"sym_{dev_id}"]
    scan_active  = st.session_state.get(f"scan_{dev_id}", True)

    # --- Inference ---
    current_features = np.array([val_pkt_size, val_iat, val_entropy, val_symmetry])
    feature_seq      = np.tile(current_features, (10, 1))[np.newaxis, :, :]
    tensor_input     = torch.tensor(feature_seq, dtype=torch.float32)

    with torch.no_grad():
        mse       = float(autoencoder.reconstruction_error(tensor_input).item())
        output    = autoencoder(tensor_input)
        mse_per_f = torch.mean((tensor_input - output) ** 2, dim=1).squeeze().tolist()

    for i in range(4):
        st.session_state.reconstruction_errors_history[dev_id][i].append(mse_per_f[i])
        st.session_state.reconstruction_errors_history[dev_id][i].pop(0)

    jsd = calculate_jsd(current_features, dev_baseline)
    for buf, val in [("pulse_mse_history", mse), ("pulse_jsd_history", jsd), ("jsd_history", jsd)]:
        st.session_state[buf][dev_id].append(val)
        st.session_state[buf][dev_id].pop(0)

    trust_score = calculate_trust_score(mse, jsd)
    st.session_state.trust_scores[dev_id] = trust_score
    if np.allclose(current_features, dev_baseline, atol=1e-8):
        mse, trust_score = 0.0, 100.0

    is_safe, is_critical, status_color, card_class, indicator_html = _resolve_status(trust_score)
    st.session_state.device_health[dev_id] = "Healthy" if is_safe else "Compromised"

    # --- Header ---
    st.markdown("""
    <div style="background:rgba(0,255,242,0.05);border:1px solid rgba(0,255,242,0.3);
                border-radius:4px;padding:5px;margin-bottom:15px;box-shadow:0 0 10px rgba(0,255,242,0.1);">
        <marquee scrollamount="5" style="color:#00fff2;font-family:'Source Code Pro',monospace;font-size:14px;letter-spacing:2px;">
            // SYSTEM INTEGRITY: OPTIMAL &nbsp;&nbsp;&nbsp;&nbsp;
            // ENCODER LATENCY: 0.002ms &nbsp;&nbsp;&nbsp;&nbsp;
            // ACTIVE NODES: 10 &nbsp;&nbsp;&nbsp;&nbsp;
            // ENCRYPTION: AES-256
        </marquee>
    </div>""", unsafe_allow_html=True)

    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <h1 style="margin:0;">{device_info['icon']} Twin Dashboard: {device_info['name']}</h1>
        <h3 style="margin:0;color:{status_color} !important;border:1px solid {status_color};
                   padding:8px 16px;border-radius:8px;box-shadow:0 0 15px {status_color}40;">
            {indicator_html}
        </h3>
    </div>""", unsafe_allow_html=True)

    # --- Alert + remediation ---
    if not is_safe:
        st.error(
            f"CRITICAL: SECURITY BREACH. Unrecognized anomalies in Sector "
            f"{device_info['sector']} ({device_info['type']}). INITIATING NETWORK QUARANTINE.",
            icon="🚨",
        )
        if trust_score < 30 and st.session_state.user_email:
            _try_send_forensic_report(dev_id, device_info, trust_score, mse, jsd,
                                      dev_baseline, current_features)

        _, col_remed = st.columns([8, 2])
        with col_remed:
            if st.button("🔧 Remediate Device", width="stretch",
                         key=f"remed_{dev_id}", disabled=disabled):
                _run_remediation(dev_id, device_info)

    # --- Live scan update ---
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    if scan_active:
        import random
        new_pkt = {
            "Time": now_str,
            "Pkt Size": round(random.uniform(64, 1500), 1),
            "IAT":      round(random.uniform(0.001, 0.05), 4),
            "Entropy":  round(random.uniform(3, 7.5), 2),
            "Symmetry": round(random.uniform(0.4, 0.9), 2),
            "Status":   "Safe" if is_safe else "Alert",
        }
        import pandas as pd
        st.session_state.packet_history[dev_id] = pd.concat(
            [pd.DataFrame([new_pkt]), st.session_state.packet_history[dev_id]], ignore_index=True,
        ).head(12)

        if not is_safe:
            threats = st.session_state.threat_log[dev_id]
            if not threats or threats[0]["time"] != now_str:
                threats.insert(0, {
                    "time": now_str,
                    "msg":  f"Anomalous flow detected! Trust dropped to {trust_score:.1f}%. MSE: {mse:.3f}",
                })
                st.session_state.threat_log[dev_id] = threats[:20]

    # --- Top row: Gauge | Packet Stream ---
    col_gauge, col_stream = st.columns([1, 1.5])

    with col_gauge:
        with glass_card(card_class):
            section_header("System Trust Gauge")
            st.plotly_chart(_gauge_chart(trust_score, status_color), width="stretch")
            st.plotly_chart(_sparkline_chart(st.session_state.jsd_history[dev_id]), width="stretch")
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
                st.session_state.packet_history[dev_id].style.map(_color_status, subset=["Status"]),
                width="stretch", hide_index=True, height=320,
            )

    # --- Middle row: Radar | Pulse ---
    stress_alert = mse > 0.15
    stress_extra = (
        "pulse-stress",
        "border:1px solid #ff007f;",
    ) if stress_alert else ("", "border:1px solid rgba(0,255,242,0.2);")

    right_html = (
        '<span style="color:#ff007f;font-size:0.8em;animation:blinker 0.8s infinite;">NEURAL STRESS DETECTED</span>'
        if stress_alert else ""
    )

    with st.container():
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
                    _pulse_chart(st.session_state.pulse_mse_history[dev_id], st.session_state.pulse_jsd_history[dev_id]),
                    width="stretch", config={"displayModeBar": False},
                )

            st.caption("Dual-Sync Visualization: Mapping multidimensional geometric drift against "
                       "temporal reconstruction residuals for 100% anomaly explainability.")

    # --- Math engine toggle ---
    def _toggle_math():
        st.session_state.math_mode_active = not st.session_state.math_mode_active

    label = "⏸️ Terminate Live Feed" if st.session_state.math_mode_active else "▶️ Initialize Live Math Engine"
    st.button(label, key=f"math_toggle_{dev_id}", on_click=_toggle_math, width="stretch")

    if st.session_state.math_mode_active:
        with glass_card(extra_style="border:1px solid #00fff2;box-shadow:0 0 15px rgba(0,255,242,0.2);"):
            section_header("Neural Engine & Mathematics (Live Computing)")
            col_math, col_neural = st.columns(2)

            with col_math:
                st.markdown("<div style='text-align:center;color:white;font-weight:600;margin-bottom:10px;'>The JSD Logic (Mathematical Engine)</div>", unsafe_allow_html=True)
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
                st.markdown("<div style='text-align:center;color:white;font-weight:600;margin-bottom:10px;'>The LSTM Encoder (Neural Architecture)</div>", unsafe_allow_html=True)
                with torch.no_grad():
                    mse_calc = float(torch.mean((tensor_input - autoencoder(tensor_input)) ** 2).item())
                st.latex(rf"f_t = \sigma(W_f \cdot [h_{{t-1}}, x_t] + b_f) \implies MSE \approx {mse_calc:.4f}")
                st.progress(min(max(mse_calc, 0.0), 1.0), text=f"Reconstruction Error (MSE): {mse_calc:.4f}")
                st.caption("If MSE > 0.1, the Twin is drifting from the Physical Device.")

    # --- Threat log ---
    with st.container():
        with glass_card():
            section_header("Threat Log")
            threats = st.session_state.threat_log[dev_id]
            if not threats:
                st.write("✅ System is secure. No recent threats logged.")
            else:
                for alert in threats:
                    st.markdown(
                        f'<div style="border-left:4px solid {NEON_RED};padding:8px 12px;'
                        f'margin-bottom:8px;background:rgba(255,0,127,0.08);border-radius:4px;">'
                        f'<span style="color:#888;font-size:0.85em;">{alert["time"]}</span>'
                        f'&nbsp;&nbsp;<span style="color:white;">{alert["msg"]}</span></div>',
                        unsafe_allow_html=True,
                    )

    if scan_active:
        time.sleep(1.0)
        st.rerun()


# ---------------------------------------------------------------------------
# Sidebar (extracted to keep render_device_dashboard readable)
# ---------------------------------------------------------------------------

def _render_sidebar(dev_id, device_info, dev_baseline, disabled):
    import time, random
    from ui import NEON_BLUE

    with st.sidebar:
        st.markdown(
            f"<h1 style='text-align:center;color:{NEON_BLUE} !important;'>🛡️ Aegis Control</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<p style='text-align:center;color:#aaa;margin-top:-10px;'>"
            f"Logged in as <strong>{st.session_state.user_email or 'Unknown'}</strong></p>",
            unsafe_allow_html=True,
        )
        if st.button("Log out", width="stretch", key="logout"):
            st.session_state.authenticated = False
            st.session_state.user_email    = None
            st.session_state.page          = "fleet"
            st.rerun()

        st.divider()

        if st.button("← Back to Fleet", width="stretch", disabled=disabled):
            st.session_state.active_device = None
            st.session_state.page          = "fleet"
            st.rerun()

        st.markdown(f"""
        <div style="background:rgba(0,207,255,0.05);padding:15px;border-radius:8px;
                    border-left:4px solid #00cfff;margin:16px 0;">
            <small style="color:#00cfff;font-weight:bold;">[ DEVICE REGISTRY ]</small><br>
            <div style="display:flex;align-items:center;gap:10px;margin-top:5px;">
                <span style="font-size:2em;">{device_info['icon']}</span>
                <div>
                    <strong style="color:white;">{device_info['name']}</strong><br>
                    <span style="color:#aaa;font-size:0.9em;">ID: {dev_id}</span><br>
                    <span style="color:#aaa;font-size:0.9em;">Sector {device_info['sector']}</span>
                </div>
            </div>
        </div>""", unsafe_allow_html=True)

        st.toggle("📡 Live Scan Mode", value=True, key=f"scan_{dev_id}", disabled=disabled)
        st.divider()
        st.markdown("### Manual Traffic Injection")

        for label, key, idx in [
            ("Packet Size (Norm)", "pkt", 0),
            ("Inter-Arrival Time (Norm)", "iat", 1),
            ("Entropy (Norm)", "ent", 2),
            ("Symmetry (Norm)", "sym", 3),
        ]:
            st.slider(label, 0.0, 1.0,
                      value=st.session_state[f"{key}_{dev_id}"],
                      key=f"{key}_{dev_id}", disabled=disabled)

        st.divider()
        attack_step = st.session_state.attack_step.get(dev_id, 0)
        if attack_step > 0:
            bar = "█" * int(min(attack_step / 5, 1.0) * 10) + "░" * (10 - int(min(attack_step / 5, 1.0) * 10))
            severity = ["", "LOW", "MODERATE", "HIGH", "SEVERE", "CRITICAL"][min(attack_step, 5)]
            st.markdown(
                f'<div class="attack-progress">⚠️ Attack in progress — {severity}<br>'
                f'<span style="font-family:monospace;letter-spacing:2px;">{bar}</span>'
                f'&nbsp;Step {attack_step}/5</div>',
                unsafe_allow_html=True,
            )

        if st.button("🚨 Launch Attack", width="stretch",
                     key=f"attack_{dev_id}", disabled=disabled):
            _launch_attack(dev_id, dev_baseline)

        st.divider()
        if st.button("Clear View Log", width="stretch",
                     key=f"clear_{dev_id}", disabled=disabled):
            import pandas as pd
            st.session_state.packet_history[dev_id] = pd.DataFrame(
                columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"])
            st.session_state.threat_log[dev_id] = []
            st.rerun()


def _launch_attack(dev_id, dev_baseline):
    import time, random
    import numpy as np

    staged   = {}
    messages = [
        "Probing network interfaces...",
        "Injecting malicious traffic packets...",
        "Escalating privilege — overloading device buffers...",
    ]
    with st.status("⚠️ Simulating cyber attack...", expanded=True) as atk:
        for i in range(3):
            st.write(messages[i])
            _advance_attack(dev_id, dev_baseline, staged)
            time.sleep(0.6)
        atk.update(label="💀 Attack payload delivered", state="error")
        time.sleep(0.4)
    st.session_state["attack_values"]  = staged
    st.session_state["attack_trigger"] = dev_id
    st.rerun()


def _advance_attack(dev_id, dev_baseline, staged):
    import random, numpy as np
    step      = st.session_state.attack_step.get(dev_id, 0)
    delta     = min(0.12 + step * 0.08 + random.uniform(0.0, 0.06), 0.40)
    for state_key, idx in [(f"pkt_{dev_id}", 0), (f"iat_{dev_id}", 1),
                            (f"ent_{dev_id}", 2), (f"sym_{dev_id}", 3)]:
        current = staged.get(state_key, st.session_state.get(state_key, float(dev_baseline[idx])))
        new_val = current + delta if dev_baseline[idx] < 0.5 else current - delta
        staged[state_key] = float(np.clip(new_val, 0.0, 1.0))
    st.session_state.attack_step[dev_id] = min(step + 1, 5)