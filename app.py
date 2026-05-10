"""
Aegis-Twin · AI-Driven Digital Twin Dashboard
==============================================
Enterprise Fleet Manager Edition.

Run with: streamlit run app.py
"""
#app.py

import os
import time
import requests
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
import folium
from streamlit_folium import st_folium

from auth import create_user, has_users, init_db
from auth_page import render_login_page
from dashboard import render_device_dashboard
from hardware_dashboard import render_hardware_dashboard
from hardware_registry import HARDWARE_REGISTRY
from model import LSTMAutoencoder
from registry import IOT_REGISTRY, SESSION_DEFAULTS
from sniffer import start_sniffer
from ui import NEON_GREEN, NEON_RED, inject_css
from isolation_model import (
    load_model, 
    train_model, 
    get_training_status, 
    get_training_estimate,
    add_baseline_sample,
    get_status,
)

# ── Pi telemetry reader ───────────────────────────────────────────────────────
import json
from pathlib import Path

def read_pi_telemetry() -> dict | None:
    try:
        f = Path("telemetry.json")
        if not f.exists():
            return None
        return json.loads(f.read_text())
    except Exception:
        return None

# Try to restore a previously trained model on startup
if load_model():
    _phase = "monitoring"
    print("[Aegis] Restored trained model from disk → MONITORING phase")
else:
    print("[Aegis] No saved model found → LEARNING phase")




# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Aegis-Twin Fleet Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
load_dotenv()
init_db()

if not has_users():
    admin_email    = os.environ.get("AEGIS_ADMIN_EMAIL")
    admin_password = os.environ.get("AEGIS_ADMIN_PASSWORD")
    if admin_email and admin_password:
        try:
            create_user(admin_email, admin_password)
        except Exception:
            pass

inject_css()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
for k, v in SESSION_DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------------------------------------------------------
# Auth guard
# ---------------------------------------------------------------------------
if not st.session_state.authenticated:
    render_login_page()
    st.stop()

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
@st.cache_resource
def load_aegis_engine():
    import torch
    model = LSTMAutoencoder()
    weights_path = "aegis_model.pth"
    if os.path.exists(weights_path):
        try:
            model.load_state_dict(torch.load(weights_path, map_location="cpu"))
            print("[model] Loaded trained weights from aegis_model.pth")
        except Exception as e:
            print(f"[model] Could not load weights: {e} — using random weights")
    else:
        print("[model] No trained weights found — using random weights")
    model.eval()
    return model

autoencoder = load_aegis_engine()

# ---------------------------------------------------------------------------
# PAGE 1 — Fleet overview
# ---------------------------------------------------------------------------
def render_fleet_page():

    st.markdown("<h1 style='text-align:center;color:white;'>🌐 Enterprise Fleet Manager</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#aaa;'>Click a hotspot on the map or a row in the registry to open its Digital Twin dashboard. <span style='color:#00ff88'>● Green = Healthy</span> | <span style='color:#ff2d55'>● Red = Compromised</span></p>", unsafe_allow_html=True)

    # --- Ticker Banner ---
    ticker_text = "⬡ SYSTEM ONLINE · 10 NODES ACTIVE · SECTOR: RR NAGAR, BENGALURU · LSTM AUTOENCODER: RUNNING · DIGITAL TWINS: SYNCHRONIZED · THREAT LEVEL: NOMINAL · ENCRYPTION: AES-256-GCM · UPTIME: 99.98% · ANOMALY DETECTION: ENABLED · RECONSTRUCTION ERROR: NOMINAL · JSD DIVERGENCE: 0.00 ⬡"
    st.markdown(f"""
        <div style="background: rgba(0,255,242,0.03); border-top: 1px solid rgba(0,255,242,0.3); border-bottom: 1px solid rgba(0,255,242,0.3); padding: 8px 0; margin: 15px 0; overflow: hidden; white-space: nowrap;">
            <div style="display: inline-block; white-space: nowrap; animation: ticker 40s linear infinite; font-family: 'Source Code Pro', monospace; color: #00fff2; font-size: 0.85rem; text-shadow: 0 0 5px rgba(0,255,242,0.5); letter-spacing: 1px;">
                {ticker_text} &nbsp;&nbsp;&nbsp;&nbsp; {ticker_text} &nbsp;&nbsp;&nbsp;&nbsp; {ticker_text}
            </div>
        </div>
        <style>
            @keyframes ticker {{ 0% {{ transform: translateX(0); }} 100% {{ transform: translateX(-33.33%); }} }}
        </style>
    """, unsafe_allow_html=True)

    st.divider()

    # --- Split Layout: Map (Left) | Registry (Right) ---
    col_map, col_reg = st.columns([6, 4])

    # Map initialization centered on JSS Academy, RR Nagar
    center_lat, center_lon = 12.9026, 77.5001
    m = folium.Map(location=[center_lat, center_lon], zoom_start=15, tiles="cartodb dark_matter", zoom_control=True)

    # --- Counters for registry header ---
    total_devices     = len(IOT_REGISTRY)
    compromised_count = sum(1 for dev_id in IOT_REGISTRY if st.session_state.device_health.get(dev_id, "Healthy") != "Healthy")
    healthy_count     = total_devices - compromised_count

    # Build map markers
    for idx, (dev_id, info) in enumerate(IOT_REGISTRY.items()):
        health         = st.session_state.device_health.get(dev_id, "Healthy")
        color          = NEON_GREEN if health == "Healthy" else NEON_RED
        is_compromised = health != "Healthy"
        pulse_class    = "map-pulsing-marker" if is_compromised else "map-static-marker"

        tooltip_html = f"""
        <div style="font-family:'Inter',sans-serif; background:rgba(17,25,40,0.95); color:white; padding:12px; border:1px solid {color}; border-radius:8px; box-shadow:0 0 10px {color}66; min-width:180px;">
            <div style="font-size:1.5rem; margin-bottom:5px;">{info['icon']}</div>
            <strong style="font-size:1.1rem; display:block; margin-bottom:2px;">{info['name']}</strong>
            <code style="color:#00cfff; font-size:0.85em;">{dev_id}</code>
            <div style="margin-top:8px; font-size:0.9em; color:#aaa;">
                Type: {info['type']}<br>
                Sector: {info['sector']}<br>
                Status: <span style="color:{color}; font-weight:bold;">{health.upper()}</span>
            </div>
            <div style="margin-top:10px; font-size:0.8em; color:{color}; border-top:1px solid rgba(255,255,255,0.1); padding-top:5px;">
                ▶ Click to open dashboard
            </div>
        </div>
        """

        icon_html = f"""
        <div class="{pulse_class}" style="
            background-color: {color};
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px solid white;
            box-shadow: 0 0 15px {color};
            cursor: pointer;
        "></div>
        """

        folium.Marker(
            location=[info['lat'], info['lon']],
            popup=folium.Popup(tooltip_html, max_width=300),
            tooltip=info['name'],
            icon=folium.DivIcon(
                icon_size=(20, 20),
                icon_anchor=(10, 10),
                html=icon_html,
            ),
            custom_id=dev_id
        ).add_to(m)

    # Custom CSS for map markers
    st.markdown("""
    <style>
    @keyframes map-pulse {
        0% { transform: scale(0.9); box-shadow: 0 0 0 0 rgba(255, 45, 85, 0.7); }
        70% { transform: scale(1.1); box-shadow: 0 0 0 15px rgba(255, 45, 85, 0); }
        100% { transform: scale(0.9); box-shadow: 0 0 0 0 rgba(255, 45, 85, 0); }
    }
    .map-pulsing-marker { animation: map-pulse 1.5s infinite; }
    .map-static-marker:hover { transform: scale(1.2); transition: transform 0.2s ease; }
    </style>
    """, unsafe_allow_html=True)

    with col_map:
        output = st_folium(m, width="100%", height=500, key="fleet_map")

    with col_reg:
        # --- Registry header with counters ---
        st.markdown(f"""
        <div style="background:rgba(8,14,28,0.85);backdrop-filter:blur(20px);border:1px solid rgba(0,255,242,0.15);
                    border-radius:12px;padding:20px 20px 10px 20px;margin-bottom:8px;">
            <div style="font-family:'Source Code Pro',monospace;color:#00fff2;font-size:1.1rem;
                        margin-bottom:12px;letter-spacing:1px;">// DEVICE REGISTRY</div>
            <div style="display:flex;gap:10px;margin-bottom:4px;">
                <div style="flex:1;background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.3);
                            border-radius:8px;padding:8px 12px;text-align:center;">
                    <div style="color:#00ff88;font-size:1.4rem;font-weight:bold;">{total_devices}</div>
                    <div style="color:#aaa;font-size:0.75rem;">TOTAL</div>
                </div>
                <div style="flex:1;background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.3);
                            border-radius:8px;padding:8px 12px;text-align:center;">
                    <div style="color:#00ff88;font-size:1.4rem;font-weight:bold;">{healthy_count}</div>
                    <div style="color:#aaa;font-size:0.75rem;">ACTIVE</div>
                </div>
                <div style="flex:1;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.3);
                            border-radius:8px;padding:8px 12px;text-align:center;">
                    <div style="color:#ff2d55;font-size:1.4rem;font-weight:bold;">{compromised_count}</div>
                    <div style="color:#aaa;font-size:0.75rem;">CRITICAL</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # --- Search box (native Streamlit) ---
        search_query = st.text_input(
            "", placeholder="🔍 Search devices...",
            key="registry_search",
            label_visibility="collapsed",
        )

        # --- Column headers ---
        h1, h2, h3, h4, h5 = st.columns([1, 1.8, 2.2, 1.8, 1.2])
        for col, label in zip([h1, h2, h3, h4, h5], ["", "ID", "NAME", "TYPE", "STATUS"]):
            col.markdown(f"<span style='color:#555;font-size:0.78em;font-family:monospace;'>{label}</span>", unsafe_allow_html=True)
        st.markdown("<hr style='margin:2px 0 4px 0;border-color:rgba(0,255,242,0.15);'>", unsafe_allow_html=True)

        # --- Scrollable device rows using st.container(height=) ---
        scroll_box = st.container(height=310, border=False)

        with scroll_box:
            any_shown = False
            for dev_id, info in IOT_REGISTRY.items():
                search_text = f"{dev_id} {info['name']} {info['type']}".lower()
                if search_query and search_query.lower() not in search_text:
                    continue
                any_shown  = True
                health     = st.session_state.device_health.get(dev_id, "Healthy")
                color      = NEON_GREEN if health == "Healthy" else NEON_RED
                status_txt = "● ONLINE" if health == "Healthy" else "● CRITICAL"

                cb, c1, c2, c3, c4 = st.columns([1, 1.8, 2.2, 1.8, 1.2])
                with cb:
                    if st.button("▶", key=f"reg_nav_{dev_id}", help=f"Open {info['name']}"):
                        st.session_state.active_device = dev_id
                        st.session_state.page          = "dashboard"
                        st.rerun()
                c1.markdown(f"<span style='color:#00cfff;font-family:monospace;font-size:0.8em;'>{dev_id}</span>", unsafe_allow_html=True)
                c2.markdown(f"<span style='color:white;font-size:0.8em;'>{info['icon']} {info['name']}</span>", unsafe_allow_html=True)
                c3.markdown(f"<span style='color:#888;font-size:0.78em;'>{info['type']}</span>", unsafe_allow_html=True)
                c4.markdown(f"<span style='color:{color};font-size:0.78em;font-weight:bold;'>{status_txt}</span>", unsafe_allow_html=True)
                st.markdown("<hr style='margin:1px 0;border-color:rgba(255,255,255,0.04);'>", unsafe_allow_html=True)

            if not any_shown:
                st.markdown("<p style='color:#555;text-align:center;font-family:monospace;padding:20px;'>// NO DEVICES FOUND</p>", unsafe_allow_html=True)

    # --- Handle map click navigation ---
    if output and output.get("last_object_clicked"):
        click_lat = output["last_object_clicked"]["lat"]
        click_lon = output["last_object_clicked"]["lng"]

        clicked_dev_id = None
        for dev_id, info in IOT_REGISTRY.items():
            if abs(info['lat'] - click_lat) < 0.0001 and abs(info['lon'] - click_lon) < 0.0001:
                clicked_dev_id = dev_id
                break

        if clicked_dev_id:
            st.session_state.active_device = clicked_dev_id
            st.session_state.page          = "dashboard"
            st.rerun()

    st.divider()

    # ── Model Training Section ───────────────────────────────────────────────────────
    st.markdown("## 🤖 Isolation Forest Training")

    # Fetch training status
    try:
        status_resp = requests.get("http://localhost:5000/api/training/status", timeout=2)
        training_status = status_resp.json()
    except Exception:
        training_status = {"status": "offline", "in_progress": False, "baseline_samples": 0, "ready_to_train": False}

    if training_status.get("status") == "offline":
        st.warning("⚠️ Flask server is offline. Start `python flask_server.py` to enable training.")
    else:
        # Display current status
        col1, col2, col3 = st.columns(3)

        with col1:
            baseline_count = training_status.get("baseline_samples", 0)
            min_req = training_status.get('min_samples_required', 100)
            st.metric(
                "Training Samples",
                baseline_count,
                f"of {min_req} required"
            )
            if baseline_count < min_req:
                st.caption(f"💡 {min_req - baseline_count} more samples needed. Each telemetry message counts as 1 sample.")

        with col2:
            status_val = training_status.get("status", "idle").upper()
            status_color = "🟢" if status_val == "IDLE" else "🟡" if status_val == "IN_PROGRESS" else "🔴" if status_val == "FAILED" else "🔵"
            st.metric("Model Status", f"{status_color} {status_val}")
            if status_val == "MONITORING" or status_val == "COMPLETED":
                 st.caption("✅ Model is active and scoring.")

        with col3:
            can_train = training_status.get("ready_to_train", False)
            st.metric("Ready to Train", "✅ Yes" if can_train else "❌ No")

        st.markdown("<br>", unsafe_allow_html=True)

        # Training controls
        tcol1, tcol2 = st.columns([2, 1])

        # Training button
        with tcol1:
            if not training_status.get("in_progress", False):
                # Only show training button if not already trained or if user wants to re-train
                if st.button(
                    "🚀 Start Isolation Forest Training" if can_train else "⏳ Collecting more samples...",
                    disabled=not can_train,
                    use_container_width=True,
                    type="primary" if can_train else "secondary",
                    key="btn_start_train"
                ):
                    with st.spinner("Training in progress..."):
                        try:
                            train_resp = requests.post("http://localhost:5000/api/pi/force_train", timeout=30)
                            if train_resp.status_code == 200:
                                st.success("✅ Training completed successfully!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error(f"Training failed: {train_resp.text}")
                        except Exception as e:
                            st.error(f"Connection error: {e}")
            else:
                st.info("⏳ Training in progress...")

        with tcol2:
            if st.button("🔄 Reset & Re-train", use_container_width=True, help="Delete model and start collecting new samples"):
                try:
                    reset_resp = requests.post("http://localhost:5000/api/pi/reset", timeout=5)
                    if reset_resp.status_code == 200:
                        st.success("System reset to LEARNING phase.")
                        time.sleep(1)
                        st.rerun()
                except Exception as e:
                    st.error(f"Reset failed: {e}")

        # Display training results if available
        if training_status.get("last_summary"):
            summary = training_status["last_summary"]
            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander("📊 View Latest Training Results", expanded=status_val == "COMPLETED"):
                res1, res2, res3, res4 = st.columns(4)
                res1.metric("Samples", summary.get("samples_total", 0))
                res2.metric("Time", f"{summary.get('training_time_sec', 0):.2f}s")
                res3.metric("Test Score", f"{summary.get('test_score_mean', 0):.4f}")
                res4.metric("Anomaly Rate", f"{summary.get('test_anomaly_rate', 0):.2f}%")
                
                st.dataframe(pd.DataFrame({
                    "Metric": ["Mean Score", "Std Dev", "Min Score", "Max Score", "Threshold (p95)"],
                    "Value": [
                        f"{summary.get('test_score_mean', 0):.4f}",
                        f"{summary.get('test_score_std', 0):.4f}",
                        f"{summary.get('test_score_min', 0):.4f}",
                        f"{summary.get('test_score_max', 0):.4f}",
                        f"{summary.get('threshold_suggested', 0):.4f}"
                    ]
                }), use_container_width=True, hide_index=True)

    st.divider()

    st.markdown("## 🔌 Real-Time Hardware Integration")

    pi_data = read_pi_telemetry()

    # ── Device cards row ─────────────────────────────────────────────────────────
    hw_col1, hw_col2 = st.columns(2)

    # ── Samsung A23 card (existing mock device) ───────────────────────────────────
    with hw_col1:
        st.markdown("""
        <div style="background:rgba(17,25,40,0.8);border:1px solid rgba(0,207,255,0.3);
                    border-radius:12px;padding:20px;text-align:center;cursor:pointer;">
            <div style="font-size:3rem;">📱</div>
            <h3 style="color:white;margin:8px 0 4px;">Samsung A23</h3>
            <p style="color:#00cfff;font-size:0.85em;">ID: PHONE-001</p>
            <p style="color:#aaa;font-size:0.8em;">Type: Mobile Device</p>
            <div style="color:#00ff88;font-weight:bold;margin-top:10px;">● LIVE</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("📊 View Dashboard", key="phone_dash", use_container_width=True):
            st.session_state.selected_hw_device = "phone"
            st.rerun()

    # ── Raspberry Pi IP Camera card ───────────────────────────────────────────────
    with hw_col2:
        if pi_data:
            trust  = pi_data["latest"]["trust_score"]
            phase  = pi_data["phase"]
            status = pi_data["latest"]["status"]
            color  = "#00ff88" if trust >= 60 else "#ffb300" if trust >= 30 else "#ff2d55"
            badge  = "🔵 LEARNING" if phase == "learning" else ("🚨 CRITICAL" if status == "CRITICAL" else "✅ MONITORING")
        else:
            trust, phase, status, color, badge = 0, "learning", "LEARNING", "#00cfff", "⏳ WAITING"

        st.markdown(f"""
        <div style="background:rgba(17,25,40,0.8);border:1px solid {color}44;
                    border-radius:12px;padding:20px;text-align:center;">
            <div style="font-size:3rem;">📷</div>
            <h3 style="color:white;margin:8px 0 4px;">Pi Security Camera</h3>
            <p style="color:#00cfff;font-size:0.85em;">ID: RPI-IPCAM-01</p>
            <p style="color:#aaa;font-size:0.8em;">Type: IP Camera</p>
            <div style="color:{color};font-weight:bold;margin-top:10px;">{badge}</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("📊 View Dashboard", key="pi_dash", use_container_width=True):
            st.session_state.selected_hw_device = "pi"
            st.rerun()

    st.divider()

    # ── Pi device dashboard ───────────────────────────────────────────────────────
    if st.session_state.get("selected_hw_device") == "pi":
        st.markdown("## 📷 Pi Security Camera — Live Dashboard")

        if st.button("← Back", key="pi_back"):
            del st.session_state["selected_hw_device"]
            st.rerun()

        pi_data = read_pi_telemetry()

        if not pi_data:
            st.info("⏳ Waiting for Pi telemetry — make sure flask_server.py and pi_sender.py are running")
        else:
            trust   = pi_data["latest"]["trust_score"]
            phase   = pi_data["phase"]
            status  = pi_data["latest"]["status"]
            log     = pi_data.get("log", [])
            elapsed = pi_data["latest"].get("elapsed_learning", 0)
            nf      = pi_data["latest"].get("network_features", {})

            # ── Countdown during learning ─────────────────────────────────────────
            if phase == "learning":
                remaining = max(0, 30 - int(elapsed))
                st.markdown(f"""
                <div style="text-align:center;padding:40px;background:rgba(17,25,40,0.8);
                            border:1px solid #00cfff44;border-radius:12px;margin-bottom:20px;">
                    <div style="color:#00cfff;font-size:1rem;margin-bottom:10px;">
                        🔵 LEARNING PHASE — Collecting baseline traffic
                    </div>
                    <div style="color:white;font-size:5rem;font-weight:bold;line-height:1;">
                        {remaining}
                    </div>
                    <div style="color:#aaa;font-size:0.9rem;margin-top:10px;">
                        seconds until trust score appears
                    </div>
                    <div style="color:#aaa;font-size:0.8rem;margin-top:6px;">
                        Samples collected: {pi_data['model']['baseline_samples']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            else:
                # ── Trust gauge ───────────────────────────────────────────────────
                color = "#00ff88" if trust >= 60 else "#ffb300" if trust >= 30 else "#ff2d55"

                g1, g2, g3 = st.columns(3)
                with g1:
                    st.markdown(f"""
                    <div style="background:rgba(17,25,40,0.8);border:1px solid {color};
                                border-radius:12px;padding:20px;text-align:center;">
                        <div style="color:#aaa;font-size:0.8em;">TRUST SCORE</div>
                        <div style="color:{color};font-size:3rem;font-weight:bold;">{trust:.1f}</div>
                        <div style="color:#aaa;font-size:0.8em;">/ 100</div>
                    </div>
                    """, unsafe_allow_html=True)
                with g2:
                    st.markdown(f"""
                    <div style="background:rgba(17,25,40,0.8);border:1px solid {color};
                                border-radius:12px;padding:20px;text-align:center;">
                        <div style="color:#aaa;font-size:0.8em;">STATUS</div>
                        <div style="color:{color};font-size:2rem;font-weight:bold;">{status}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with g3:
                    st.markdown(f"""
                    <div style="background:rgba(17,25,40,0.8);border:1px solid #00cfff;
                                border-radius:12px;padding:20px;text-align:center;">
                        <div style="color:#aaa;font-size:0.8em;">DEVICE</div>
                        <div style="color:#00cfff;font-size:1.2rem;font-weight:bold;">RPI-IPCAM-01</div>
                        <div style="color:#aaa;font-size:0.8em;">IP Camera</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Trust score gauge chart ───────────────────────────────────────
                import plotly.graph_objects as go
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=trust,
                    number={"font": {"color": "white", "size": 75}, "suffix": "%"},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "white"},
                        "bar":  {"color": color, "thickness": 0.8},
                        "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                        "steps": [
                            {"range": [0,  30], "color": "rgba(255,45,85,0.15)"},
                            {"range": [30, 60], "color": "rgba(255,179,0,0.15)"},
                            {"range": [60,100], "color": "rgba(0,255,136,0.15)"},
                        ],
                        "threshold": {"line": {"color": "white", "width": 3},
                                      "thickness": 0.9, "value": trust},
                    },
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font={"color": "white"}, height=260,
                    margin=dict(l=20, r=20, t=10, b=10),
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

                # ── Live network features ─────────────────────────────────────────
                st.markdown("### 📡 Live Network Features")
                f1, f2, f3, f4 = st.columns(4)
                def feature_card(col, label, val, normal_range):
                    with col:
                        fcolor = "#00ff88" if 0.05 <= val <= 0.8 else "#ff2d55"
                        st.markdown(f"""
                        <div style="background:rgba(17,25,40,0.8);border:1px solid {fcolor}44;
                                    border-radius:10px;padding:15px;text-align:center;">
                            <div style="color:#aaa;font-size:0.75em;">{label}</div>
                            <div style="color:{fcolor};font-size:1.8rem;font-weight:bold;">
                                {val:.3f}
                            </div>
                            <div style="color:#555;font-size:0.7em;">normal: {normal_range}</div>
                        </div>
                        """, unsafe_allow_html=True)

                feature_card(f1, "PKT SIZE",  nf.get("pkt_size", 0),  "0.10–0.20")
                feature_card(f2, "IAT",       nf.get("iat", 0),       "0.25–0.45")
                feature_card(f3, "ENTROPY",   nf.get("entropy", 0),   "0.10–0.25")
                feature_card(f4, "SYMMETRY",  nf.get("symmetry", 0),  "0.40–0.65")

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Trust score history graph ─────────────────────────────────────
                if log:
                    st.markdown("### 📈 Trust Score History")
                    import pandas as pd
                    df = pd.DataFrame([
                        {"time": r.get("timestamp","")[-8:-3],
                         "trust": r.get("trust_score", 0)}
                        for r in log[-60:] if r.get("trust_score") is not None
                    ])
                    if not df.empty:
                        # Convert hex color to rgba for fillcolor (Plotly requirement)
                        fill_hex = color.lstrip('#')
                        fill_rgba = f"rgba({int(fill_hex[0:2], 16)},{int(fill_hex[2:4], 16)},{int(fill_hex[4:6], 16)},0.2)"
                        fig_line = go.Figure(go.Scatter(
                            x=df["time"], y=df["trust"],
                            mode="lines", fill="tozeroy",
                            line={"color": color, "width": 2, "shape": "spline"},
                            fillcolor=fill_rgba,
                        ))
                        fig_line.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font={"color": "white"},
                            height=200,
                            margin=dict(l=0, r=0, t=10, b=0),
                            xaxis={"showgrid": False},
                            yaxis={"range": [0, 100], "showgrid": True,
                                   "gridcolor": "rgba(255,255,255,0.05)"},
                        )
                        st.plotly_chart(fig_line, use_container_width=True)

                # ── Live feature log table ────────────────────────────────────────
                if log:
                    st.markdown("### 🗃️ Live Feature Log")
                    import pandas as pd
                    rows = []
                    for r in reversed(log[-20:]):
                        nff = r.get("network_features", {})
                        rows.append({
                            "Time":     r.get("timestamp","")[-8:],
                            "Trust":    round(r.get("trust_score", 0), 1),
                            "Status":   r.get("status",""),
                            "PKT Size": nff.get("pkt_size",""),
                            "IAT":      nff.get("iat",""),
                            "Entropy":  nff.get("entropy",""),
                            "Symmetry": nff.get("symmetry",""),
                        })
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

                # ── Status banner + remediation ───────────────────────────────────
                st.markdown("<br>", unsafe_allow_html=True)
                if status == "CRITICAL":
                    st.error("🚨 CRITICAL — Active SYN Flood Attack Detected on Pi", icon="🚨")
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("🛡️ Initiate Remediation", type="primary",
                                     use_container_width=True, key="pi_remediate"):
                            import requests as _req
                            with st.spinner("Applying iptables rules on Pi via SSH..."):
                                try:
                                    r = _req.post("http://localhost:5000/api/pi/remediate", timeout=15)
                                    result = r.json()
                                    if result.get("success"):
                                        st.success("✅ Remediation applied!")
                                        for rule in result["event"]["rules_applied"]:
                                            st.markdown(f"- {rule}")
                                        st.balloons()
                                    else:
                                        st.error("SSH failed — check PI_HOST in flask_server.py")
                                except Exception as e:
                                    st.error(f"Error: {e}")
                    with col2:
                        if st.button("🔓 Clear Rules", use_container_width=True, key="pi_clear"):
                            import requests as _req
                            _req.post("http://localhost:5000/api/pi/clear_rules", timeout=10)
                            st.info("iptables rules cleared on Pi")
                elif status == "WARNING":
                    st.warning("⚠️ WARNING — Unusual activity detected", icon="⚠️")
                else:
                    st.success("✅ System Secure — No active threats", icon="🛡️")

    st.divider()
    st.info("💡 Pro-Tip: Ensure `flask_server.py` is running and the Pi is sending telemetry to see the sample counter increase.")

    # ── Auto refresh ──────────────────────────────────────────────────────────────
    time.sleep(3)
    st.rerun()



# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
page = st.session_state.get("page", "fleet")

if page == "fleet":
    render_fleet_page()
    st.stop()
elif page == "dashboard":
    render_device_dashboard(autoencoder)
    st.stop()
elif page == "hardware_dashboard":
    render_hardware_dashboard(autoencoder)
    st.stop()
else:
    st.session_state.page = "fleet"
    st.rerun()