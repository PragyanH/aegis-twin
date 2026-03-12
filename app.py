"""
Aegis-Twin · AI-Driven Digital Twin Dashboard
==============================================
Enterprise Fleet Manager Edition.
Includes a multi-device IoT Registry, Fleet Overview, and deep-dive
anomaly dashboard powered by PyTorch and the LSTM Autoencoder engines.

Run with: streamlit run app.py
"""

import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import time
import datetime
import random
import torch

from engine import calculate_trust_score, calculate_jsd
from model import LSTMAutoencoder

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Aegis-Twin Fleet Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- THEME & CSS (Glassmorphism + Dark Theme) ---
NEON_GREEN = "#00ff88"
NEON_RED = "#ff2d55"
NEON_BLUE = "#00cfff"

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
        background-color: #05070a;
        background-image: 
            linear-gradient(rgba(0, 207, 255, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 207, 255, 0.05) 1px, transparent 1px);
        background-size: 40px 40px;
        background-position: center bottom;
        animation: cyber-pulse 4s linear infinite;
        color: #e0e6ed;
    }}

    @keyframes cyber-pulse {{
        0% {{ background-position: 0 0; }}
        100% {{ background-position: 40px 40px; }}
    }}

    /* Glassmorphism Card Style */
    .glass-card {{
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(14px);         
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(0, 207, 255, 0.2); 
        border-top: 1px solid rgba(255, 255, 255, 0.3);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
        transition: border 0.3s ease, box-shadow 0.3s ease;
    }}

    .fleet-card {{
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(0, 255, 136, 0.3);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
        text-align: center;
        transition: all 0.2s ease-in-out;
    }}
    .fleet-card:hover {{
        border: 1px solid {NEON_BLUE};
        box-shadow: 0 0 15px rgba(0, 207, 255, 0.4);
    }}

    /* Neon Borders */
    .neon-safe {{
        border: 1px solid rgba(0, 255, 136, 0.4);
        box-shadow: 0 0 10px rgba(0, 255, 136, 0.1);
    }}
    
    .neon-compromised {{
        border: 1px solid rgba(255, 45, 85, 0.5);
        box-shadow: 0 0 15px rgba(255, 45, 85, 0.2);
    }}
    
    /* Pulsing Red Animation */
    @keyframes pulse-red {{
        0% {{ box-shadow: 0 0 0 0 rgba(255, 45, 85, 0.4); }}
        70% {{ box-shadow: 0 0 0 15px rgba(255, 45, 85, 0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(255, 45, 85, 0); }}
    }}

    .pulse-red {{
        animation: pulse-red 2s infinite;
        border: 1px solid rgba(255, 45, 85, 0.5) !important;
    }}

    @keyframes blinker {{
        50% {{ opacity: 0; }}
    }}

    /* Ghost Buttons */
    div.stButton > button {{
        background: transparent !important;
        border: 1px solid #00cfff !important;
        color: #00cfff !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
    }}
    div.stButton > button:hover {{
        background: rgba(0, 207, 255, 0.1) !important;
        box-shadow: 0 0 10px rgba(0, 207, 255, 0.5) !important;
        border: 1px solid #00ff88 !important;
        color: #00ff88 !important;
    }}

    .section-header {{
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 15px;
        color: {NEON_BLUE};
        text-transform: uppercase;
        letter-spacing: 1.2px;
    }}

    /* Sidebar styling */
    [data-testid="stSidebar"] {{
        background-color: rgba(10, 12, 18, 0.95);
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }}

    h1, h2, h3 {{
        color: white !important;
    }}
    
    /* Table Styling */
    .stDataFrame {{
        background: transparent !important;
    }}
</style>
""", unsafe_allow_html=True)

# --- IOT ENTERPRISE REGISTRY ---
IOT_REGISTRY = {
    "DEV-001": {"name": "AEGIS-PUMP-01", "type": "Pump", "sector": "1", "baseline": [0.4, 0.5, 0.3, 0.6], "icon": "🚰"},
    "DEV-002": {"name": "Assembly Arm", "type": "Robotic Arm", "sector": "2", "baseline": [0.6, 0.3, 0.7, 0.5], "icon": "🦾"},
    "DEV-003": {"name": "Grid Node 0X", "type": "Smart Grid Node", "sector": "3", "baseline": [0.3, 0.8, 0.4, 0.5], "icon": "⚡"},
    "DEV-004": {"name": "Cryo-Storage A", "type": "Bio-Storage Fridge", "sector": "4", "baseline": [0.2, 0.6, 0.2, 0.8], "icon": "❄️"},
    "DEV-005": {"name": "Mixer V-12", "type": "Chemical Mixer", "sector": "5", "baseline": [0.5, 0.5, 0.6, 0.4], "icon": "🧪"},
    "DEV-006": {"name": "Security Cam 1", "type": "Camera", "sector": "6", "baseline": [0.8, 0.2, 0.4, 0.9], "icon": "📷"},
    "DEV-007": {"name": "Security Cam 2", "type": "Camera", "sector": "7", "baseline": [0.8, 0.2, 0.3, 0.8], "icon": "📷"},
    "DEV-008": {"name": "Coolant Pump", "type": "Pump", "sector": "8", "baseline": [0.5, 0.4, 0.4, 0.6], "icon": "⚙️"},
    "DEV-009": {"name": "Welding Arm", "type": "Robotic Arm", "sector": "9", "baseline": [0.7, 0.2, 0.8, 0.4], "icon": "🤖"},
    "DEV-010": {"name": "Main Grid Relay", "type": "Smart Grid Node", "sector": "7-G", "baseline": [0.4, 0.7, 0.5, 0.6], "icon": "🔌"},
}

# --- SESSION STATE ---
if 'page' not in st.session_state:
    st.session_state.page = "fleet"
if 'active_device' not in st.session_state:
    st.session_state.active_device = None
if 'device_health' not in st.session_state:
    st.session_state.device_health = {k: "Healthy" for k in IOT_REGISTRY.keys()}
if 'packet_history' not in st.session_state:
    st.session_state.packet_history = pd.DataFrame(columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"])
if 'threat_log' not in st.session_state:
    st.session_state.threat_log = []
if 'remediation_log' not in st.session_state:
    st.session_state.remediation_log = []

# --- MODEL CACHING ---
@st.cache_resource
def load_aegis_engine():
    model = LSTMAutoencoder()
    model.eval()  # ensure inference mode
    return model

autoencoder = load_aegis_engine()

def navigate_to_dashboard(dev_id):
    st.session_state.active_device = dev_id
    st.session_state.page = "dashboard"
    st.session_state.packet_history = pd.DataFrame(columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"])
    st.session_state.threat_log = []

def navigate_to_fleet():
    st.session_state.active_device = None
    st.session_state.page = "fleet"

# ==========================================
# PAGE 1: FLEET OVERVIEW
# ==========================================
if st.session_state.page == "fleet":
    st.markdown("<h1 style='text-align: center; color: white;'>🌐 Enterprise Fleet Manager</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #aaa;'>Select a registered IoT device to enter its continuous monitoring Digital Twin dashboard.</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Create a 4-column grid
    cols = st.columns(4)
    for idx, (dev_id, info) in enumerate(IOT_REGISTRY.items()):
        col = cols[idx % 4]
        with col:
            health = st.session_state.device_health.get(dev_id, 'Healthy')
            h_color = NEON_GREEN if health == 'Healthy' else NEON_RED
            h_text = "● ONLINE" if health == 'Healthy' else "● CRITICAL"
            h_anim = "none" if health == 'Healthy' else "blinker 1s linear infinite"
            
            st.markdown(f"""
            <div class="fleet-card">
                <div style="font-size: 3rem;">{info['icon']}</div>
                <h3 style="color: white; margin-bottom: 5px;">{info['name']}</h3>
                <p style="color: #00cfff; font-size: 0.9em; margin-bottom: 5px;">ID: {dev_id}</p>
                <p style="color: #aaa; font-size: 0.8em; margin-bottom: 15px;">Sector: {info['sector']} | Type: {info['type']}</p>
                <div style="color: {h_color}; font-weight: bold; margin-bottom: 10px; animation: {h_anim};">{h_text}</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"View Digital Twin", key=f"btn_{dev_id}", use_container_width=True):
                navigate_to_dashboard(dev_id)
                st.rerun()
                
    st.markdown("---")
    if st.session_state.remediation_log:
        st.markdown("### 🛠️ Remediation History")
        df_remedy = pd.DataFrame(st.session_state.remediation_log)
        st.dataframe(df_remedy, use_container_width=True, hide_index=True)


# ==========================================
# PAGE 2: DRILL-DOWN DASHBOARD
# ==========================================
elif st.session_state.page == "dashboard":
    dev_id = st.session_state.active_device
    device_info = IOT_REGISTRY[dev_id]
    dev_baseline = device_info["baseline"]

    # --- SIDEBAR & DEVICE REGISTRY ---
    with st.sidebar:
        st.markdown(f"<h1 style='text-align: center; color: {NEON_BLUE} !important;'>🛡️ Aegis Control</h1>", unsafe_allow_html=True)
        st.markdown("---")
        
        # Back Button
        if st.button("← Back to Fleet", use_container_width=True):
            navigate_to_fleet()
            st.rerun()
            
        st.markdown("<br>", unsafe_allow_html=True)

        # IoT Identity Card
        st.markdown(f"""
            <div style="background: rgba(0, 207, 255, 0.05); padding: 15px; border-radius: 8px; border-left: 4px solid #00cfff; margin-bottom: 20px;">
                <small style="color: #00cfff; font-weight: bold;">[ DEVICE REGISTRY ]</small><br>
                <div style="display: flex; align-items: center; gap: 10px; margin-top: 5px;">
                    <span style="font-size: 2em;">{device_info['icon']}</span>
                    <div>
                        <strong style="color: white; font-size: 1.1em;">{device_info['name']}</strong><br>
                        <span style="color: #aaa; font-size: 0.9em;">ID: {dev_id}</span><br>
                        <span style="color: #aaa; font-size: 0.9em;">Loc: Sector {device_info['sector']}</span>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        scan_active = st.toggle("📡 Live Scan Mode", value=True, key=f"scan_{dev_id}")
        st.markdown("---")
        
        st.markdown("### Manual Traffic Injection")
        # Initialize sliders around baseline
        val_pkt_size = st.slider("Packet Size (Norm)", 0.0, 1.0, float(dev_baseline[0]), key=f"pkt_{dev_id}")
        val_iat = st.slider("Inter-Arrival Time (Norm)", 0.0, 1.0, float(dev_baseline[1]), key=f"iat_{dev_id}")
        val_entropy = st.slider("Entropy (Norm)", 0.0, 1.0, float(dev_baseline[2]), key=f"ent_{dev_id}")
        val_symmetry = st.slider("Symmetry (Norm)", 0.0, 1.0, float(dev_baseline[3]), key=f"sym_{dev_id}")

        st.markdown("---")
        if st.button("Clear View Log", use_container_width=True, key=f"clear_{dev_id}"):
            st.session_state.packet_history = pd.DataFrame(columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"])
            st.session_state.threat_log = []
            st.rerun()

    # --- AUTOENCODER INFERENCE ---
    current_features = np.array([val_pkt_size, val_iat, val_entropy, val_symmetry])
    feature_sequence = np.tile(current_features, (1, 10, 1))
    tensor_input = torch.tensor(feature_sequence, dtype=torch.float32)

    with torch.no_grad():
        mse_tensor = autoencoder.reconstruction_error(tensor_input)
        mse = float(mse_tensor.item())

    jsd = calculate_jsd(current_features, dev_baseline)
    trust_score = calculate_trust_score(mse, jsd)

    is_safe = trust_score >= 50
    status_color = NEON_GREEN if is_safe else NEON_RED
    status_text = "SAFE" if is_safe else "COMPROMISED"

    if is_safe:
        st.session_state.device_health[dev_id] = "Healthy"
        card_class = "neon-safe"
        indicator_html = f"<span style='color: {NEON_GREEN};'>● ONLINE</span>"
    else:
        st.session_state.device_health[dev_id] = "Compromised"
        card_class = "neon-compromised pulse-red"
        indicator_html = f"<span style='color: {NEON_RED}; animation: blinker 1s linear infinite;'>● CRITICAL</span>"

    # --- MAIN LAYOUT : BENTO GRID ---
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
        <h1 style="margin:0;">{device_info['icon']} Twin Dashboard: {device_info['name']}</h1>
        <h3 style="margin:0; color:{status_color} !important; border: 1px solid {status_color}; padding: 8px 16px; border-radius: 8px;">
            {indicator_html}
        </h3>
    </div>
    """, unsafe_allow_html=True)

    # Trigger alerts implicitly based on state
    if not is_safe:
        st.error(f"CRITICAL: SECURITY BREACH. Unrecognized anomalies in Sector {device_info['sector']} ({device_info['type']}). INITIATING NETWORK QUARANTINE.", icon="🚨")
        
        # Remediate Action Hook
        col_err1, col_err2 = st.columns([8, 2])
        with col_err2:
            if st.button("🔧 Remediate Device", use_container_width=True, key=f"remed_{dev_id}"):
                # Log remediation
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.session_state.remediation_log.append({
                    "Timestamp": now_str,
                    "Device ID": dev_id,
                    "Device Name": device_info['name'],
                    "Sector": device_info['sector'],
                    "Action Taken": "Quarantine Lifted & Params Reset"
                })
                # Heal the device globally
                st.session_state.device_health[dev_id] = "Healthy"
                # Reset sliders natively
                st.session_state[f"pkt_{dev_id}"] = float(dev_baseline[0])
                st.session_state[f"iat_{dev_id}"] = float(dev_baseline[1])
                st.session_state[f"ent_{dev_id}"] = float(dev_baseline[2])
                st.session_state[f"sym_{dev_id}"] = float(dev_baseline[3])
                
                st.session_state.threat_log = []
                st.success("Remediation Complete.")
                time.sleep(1.0)
                st.rerun()

    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    
    if scan_active:
        new_packet = {
            "Time": now_str,
            "Pkt Size": round(random.uniform(64, 1500), 1),
            "IAT": round(random.uniform(0.001, 0.05), 4),
            "Entropy": round(random.uniform(3, 7.5), 2),
            "Symmetry": round(random.uniform(0.4, 0.9), 2),
            "Status": "Safe" if is_safe else "Alert"
        }
        df_new = pd.DataFrame([new_packet])
        st.session_state.packet_history = pd.concat([df_new, st.session_state.packet_history], ignore_index=True).head(12)

        if not is_safe:
            # Check if this precise second was logged to avoid massive duplicates 
            # (though with sleep it's less an issue)
            if not st.session_state.threat_log or st.session_state.threat_log[0]["time"] != now_str:
                st.session_state.threat_log.insert(0, {
                    "time": now_str,
                    "msg": f"Anomalous flow detected! Trust dropped to {trust_score}%. MSE: {mse:.3f}"
                })
                st.session_state.threat_log = st.session_state.threat_log[:20]

    # ===== TOP ROW =====
    top_col1, top_col2 = st.columns([1, 1.5])

    with top_col1:
        st.markdown(f'<div class="glass-card {card_class}">', unsafe_allow_html=True)
        st.markdown('<div class="section-header">System Trust Gauge</div>', unsafe_allow_html=True)
        
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = trust_score,
            number = {'font': {'color': 'white', 'size': 60}, 'suffix': "%"},
            gauge = {
                'axis': {'range': [0, 100], 'tickcolor': "white"},
                'bar': {'color': status_color, 'thickness': 0.8},
                'bgcolor': "rgba(0,0,0,0)",
                'borderwidth': 0,
                'steps': [
                    {'range': [0, 50], 'color': 'rgba(255, 45, 85, 0.15)'},
                    {'range': [50, 100], 'color': 'rgba(0, 255, 136, 0.15)'}
                ],
                'threshold': {
                    'line': {'color': 'white', 'width': 3},
                    'thickness': 0.9,
                    'value': trust_score
                }
            }
        ))
        fig_gauge.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': "white", 'family': "Inter"},
            height=320,
            margin=dict(l=30, r=30, t=10, b=10)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with top_col2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-header">Live Packet Stream</div>', unsafe_allow_html=True)
        
        def color_status(val):
            color = NEON_RED if val == 'Alert' else NEON_GREEN
            return f'color: {color}'
            
        styled_df = st.session_state.packet_history.style.map(color_status, subset=['Status'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True, height=320)
        st.markdown('</div>', unsafe_allow_html=True)


    # ===== MIDDLE ROW =====
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">Feature Drift Analysis</div>', unsafe_allow_html=True)

    categories = ['Packet Size', 'IAT', 'Payload Entropy', 'Flow Symmetry']

    fig_radar = go.Figure()
    # Baseline
    fig_radar.add_trace(go.Scatterpolar(
        r=dev_baseline,
        theta=categories,
        fill='toself',
        name=f'{device_info["type"]} Baseline',
        line_color=NEON_BLUE,
        fillcolor='rgba(0, 207, 255, 0.2)'
    ))
    # Current
    fig_radar.add_trace(go.Scatterpolar(
        r=current_features,
        theta=categories,
        fill='toself',
        name='Current Traffic',
        line_color=status_color,
        fillcolor=f'rgba({255 if not is_safe else 0}, {45 if not is_safe else 255}, {85 if not is_safe else 136}, 0.3)'
    ))
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 1], gridcolor="rgba(255,255,255,0.1)"),
            angularaxis=dict(gridcolor="rgba(255,255,255,0.1)"),
            bgcolor="rgba(0,0,0,0)"
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': "white"},
        height=400,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    st.plotly_chart(fig_radar, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)


    # ===== BOTTOM ROW =====
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">Threat Log</div>', unsafe_allow_html=True)

    if not st.session_state.threat_log:
        st.write("✅ System is secure. No recent threats logged.")
    else:
        for alert in st.session_state.threat_log:
            st.markdown(f"""
            <div style="border-left: 4px solid {NEON_RED}; padding-left: 12px; margin-bottom: 8px; background: rgba(255, 45, 85, 0.08); padding-top: 8px; padding-bottom: 8px; border-radius: 4px;">
                <span style="color: #888; font-size: 0.85em;">{alert['time']}</span> &nbsp;&nbsp; 
                <span style="color: white;">{alert['msg']}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # Application polling loop
    if scan_active:
        time.sleep(1.0)
        st.rerun()
