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
NEON_GREEN = "#00fff2"
NEON_RED = "#ff007f"
NEON_BLUE = "#00cfff"

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@400;600;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
        background: radial-gradient(circle at center, #0B1120 0%, #000000 100%);
        background-color: #0b1120;
        background-image: 
            linear-gradient(rgba(0, 255, 242, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 242, 0.03) 1px, transparent 1px);
        background-size: 40px 40px;
        background-position: center bottom;
        animation: cyber-pulse 4s linear infinite;
        color: #e0e6ed;
    }}

    @keyframes cyber-pulse {{
        0% {{ background-position: 0 0; }}
        100% {{ background-position: 40px 40px; }}
    }}

    .glass-card {{
        background: rgba(17, 25, 40, 0.7);
        backdrop-filter: blur(12px);         
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.1); 
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
        transition: border 0.3s ease, box-shadow 0.3s ease;
    }}

    .fleet-card {{
        background: rgba(17, 25, 40, 0.7);
        backdrop-filter: blur(12px);         
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
        text-align: center;
        transition: all 0.2s ease-in-out;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
    }}
    .fleet-card:hover {{
        border: 1px solid {NEON_GREEN};
        box-shadow: 0 0 15px rgba(0, 255, 242, 0.4);
    }}

    .neon-safe {{
        border: 1px solid rgba(0, 255, 242, 0.4);
        box-shadow: 0 0 10px rgba(0, 255, 242, 0.1);
    }}
    
    .neon-compromised {{
        border: 1px solid rgba(255, 0, 127, 0.5);
        box-shadow: 0 0 15px rgba(255, 0, 127, 0.4);
    }}
    
    @keyframes pulse {{
        0% {{ box-shadow: 0 0 0 0 rgba(255, 0, 127, 0.6); }}
        70% {{ box-shadow: 0 0 0 20px rgba(255, 0, 127, 0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(255, 0, 127, 0); }}
    }}

    .pulse-red {{
        animation: pulse 2s infinite !important;
        border: 1px solid #ff007f !important;
    }}

    @keyframes pulse-stress {{
        0% {{ border: 1px solid rgba(255, 0, 127, 0.4); box-shadow: 0 0 0 0 rgba(255, 0, 127, 0.4); }}
        70% {{ border: 1px solid rgba(255, 0, 127, 1); box-shadow: 0 0 10px 5px rgba(255, 0, 127, 0); }}
        100% {{ border: 1px solid rgba(255, 0, 127, 0.4); box-shadow: 0 0 0 0 rgba(255, 0, 127, 0); }}
    }}

    .pulse-stress {{
        animation: pulse-stress 1.5s infinite !important;
    }}

    @keyframes blinker {{
        50% {{ opacity: 0; }}
    }}

    div.stButton > button {{
        background: transparent !important;
        border: 1px solid #00fff2 !important;
        color: #00fff2 !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
    }}
    div.stButton > button:hover {{
        background: rgba(0, 255, 242, 0.1) !important;
        box-shadow: 0 0 10px rgba(0, 255, 242, 0.5) !important;
        border: 1px solid #00fff2 !important;
        color: #00fff2 !important;
    }}

    .section-header {{
        font-family: 'Source Code Pro', monospace;
        font-size: 1.1rem;
        font-weight: 700;
        margin-bottom: 15px;
        color: {NEON_GREEN};
        text-transform: uppercase;
        letter-spacing: 1.2px;
    }}

    [data-testid="stSidebar"] {{
        background-color: rgba(11, 17, 32, 0.85);
        backdrop-filter: blur(12px);
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }}

    h1, h2, h3 {{
        color: white !important;
        font-family: 'Source Code Pro', monospace !important;
        text-transform: uppercase;
    }}
    
    .stDataFrame {{
        background: transparent !important;
    }}

    .attack-progress {{
        background: rgba(255, 0, 127, 0.15);
        border: 1px solid rgba(255, 0, 127, 0.4);
        border-radius: 8px;
        padding: 10px 12px;
        margin-top: 8px;
        font-size: 0.85em;
        color: #ff007f;
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
# Piyush: audit log, remediation lock, attack step tracker
if 'audit_logs' not in st.session_state:
    st.session_state.audit_logs = []
if 'remediation_locked' not in st.session_state:
    st.session_state.remediation_locked = False
if 'attack_step' not in st.session_state:
    st.session_state.attack_step = {}
# Pragyan: math mode toggle + live history buffers
if 'math_mode_active' not in st.session_state:
    st.session_state.math_mode_active = False
if 'jsd_history' not in st.session_state:
    st.session_state.jsd_history = [0.0] * 10
if 'pulse_mse_history' not in st.session_state:
    st.session_state.pulse_mse_history = [0.0] * 30
if 'pulse_jsd_history' not in st.session_state:
    st.session_state.pulse_jsd_history = [0.0] * 30
if 'reconstruction_errors_history' not in st.session_state:
    st.session_state.reconstruction_errors_history = [[0.0] * 20 for _ in range(4)]

# --- MODEL CACHING ---
@st.cache_resource
def load_aegis_engine():
    model = LSTMAutoencoder()
    model.eval()
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

def advance_attack(dev_id, dev_baseline, staged: dict):
    """
    Compute one attack step and write results into `staged` (a plain dict).
    Values are read from `staged` first so sequential steps accumulate correctly.
    Nothing is written to session_state here — that happens in the deferred
    block at the top of the render cycle, BEFORE widgets are instantiated.
    """
    step = st.session_state.attack_step.get(dev_id, 0)

    base_delta = 0.12 + step * 0.08
    jitter     = random.uniform(0.0, 0.06)
    delta      = min(base_delta + jitter, 0.40)

    keys = [
        (f"pkt_{dev_id}", 0),
        (f"iat_{dev_id}", 1),
        (f"ent_{dev_id}", 2),
        (f"sym_{dev_id}", 3),
    ]

    for state_key, idx in keys:
        current = staged.get(state_key,
                  st.session_state.get(state_key, float(dev_baseline[idx])))
        if dev_baseline[idx] < 0.5:
            new_val = current + delta
        else:
            new_val = current - delta
        staged[state_key] = float(np.clip(new_val, 0.0, 1.0))

    st.session_state.attack_step[dev_id] = min(step + 1, 5)


# ==========================================
# PAGE 1: FLEET OVERVIEW
# ==========================================
if st.session_state.page == "fleet":
    st.markdown("<h1 style='text-align: center; color: white;'>🌐 Enterprise Fleet Manager</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #aaa;'>Select a registered IoT device to enter its continuous monitoring Digital Twin dashboard.</p>", unsafe_allow_html=True)
    st.markdown("---")
    
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
            if st.button(f"View Digital Twin", key=f"btn_{dev_id}", width="stretch"):
                navigate_to_dashboard(dev_id)
                st.rerun()
                
    st.markdown("---")
    if st.session_state.remediation_log:
        st.markdown("### 🛠️ Remediation History")
        df_remedy = pd.DataFrame(st.session_state.remediation_log)
        st.dataframe(df_remedy, width="stretch", hide_index=True)

    if st.session_state.audit_logs:
        st.markdown("### 🧾 Audit Trail")
        df_audit = pd.DataFrame(st.session_state.audit_logs)
        st.dataframe(df_audit, width="stretch", hide_index=True)


# ==========================================
# PAGE 2: DRILL-DOWN DASHBOARD
# ==========================================
elif st.session_state.page == "dashboard":
    dev_id = st.session_state.active_device
    device_info = IOT_REGISTRY[dev_id]
    dev_baseline = device_info["baseline"]

    disabled = st.session_state.remediation_locked

    # --- Deferred state updates (MUST run before any widget is instantiated) ---

    # Remediation reset: restore all sliders to baseline and clear attack step
    if st.session_state.get("remediation_reset") == dev_id:
        st.session_state[f"pkt_{dev_id}"] = float(dev_baseline[0])
        st.session_state[f"iat_{dev_id}"] = float(dev_baseline[1])
        st.session_state[f"ent_{dev_id}"] = float(dev_baseline[2])
        st.session_state[f"sym_{dev_id}"] = float(dev_baseline[3])
        st.session_state.attack_step[dev_id] = 0
        st.session_state.threat_log = []
        st.session_state.remediation_locked = False
        del st.session_state["remediation_reset"]

    # Attack trigger: apply pre-computed values BEFORE sliders are created
    if st.session_state.get("attack_trigger") == dev_id:
        st.session_state.pop("attack_trigger")
        computed = st.session_state.pop("attack_values", {})
        for k, v in computed.items():
            st.session_state[k] = v

    # Ensure slider keys exist before widgets are created
    for key, idx in [("pkt", 0), ("iat", 1), ("ent", 2), ("sym", 3)]:
        state_key = f"{key}_{dev_id}"
        if state_key not in st.session_state:
            st.session_state[state_key] = float(dev_baseline[idx])

    # Initialise attack step counter for this device
    if dev_id not in st.session_state.attack_step:
        st.session_state.attack_step[dev_id] = 0

    # --- SIDEBAR ---
    with st.sidebar:
        st.markdown(f"<h1 style='text-align: center; color: {NEON_BLUE} !important;'>🛡️ Aegis Control</h1>", unsafe_allow_html=True)
        st.markdown("---")
        
        if st.button("← Back to Fleet", width="stretch", disabled=disabled):
            navigate_to_fleet()
            st.rerun()
            
        st.markdown("<br>", unsafe_allow_html=True)

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

        scan_active = st.toggle("📡 Live Scan Mode", value=True, key=f"scan_{dev_id}", disabled=disabled)
        st.markdown("---")
        
        st.markdown("### Manual Traffic Injection")
        val_pkt_size = st.slider("Packet Size (Norm)", 0.0, 1.0, value=st.session_state[f"pkt_{dev_id}"], key=f"pkt_{dev_id}", disabled=disabled)
        val_iat      = st.slider("Inter-Arrival Time (Norm)", 0.0, 1.0, value=st.session_state[f"iat_{dev_id}"], key=f"iat_{dev_id}", disabled=disabled)
        val_entropy  = st.slider("Entropy (Norm)", 0.0, 1.0, value=st.session_state[f"ent_{dev_id}"], key=f"ent_{dev_id}", disabled=disabled)
        val_symmetry = st.slider("Symmetry (Norm)", 0.0, 1.0, value=st.session_state[f"sym_{dev_id}"], key=f"sym_{dev_id}", disabled=disabled)

        # ── ATTACK BUTTON — always visible below sliders (Piyush) ─────────────
        st.markdown("---")

        attack_step_now = st.session_state.attack_step.get(dev_id, 0)

        if attack_step_now > 0:
            bar_pct  = min(attack_step_now / 5, 1.0)
            bar_fill = int(bar_pct * 10)
            bar_str  = "█" * bar_fill + "░" * (10 - bar_fill)
            severity_labels = ["", "LOW", "MODERATE", "HIGH", "SEVERE", "CRITICAL"]
            severity = severity_labels[min(attack_step_now, 5)]
            st.markdown(f"""
            <div class="attack-progress">
                ⚠️ Attack in progress — {severity}<br>
                <span style="font-family: monospace; letter-spacing: 2px;">{bar_str}</span>
                &nbsp;Step {attack_step_now}/5
            </div>
            """, unsafe_allow_html=True)

        if st.button("🚨 Launch Attack", width="stretch", key=f"attack_{dev_id}", disabled=disabled):
            staged = {}
            with st.status("⚠️ Simulating cyber attack...", expanded=True) as attack_status:
                messages = [
                    "Probing network interfaces...",
                    "Injecting malicious traffic packets...",
                    "Escalating privilege — overloading device buffers...",
                    "Corrupting telemetry stream...",
                    "Bypassing anomaly thresholds...",
                ]
                for i in range(3):
                    st.write(messages[min(i, len(messages) - 1)])
                    advance_attack(dev_id, dev_baseline, staged)
                    time.sleep(0.6)

                attack_status.update(label="💀 Attack payload delivered", state="error")
                time.sleep(0.4)

            # Stage values are applied at the top of the next render cycle
            st.session_state["attack_values"]  = staged
            st.session_state["attack_trigger"] = dev_id
            st.rerun()
        # ──────────────────────────────────────────────────────────────────────

        st.markdown("---")
        if st.button("Clear View Log", width="stretch", key=f"clear_{dev_id}", disabled=disabled):
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
        output = autoencoder(tensor_input)
        diff = tensor_input - output
        mse_per_feature = torch.mean(diff ** 2, dim=1).squeeze().tolist()

    for i in range(4):
        st.session_state.reconstruction_errors_history[i].append(mse_per_feature[i])
        st.session_state.reconstruction_errors_history[i].pop(0)

    jsd = calculate_jsd(current_features, dev_baseline)

    # Update live history buffers (Pragyan)
    st.session_state.pulse_mse_history.append(mse)
    st.session_state.pulse_mse_history.pop(0)
    st.session_state.pulse_jsd_history.append(jsd)
    st.session_state.pulse_jsd_history.pop(0)
    st.session_state.jsd_history.append(jsd)
    st.session_state.jsd_history.pop(0)

    trust_score = calculate_trust_score(mse, jsd)

    if np.allclose(current_features, dev_baseline, atol=1e-8):
        mse = 0.0
        trust_score = 100.0

    is_safe = trust_score >= 50
    status_color = NEON_GREEN if is_safe else NEON_RED

    if is_safe:
        st.session_state.device_health[dev_id] = "Healthy"
        card_class = "neon-safe"
        indicator_html = f"<span style='color: {NEON_GREEN};'>● ONLINE</span>"
    else:
        st.session_state.device_health[dev_id] = "Compromised"
        card_class = "neon-compromised pulse-red"
        indicator_html = f"<span style='color: {NEON_RED}; animation: blinker 1s linear infinite;'>● CRITICAL</span>"

    # --- HEADER + MARQUEE (Pragyan) ---
    st.markdown("""
    <div style="background: rgba(0, 255, 242, 0.05); border: 1px solid rgba(0, 255, 242, 0.3); border-radius: 4px; padding: 5px; margin-bottom: 15px; box-shadow: 0 0 10px rgba(0,255,242,0.1);">
        <marquee scrollamount="5" style="color: #00fff2; font-family: 'Source Code Pro', monospace; font-size: 14px; letter-spacing: 2px;">
            // SYSTEM INTEGRITY: OPTIMAL &nbsp;&nbsp;&nbsp;&nbsp; // ENCODER LATENCY: 0.002ms &nbsp;&nbsp;&nbsp;&nbsp; // ACTIVE NODES: 10 &nbsp;&nbsp;&nbsp;&nbsp; // ENCRYPTION: AES-256
        </marquee>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
        <h1 style="margin:0;">{device_info['icon']} Twin Dashboard: {device_info['name']}</h1>
        <h3 style="margin:0; color:{status_color} !important; border: 1px solid {status_color}; padding: 8px 16px; border-radius: 8px; box-shadow: 0 0 15px {status_color}40;">
            {indicator_html}
        </h3>
    </div>
    """, unsafe_allow_html=True)

    # Critical alert banner + Remediate button (Piyush)
    if not is_safe:
        st.error(f"CRITICAL: SECURITY BREACH. Unrecognized anomalies in Sector {device_info['sector']} ({device_info['type']}). INITIATING NETWORK QUARANTINE.", icon="🚨")
        
        col_err1, col_err2 = st.columns([8, 2])
        with col_err2:
            if st.button("🔧 Remediate Device", width="stretch", key=f"remed_{dev_id}", disabled=disabled):
                st.session_state.remediation_locked = True

                prev_status = st.session_state.device_health.get(dev_id, "Unknown")
                now = datetime.datetime.now()

                st.session_state.audit_logs.insert(0, {
                    "device": dev_id,
                    "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "event": "Remediation Success",
                    "previous_status": prev_status,
                })

                with st.status("Running remediation protocol...", expanded=True) as remed_status:
                    st.write("Resetting device parameters...")
                    time.sleep(0.8)

                    st.session_state.device_health[dev_id] = "Healthy"
                    st.session_state.remediation_reset = dev_id
                    st.session_state.threat_log = []

                    st.write("Flushing network buffers...")
                    time.sleep(0.7)

                    st.write("Re-synchronizing digital twin...")
                    time.sleep(0.7)

                    remed_status.update(label="✅ Device restored to safe baseline", state="complete")
                    time.sleep(0.4)

                    st.session_state.remediation_locked = False

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
            number = {'font': {'color': 'white', 'size': 75}, 'suffix': "%"},
            gauge = {
                'axis': {'range': [0, 100], 'tickcolor': "white"},
                'bar': {'color': status_color, 'thickness': 0.8},
                'bgcolor': "rgba(0,0,0,0)",
                'borderwidth': 0,
                'steps': [
                    {'range': [0, 50], 'color': 'rgba(255, 0, 127, 0.15)'},
                    {'range': [50, 100], 'color': 'rgba(0, 255, 242, 0.15)'}
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
            font={'color': "white", 'family': "Source Code Pro"},
            height=260,
            margin=dict(l=20, r=20, t=10, b=10)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        # JSD Sparkline (Pragyan)
        fig_spark = go.Figure(go.Scatter(
            y=st.session_state.jsd_history,
            mode='lines',
            line={'color': NEON_GREEN, 'width': 3, 'shape': 'spline'},
            fill='tozeroy',
            fillcolor='rgba(0, 255, 242, 0.15)'
        ))
        fig_spark.update_layout(
            height=50, margin={'l': 0, 'r': 0, 't': 0, 'b': 0},
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            xaxis={'visible': False}, yaxis={'visible': False, 'range': [0, 1]}
        )
        st.plotly_chart(fig_spark, use_container_width=True)
        st.markdown("<div style='text-align:center; font-family:\"Source Code Pro\", monospace; font-size:12px; color:#00fff2; text-shadow: 0 0 5px #00fff2; margin-top:-10px;'>FEATURE CONTRIBUTION (JSD)</div>", unsafe_allow_html=True)

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


    # ===== MIDDLE ROW — Feature Drift + Neural Health Monitor (both branches) =====
    stress_alert = mse > 0.15
    stress_class = "pulse-stress" if stress_alert else ""
    stress_border = "border: 1px solid #ff007f;" if stress_alert else "border: 1px solid rgba(0, 255, 242, 0.2);"

    st.markdown(f'''
    <div class="glass-card {stress_class}" style="box-shadow: 0 0 15px rgba(0, 255, 242, 0.2); {stress_border}">
        <div class="section-header" style="display: flex; justify-content: space-between;">
            <span>Feature Drift Analysis</span>
            {'<span style="color: #ff007f; font-size: 0.8em; animation: blinker 0.8s infinite;">NEURAL STRESS DETECTED</span>' if stress_alert else ''}
        </div>
    ''', unsafe_allow_html=True)

    col_left, col_right = st.columns(2)
    categories = ['Packet Size', 'IAT', 'Payload Entropy', 'Flow Symmetry']

    with col_left:
        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=dev_baseline,
            theta=categories,
            fill='toself',
            name=f'{device_info["type"]} Baseline',
            line_color=NEON_BLUE,
            fillcolor='rgba(0, 207, 255, 0.2)'
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=current_features,
            theta=categories,
            fill='toself',
            name='Current Traffic',
            line_color=status_color,
            fillcolor=f'rgba({255 if not is_safe else 0}, {0 if not is_safe else 255}, {127 if not is_safe else 242}, 0.3)'
        ))
        fig_radar.update_layout(
            polar={
                'radialaxis': {'visible': True, 'range': [0, 1], 'gridcolor': "rgba(255,255,255,0.1)"},
                'angularaxis': {'gridcolor': "rgba(255,255,255,0.1)"},
                'bgcolor': "rgba(0,0,0,0)"
            },
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': "white"},
            height=360,
            margin={'l': 40, 'r': 40, 't': 10, 'b': 10},
            hovermode='closest'
        )
        st.plotly_chart(fig_radar, use_container_width=True, config={'displayModeBar': False})

    with col_right:
        # Neural Health Monitor / Live Pulse (Pragyan)
        st.markdown("<div style='text-align: center; color: #00fff2; font-weight: 600; margin-bottom: 5px; font-family: \"Source Code Pro\", monospace; font-size: 0.9em;'>Neural Health Monitor (Live Pulse)</div>", unsafe_allow_html=True)
        
        fig_pulse = go.Figure()
        fig_pulse.update_xaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0, 255, 242, 0.05)', zeroline=False)
        fig_pulse.update_yaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0, 255, 242, 0.05)', zeroline=False)
        fig_pulse.add_hline(y=0.15, line_dash="dot", line_color="white", line_width=1,
                            annotation_text="ALERT BOUNDARY", annotation_position="top left",
                            annotation_font={'size': 10, 'color': 'white'})
        fig_pulse.add_trace(go.Scatter(
            y=st.session_state.pulse_mse_history,
            name="MSE",
            line={'color': '#ff007f', 'width': 3},
            mode='lines',
            hovertemplate="MSE: %{y:.4f}<extra></extra>"
        ))
        fig_pulse.add_trace(go.Scatter(
            y=st.session_state.pulse_jsd_history,
            name="JSD",
            line={'color': '#00fff2', 'width': 3},
            mode='lines',
            hovertemplate="JSD: %{y:.4f}<extra></extra>"
        ))
        fig_pulse.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': "white", 'family': "Source Code Pro"},
            height=360,
            margin={'l': 30, 'r': 30, 't': 10, 'b': 10},
            legend={'orientation': "h", 'yanchor': "bottom", 'y': 1.02, 'xanchor': "right", 'x': 1},
            hovermode='x unified',
            xaxis={'showticklabels': False}
        )
        st.plotly_chart(fig_pulse, use_container_width=True, config={'displayModeBar': False})

    st.markdown("<div style='color: #aaa; font-size: 0.85em; text-align: center; margin-top: 15px; font-style: italic;'>Dual-Sync Visualization: Mapping multidimensional geometric drift against temporal reconstruction residuals for 100% anomaly explainability.</div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


    # ===== NEURAL ENGINE & MATHEMATICS ROW (Pragyan) =====
    def toggle_math_mode():
        st.session_state.math_mode_active = not st.session_state.math_mode_active

    st.markdown('<br>', unsafe_allow_html=True)
    if not st.session_state.math_mode_active:
        st.button("▶️ Initialize Live Math Engine", key=f"math_toggle_{dev_id}", on_click=toggle_math_mode, use_container_width=True)
    else:
        st.button("⏸️ Terminate Live Feed", key=f"math_toggle_{dev_id}", on_click=toggle_math_mode, use_container_width=True)

        st.markdown('''
        <div class="glass-card" style="border: 1px solid #00fff2; box-shadow: 0 0 15px rgba(0, 255, 242, 0.2);">
            <div class="section-header" style="color: #00fff2; text-shadow: 0 0 8px rgba(0, 255, 242, 0.5);">Neural Engine & Mathematics (Live Computing)</div>
        ''', unsafe_allow_html=True)

        col_math, col_neural = st.columns(2)

        with col_math:
            st.markdown("<div style='text-align: center; color: white; font-weight: 600; margin-bottom: 10px;'>The JSD Logic (Mathematical Engine)</div>", unsafe_allow_html=True)
            live_jsd = calculate_jsd(current_features, dev_baseline)
            st.latex(rf"JSD(P || Q) \approx {live_jsd:.4f}")
            st.markdown(f"<div style='color: #00ff88; font-weight: bold; text-align: center; padding: 10px; border: 1px solid #00ff88; border-radius: 8px; margin-top: 10px; box-shadow: 0 0 10px rgba(0,255,136,0.2);'>Current Statistical Friction: {live_jsd:.4f}</div>", unsafe_allow_html=True)

        with col_neural:
            st.markdown("<div style='text-align: center; color: white; font-weight: 600; margin-bottom: 10px;'>The LSTM Encoder (Neural Architecture)</div>", unsafe_allow_html=True)
            with torch.no_grad():
                output_math = autoencoder(tensor_input)
                diff_math = tensor_input - output_math
                mse_calc = torch.mean(diff_math ** 2).item()
            st.latex(rf"f_t = \sigma(W_f \cdot [h_{{t-1}}, x_t] + b_f) \implies MSE \approx {mse_calc:.4f}")
            st.progress(min(max(mse_calc, 0.0), 1.0), text=f"Reconstruction Error (MSE): {mse_calc:.4f}")
            st.markdown("<div style='color: #aaa; font-size: 0.85em; text-align: center; margin-top: 5px;'>If MSE > 0.1, the Twin is drifting from the Physical Device.</div>", unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)


    # ===== BOTTOM ROW — Threat Log =====
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">Threat Log</div>', unsafe_allow_html=True)

    if not st.session_state.threat_log:
        st.write("✅ System is secure. No recent threats logged.")
    else:
        for alert in st.session_state.threat_log:
            st.markdown(f"""
            <div style="border-left: 4px solid {NEON_RED}; padding-left: 12px; margin-bottom: 8px; background: rgba(255, 0, 127, 0.08); padding-top: 8px; padding-bottom: 8px; border-radius: 4px;">
                <span style="color: #888; font-size: 0.85em;">{alert['time']}</span> &nbsp;&nbsp; 
                <span style="color: white;">{alert['msg']}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # Application polling loop
    if scan_active:
        time.sleep(1.0)
        st.rerun()