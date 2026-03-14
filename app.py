"""
Aegis-Twin · AI-Driven Digital Twin Dashboard
==============================================
Enterprise Fleet Manager Edition.

Run with: streamlit run app.py
"""

import os

import pandas as pd
import streamlit as st
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

        # Search box
        search_query = st.text_input(
            "", placeholder="🔍 Search devices...",
            key="registry_search",
            label_visibility="collapsed",
        )

        # Column headers (outside scroll container)
        h1, h2, h3, h4, h5 = st.columns([1, 1.8, 2.2, 1.8, 1.2])
        for col, label in zip([h1, h2, h3, h4, h5], ["", "ID", "NAME", "TYPE", "STATUS"]):
            col.markdown(f"<span style='color:#555;font-size:0.78em;font-family:monospace;'>{label}</span>", unsafe_allow_html=True)
        st.markdown("<hr style='margin:2px 0 4px 0;border-color:rgba(0,255,242,0.15);'>", unsafe_allow_html=True)

        # st.container(height=N) is the ONLY reliable way to scroll native Streamlit widgets
        scroll_box = st.container(height=310, border=False)

        with scroll_box:
            any_shown = False
            for dev_id, info in IOT_REGISTRY.items():
                search_text = f"{dev_id} {info['name']} {info['type']}".lower()
                if search_query and search_query.lower() not in search_text:
                    continue
                any_shown = True
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

    # ── Real-Time Hardware Integration ────────────────────────────────────────
    st.markdown("## 🔌 Real-Time Hardware Integration")
    st.markdown(
        "Live devices monitored via Scapy packet capture on your local network. "
        "Requires administrator / root privileges."
    )

    hw_cols = st.columns(4)
    for hw_idx, (hw_id, hw_info) in enumerate(HARDWARE_REGISTRY.items()):
        with hw_cols[hw_idx % 4]:
            st.markdown(f"""
            <div class="fleet-card" style="border:1px solid rgba(0,255,136,0.3);">
                <div style="font-size:3rem;">{hw_info['icon']}</div>
                <h3 style="color:white;margin-bottom:5px;">{hw_info['name']}</h3>
                <p style="color:#00cfff;font-size:0.9em;margin-bottom:5px;">ID: {hw_id}</p>
                <p style="color:#aaa;font-size:0.8em;margin-bottom:15px;">
                    Sector: {hw_info['sector']} | Type: {hw_info['type']}
                </p>
                <div style="color:{NEON_GREEN};font-weight:bold;margin-bottom:10px;">
                    ● LIVE
                </div>
            </div>""", unsafe_allow_html=True)

            with st.expander("⚙️ Device Setup"):
                mac_input = st.text_input(
                    "MAC Address",
                    value=HARDWARE_REGISTRY[hw_id].get("mac", ""),
                    placeholder="aa:bb:cc:dd:ee:ff",
                    key=f"hw_mac_{hw_id}",
                )
                iface_input = st.text_input(
                    "Network Interface",
                    value=HARDWARE_REGISTRY[hw_id].get("iface", ""),
                    placeholder="Wi-Fi (Windows) / wlan0 (Linux) / en0 (macOS)",
                    key=f"hw_iface_{hw_id}",
                )
                if st.button("Connect & Start Sniffer", key=f"hw_connect_{hw_id}", width="stretch"):
                    if mac_input and iface_input:
                        HARDWARE_REGISTRY[hw_id]["mac"]   = mac_input.strip()
                        HARDWARE_REGISTRY[hw_id]["iface"] = iface_input.strip()
                        st.session_state["hw_mac"]   = mac_input.strip()
                        st.session_state["hw_iface"] = iface_input.strip()
                        try:
                            start_sniffer(mac_input.strip(), iface_input.strip())
                            st.session_state.sniffer_active = True
                        except Exception as _sniffer_exc:
                            st.error(f"Failed to start sniffer: {_sniffer_exc}")
                    else:
                        st.warning("Please enter both MAC address and interface name.")

                if st.session_state.sniffer_active:
                    active_iface = HARDWARE_REGISTRY[hw_id].get("iface", "?")
                    st.success(f"Sniffer active — capturing on {active_iface}")

                if st.checkbox("Show Scapy resolved interface (debug)", key=f"hw_dbg_resolve_{hw_id}"):
                    try:
                        from sniffer import _resolve_iface, list_interfaces
                        resolved = _resolve_iface(iface_input.strip() or "Wi-Fi")
                        st.code(f"Input: '{iface_input}'\nResolved to: '{resolved}'", language=None)
                        st.markdown("**All interfaces:**")
                        for i in list_interfaces():
                            st.code(i, language=None)
                    except Exception as e:
                        st.error(f"Debug error: {e}")

            if st.session_state.sniffer_active:
                if st.button("View Dashboard", key=f"hw_view_{hw_id}", width="stretch"):
                    st.session_state.hw_active_device = hw_id
                    st.session_state.page             = "hardware_dashboard"
                    st.rerun()
            else:
                st.warning("Start the sniffer first to access the live dashboard.")

    st.divider()

    if st.session_state.remediation_log:
        flattened_remediation = [item for sublist in st.session_state.remediation_log.values() for item in sublist]
        if flattened_remediation:
            st.markdown("### 🛠️ Remediation History")
            st.dataframe(pd.DataFrame(flattened_remediation).sort_values("Timestamp", ascending=False), width="stretch", hide_index=True)

    if st.session_state.audit_logs:
        st.markdown("### 🧾 Audit Trail")
        st.dataframe(pd.DataFrame(st.session_state.audit_logs), width="stretch", hide_index=True)


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