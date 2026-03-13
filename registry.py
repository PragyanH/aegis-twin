"""registry.py — IoT device registry and session-state defaults."""

import pandas as pd

IOT_REGISTRY = {
    "DEV-001": {"name": "AEGIS-PUMP-01",    "type": "Pump",              "sector": "1",   "baseline": [0.4, 0.5, 0.3, 0.6], "icon": "🚰", "lat": 12.9026, "lon": 77.5001},
    "DEV-002": {"name": "Assembly Arm",      "type": "Robotic Arm",       "sector": "2",   "baseline": [0.6, 0.3, 0.7, 0.5], "icon": "🦾", "lat": 12.9035, "lon": 77.5012},
    "DEV-003": {"name": "Grid Node 0X",      "type": "Smart Grid Node",   "sector": "3",   "baseline": [0.3, 0.8, 0.4, 0.5], "icon": "⚡", "lat": 12.9020, "lon": 77.4990},
    "DEV-004": {"name": "Cryo-Storage A",    "type": "Bio-Storage Fridge","sector": "4",   "baseline": [0.2, 0.6, 0.2, 0.8], "icon": "❄️", "lat": 12.9045, "lon": 77.5005},
    "DEV-005": {"name": "Mixer V-12",        "type": "Chemical Mixer",    "sector": "5",   "baseline": [0.5, 0.5, 0.6, 0.4], "icon": "🧪", "lat": 12.9015, "lon": 77.5015},
    "DEV-006": {"name": "Security Cam 1",    "type": "Camera",            "sector": "6",   "baseline": [0.8, 0.2, 0.4, 0.9], "icon": "📷", "lat": 12.9030, "lon": 77.4985},
    "DEV-007": {"name": "Security Cam 2",    "type": "Camera",            "sector": "7",   "baseline": [0.8, 0.2, 0.3, 0.8], "icon": "📷", "lat": 12.9022, "lon": 77.5025},
    "DEV-008": {"name": "Coolant Pump",      "type": "Pump",              "sector": "8",   "baseline": [0.5, 0.4, 0.4, 0.6], "icon": "⚙️", "lat": 12.9050, "lon": 77.4995},
    "DEV-009": {"name": "Welding Arm",       "type": "Robotic Arm",       "sector": "9",   "baseline": [0.7, 0.2, 0.8, 0.4], "icon": "🤖", "lat": 12.9010, "lon": 77.5000},
    "DEV-010": {"name": "Main Grid Relay",   "type": "Smart Grid Node",   "sector": "7-G", "baseline": [0.4, 0.7, 0.5, 0.6], "icon": "🔌", "lat": 12.9038, "lon": 77.4975},
}

SESSION_DEFAULTS = {
    "page":                          "fleet",
    "active_device":                 None,
    "device_health":                 {k: "Healthy" for k in IOT_REGISTRY},
    "packet_history":                pd.DataFrame(columns=["Time", "Pkt Size", "IAT", "Entropy", "Symmetry", "Status"]),
    "threat_log":                    [],
    "remediation_log":               [],
    "audit_logs":                    [],
    "remediation_locked":            False,
    "attack_step":                   {},
    "math_mode_active":              False,
    "jsd_history":                   [0.0] * 10,
    "pulse_mse_history":             [0.0] * 30,
    "pulse_jsd_history":             [0.0] * 30,
    "reconstruction_errors_history": [[0.0] * 20 for _ in range(4)],
    # auth
    "authenticated":                 False,
    "user_email":                    None,
    "login_error":                   None,
    "password_visible":              False,
    "register_mode":                 False,
    "last_alert_sent":               {},
}