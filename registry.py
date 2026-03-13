"""registry.py — IoT device registry and session-state defaults."""

import pandas as pd

IOT_REGISTRY = {
    "DEV-001": {"name": "AEGIS-PUMP-01",    "type": "Pump",              "sector": "1",   "baseline": [0.4, 0.5, 0.3, 0.6], "icon": "🚰"},
    "DEV-002": {"name": "Assembly Arm",      "type": "Robotic Arm",       "sector": "2",   "baseline": [0.6, 0.3, 0.7, 0.5], "icon": "🦾"},
    "DEV-003": {"name": "Grid Node 0X",      "type": "Smart Grid Node",   "sector": "3",   "baseline": [0.3, 0.8, 0.4, 0.5], "icon": "⚡"},
    "DEV-004": {"name": "Cryo-Storage A",    "type": "Bio-Storage Fridge","sector": "4",   "baseline": [0.2, 0.6, 0.2, 0.8], "icon": "❄️"},
    "DEV-005": {"name": "Mixer V-12",        "type": "Chemical Mixer",    "sector": "5",   "baseline": [0.5, 0.5, 0.6, 0.4], "icon": "🧪"},
    "DEV-006": {"name": "Security Cam 1",    "type": "Camera",            "sector": "6",   "baseline": [0.8, 0.2, 0.4, 0.9], "icon": "📷"},
    "DEV-007": {"name": "Security Cam 2",    "type": "Camera",            "sector": "7",   "baseline": [0.8, 0.2, 0.3, 0.8], "icon": "📷"},
    "DEV-008": {"name": "Coolant Pump",      "type": "Pump",              "sector": "8",   "baseline": [0.5, 0.4, 0.4, 0.6], "icon": "⚙️"},
    "DEV-009": {"name": "Welding Arm",       "type": "Robotic Arm",       "sector": "9",   "baseline": [0.7, 0.2, 0.8, 0.4], "icon": "🤖"},
    "DEV-010": {"name": "Main Grid Relay",   "type": "Smart Grid Node",   "sector": "7-G", "baseline": [0.4, 0.7, 0.5, 0.6], "icon": "🔌"},
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
    # hardware / sniffer
    "sniffer_active":                False,
    "hw_active_device":              None,
    "hw_calibrating":                False,
}