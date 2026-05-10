"""
flask_server.py — Standalone Flask server for Aegis-Twin
=========================================================
Runs SEPARATELY from Streamlit (app.py).
Receives Pi telemetry via MQTT, runs Isolation Forest scoring,
writes results to telemetry.json for Streamlit to read.

Run this FIRST, before streamlit:
    python flask_server.py

Then in a second terminal:
    streamlit run app.py

Requirements:
    pip install flask flask-cors paho-mqtt paramiko
"""

from __future__ import annotations

import json
import psutil
import paho.mqtt.client as mqtt
from flask import Flask, jsonify, request
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko
import paho.mqtt.client as mqtt
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from isolation_model import (
    add_baseline_sample,
    get_status,
    get_training_status,
    get_training_estimate,
    get_trust_score,
    load_model,
    score_sample,
    train_model,
    reset_training,
)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Shared state file (bridge to Streamlit) ───────────────────────────────────
TELEMETRY_FILE = Path("telemetry.json")

# ── MQTT config ───────────────────────────────────────────────────────────────
MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", 1883))
TOPIC_SUB   = "aegis/telemetry"   # Pi publishes here
TOPIC_PUB   = "aegis/status"      # We publish trust score back to Pi
_mqtt_client: mqtt.Client | None = None

# ── SSH config for Pi remediation ─────────────────────────────────────────────
PI_HOST     = os.environ.get("PI_HOST", "192.168.1.100")   # ← SET YOUR PI'S IP
PI_USER     = os.environ.get("PI_USER", "pi")
PI_PASSWORD = os.environ.get("PI_PASSWORD", "raspberry")

# ── In-memory state ───────────────────────────────────────────────────────────
_lock              = threading.Lock()
_phase             = "learning"
_learning_start    = time.time()
_pi_telemetry_log: list[dict] = []
LEARNING_DURATION  = 120

# Attacker IP — detected automatically when CRITICAL fires
_attacker_ip: str | None = None

# Forensic report cooldown
_last_forensic_time: float = 0.0
FORENSIC_COOLDOWN = 60.0   # seconds

# Try to restore a previously trained model on startup
if load_model():
    _phase = "monitoring"
    print("[Aegis Flask] Restored trained model from disk → MONITORING phase")
else:
    print("[Aegis Flask] No saved model found → LEARNING phase")


# ── SSH helper ────────────────────────────────────────────────────────────────
def _ssh_run(commands: list[str]) -> dict:
    """SSH into Pi and run a list of shell commands."""
    results = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PI_HOST, username=PI_USER, password=PI_PASSWORD, timeout=10)
        for cmd in commands:
            _, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            results.append({"cmd": cmd, "out": out, "err": err})
            print(f"[Aegis SSH] $ {cmd}")
            if out: print(f"  → {out}")
            if err: print(f"  ⚠️ {err}")
        ssh.close()
        return {"success": True, "results": results}
    except Exception as e:
        print(f"[Aegis SSH] ❌ SSH failed: {e}")
        return {"success": False, "error": str(e)}


# ── Attacker IP detection ─────────────────────────────────────────────────────
def _detect_attacker_ip(telemetry_log: list) -> str | None:
    for record in reversed(telemetry_log[-20:]):
        src = record.get("network_features", {}).get("src_ip")
        if src and src not in ("0.0.0.0", "127.0.0.1", ""):
            return src
    return None


# ── Shared file writer ────────────────────────────────────────────────────────
def _write_telemetry_file(record: dict) -> None:
    try:
        with _lock:
            log_snapshot = _pi_telemetry_log[-100:]
        payload = {
            "latest":     record,
            "log":        log_snapshot,
            "phase":      _phase,
            "model":      get_status(),
            "written_at": datetime.now(timezone.utc).isoformat(),
        }
        TELEMETRY_FILE.write_text(json.dumps(payload, indent=2))
    except Exception as e:
        print(f"[Aegis Flask] Failed to write telemetry.json: {e}")


# ── Forensic report trigger ───────────────────────────────────────────────────
def _trigger_forensic_report(data: dict, features: list, trust: float) -> None:
    global _last_forensic_time
    now = time.time()
    if now - _last_forensic_time < FORENSIC_COOLDOWN:
        return
    _last_forensic_time = now

    def _run():
        try:
            from forensics import generate_and_send_report
            import isolation_model as _im
            baseline = list(_im._baseline_buffer[-1]) if _im._baseline_buffer else [0.15, 0.35, 0.18, 0.52]
            device_data = {
                "device_id":           data.get("device_id", "RPI-IPCAM-01"),
                "device_name":         data.get("device_name", "Entrance IP Security Camera"),
                "sector":              "IoT Security",
                "timestamp":           data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "trust_score":         trust,
                "reconstruction_error": round(1.0 - (trust / 100.0), 4),
                "jsd_value":           round(features[2], 4),
                "baseline_features":   baseline,
                "current_features":    features,
                "packet_history":      [],
                "threat_log": [{
                    "time": datetime.now(timezone.utc).isoformat(),
                    "msg":  (
                        f"SYN Flood detected on IP Camera — trust dropped to {trust:.1f}. "
                        f"pkt_size={features[0]:.3f} iat={features[1]:.3f} "
                        f"entropy={features[2]:.3f} symmetry={features[3]:.3f}"
                    ),
                }],
            }
            pdf_path = generate_and_send_report(device_data)
            print(f"[Aegis] 📄 Forensic report generated → {pdf_path}")
        except Exception as e:
            print(f"[Aegis] Forensic report failed: {e}")

    threading.Thread(target=_run, daemon=True).start()


# ── Core processing (shared by MQTT and HTTP) ─────────────────────────────────
def _process_telemetry(data: dict) -> dict:
    global _phase, _pi_telemetry_log, _learning_start

    features_raw = data.get("network_features", {})
    features = [
        float(features_raw.get("pkt_size", 0.0)),
        float(features_raw.get("iat",      0.0)),
        float(features_raw.get("entropy",  0.0)),
        float(features_raw.get("symmetry", 0.0)),
    ]

    elapsed = time.time() - _learning_start

    if _phase == "learning":
        add_baseline_sample(features)
        
        # Check progress
        status_info = get_status()
        baseline_count = status_info.get("baseline_samples", 0)
        
        if elapsed >= LEARNING_DURATION and baseline_count >= 100:
            try:
                summary = train_model()
                _phase = "monitoring"
                print(f"[Aegis] Auto-trained after {elapsed:.0f}s | {summary}")
            except Exception as e:
                print(f"[Aegis] Auto-train failed: {e}")
        elif elapsed >= LEARNING_DURATION:
             # Wait for more samples
             if int(elapsed) % 10 == 0:
                 print(f"[Aegis] Waiting for more samples... ({baseline_count}/100 collected)")
             pass
        trust  = 95.0
        status = "LEARNING"
    else:
        trust = get_trust_score(features)
        if trust < 30:
            status = "CRITICAL"
        elif trust < 60:
            status = "WARNING"
        else:
            status = "NORMAL"

    if status == "CRITICAL":
        sc = score_sample(features)
        print(
            f"[Aegis] 🚨 CRITICAL trust={trust:.1f} "
            f"anomaly={sc['anomaly_score']:.3f} "
            f"device={data.get('device_id', '?')}"
        )
        _trigger_forensic_report(data, features, trust)

    record = {
        "timestamp":       data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "device_id":       data.get("device_id",   "UNKNOWN"),
        "device_name":     data.get("device_name", "Unknown Device"),
        "trust_score":     trust,
        "status":          status,
        "phase":           _phase,
        "elapsed_learning": round(elapsed, 1),
        "telemetry":       data.get("telemetry", {}),
        "network_features": features_raw,
        "model_status":    get_status(),
    }

    with _lock:
        _pi_telemetry_log.append(record)
        _pi_telemetry_log = _pi_telemetry_log[-500:]

    _write_telemetry_file(record)
    return record


# ── MQTT callbacks ────────────────────────────────────────────────────────────
def _on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe(TOPIC_SUB, qos=1)
        print(f"[Aegis MQTT] ✅ Connected | subscribed to '{TOPIC_SUB}'")
    else:
        print(f"[Aegis MQTT] ❌ Connection failed rc={rc}")


def _on_mqtt_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
    except Exception as e:
        print(f"[Aegis MQTT] Bad payload: {e}")
        return

    record = _process_telemetry(data)

    # Publish trust score back to Pi
    client.publish(TOPIC_PUB, json.dumps({
        "trust_score": record["trust_score"],
        "status":      record["status"],
        "phase":       record["phase"],
    }), qos=0)


def start_mqtt(broker: str, port: int) -> mqtt.Client:
    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id="aegis-flask-server",
            clean_session=True,
        )
    except AttributeError:
        client = mqtt.Client(client_id="aegis-flask-server", clean_session=True)

    client.on_connect = _on_mqtt_connect
    client.on_message = _on_mqtt_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    client.connect(broker, port, keepalive=60)
    client.loop_start()
    return client


# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "phase":  _phase,
        "time":   datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/telemetry", methods=["POST"])
def receive_telemetry():
    """HTTP fallback — works if Pi uses HTTP instead of MQTT."""
    data   = request.get_json(force=True, silent=True) or {}
    record = _process_telemetry(data)
    return jsonify({
        "trust_score": record["trust_score"],
        "status":      record["status"],
        "phase":       record["phase"],
    })


@app.route("/api/pi/force_train", methods=["POST"])
def force_train():
    global _phase
    try:
        summary = train_model()
        _phase  = "monitoring"
        print(f"[Aegis Flask] Force trained! {summary}")
        return jsonify({
            "success": True,
            "message": "Model trained. Now in MONITORING phase.",
            "summary": summary,
        })
    except ValueError as e:
        st = get_status()
        return jsonify({
            "success":      False,
            "error":        str(e),
            "samples_so_far": st["baseline_samples"],
            "samples_needed": 100,
        }), 400


@app.route("/api/training/status")
def training_status():
    """Get current training status and progress."""
    status = get_training_status()
    return jsonify(status)


@app.route("/api/training/estimate")
def training_estimate():
    """Get estimated training time."""
    estimate = get_training_estimate()
    return jsonify(estimate)


@app.route("/api/pi/status")
def pi_status():
    with _lock:
        recent = _pi_telemetry_log[-5:]
    return jsonify({
        "phase":            _phase,
        "elapsed_learning": round(time.time() - _learning_start, 1),
        "model_status":     get_status(),
        "recent":           recent,
    })


@app.route("/api/pi/seed", methods=["POST"])
def seed_data():
    """Populate the baseline buffer with synthetic 'normal' data for testing."""
    import numpy as np
    # Generate 120 samples of typical 'normal' traffic
    rng = np.random.default_rng()
    # Typical values: pkt_size ~ 0.15, iat ~ 0.3, entropy ~ 0.2, symmetry ~ 0.5
    synthetic_data = rng.normal(loc=[0.15, 0.30, 0.20, 0.50], scale=0.03, size=(120, 4))
    synthetic_data = np.clip(synthetic_data, 0, 1).tolist()

    for sample in synthetic_data:
        add_baseline_sample(sample)
    
    print(f"[Aegis Flask] Seeded {len(synthetic_data)} synthetic samples into baseline buffer.")
    return jsonify({
        "success": True, 
        "message": f"Seeded {len(synthetic_data)} synthetic samples. You can now train."
    })


@app.route("/api/pi/reset", methods=["POST"])
def reset():
    global _phase, _learning_start, _pi_telemetry_log, _attacker_ip, _last_forensic_time
    
    # 1. Reset the underlying model and buffer
    success = reset_training()
    
    # 2. Reset Flask server internal state
    with _lock:
        _phase              = "learning"
        _learning_start     = time.time()
        _pi_telemetry_log   = []
        _attacker_ip        = None
        _last_forensic_time = 0.0

    # 3. Clean up the public JSON file
    if TELEMETRY_FILE.exists():
        try:
            TELEMETRY_FILE.unlink()
        except Exception:
            pass

    print("[Aegis Flask] Full reset complete → LEARNING phase")
    return jsonify({"success": success, "message": "Reset complete. Back to LEARNING phase."})
@app.route("/api/telemetry/latest")
def latest_telemetry():
    with _lock:
        if not _pi_telemetry_log:
            return jsonify({"error": "No telemetry received yet"}), 404
        latest = _pi_telemetry_log[-1]
    return jsonify(latest)


@app.route("/api/telemetry/log")
def telemetry_log():
    n = min(int(request.args.get("n", 50)), 500)
    with _lock:
        log = _pi_telemetry_log[-n:]
    return jsonify({"count": len(log), "log": log})


# ── Remediation routes ────────────────────────────────────────────────────────
@app.route("/api/pi/remediate", methods=["POST"])
def remediate():
    global _attacker_ip
    import isolation_model as _im

    # Clear rolling anomaly window for immediate dashboard recovery
    with _im._lock:
        _im._score_window.clear()

    # Try to detect attacker IP from recent telemetry
    with _lock:
        detected = _detect_attacker_ip(_pi_telemetry_log)
        if detected:
            _attacker_ip = detected
            print(f"[Aegis] Detected attacker IP: {_attacker_ip}")

    # Build iptables + sysctl commands for SYN flood defense
    commands = [
        "sudo sysctl -w net.ipv4.tcp_syncookies=1",
        "sudo sysctl -w net.ipv4.tcp_synack_retries=2",
        "sudo sysctl -w net.ipv4.tcp_max_syn_backlog=128",
        "sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP",
        "sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
        "sudo iptables -A INPUT -p tcp --syn -j DROP",
    ]

    if _attacker_ip:
        commands.insert(0, f"sudo iptables -I INPUT 1 -s {_attacker_ip} -j DROP")
        commands.insert(1, f"sudo iptables -I OUTPUT 1 -d {_attacker_ip} -j DROP")
        print(f"[Aegis] Blocking attacker IP: {_attacker_ip}")

    commands.append("sudo iptables -L INPUT -n --line-numbers | head -15")
    commands.append("sudo sysctl net.ipv4.tcp_syncookies")

    ssh_result = _ssh_run(commands)

    rules_applied = [
        "SYN cookies enabled (tcp_syncookies=1)",
        "SYN-ACK retries reduced to 2",
        "Max SYN backlog reduced to 128",
        "INVALID packets dropped",
        "SYN rate limited to 10/sec",
        "SYN flood packets dropped at kernel",
    ]
    if _attacker_ip:
        rules_applied.insert(0, f"Attacker IP blocked: {_attacker_ip}")

    event = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "event":       "REMEDIATION_TRIGGERED",
        "ssh_success": ssh_result["success"],
        "attacker_ip": _attacker_ip,
        "rules_applied": rules_applied,
    }

    with _lock:
        if _pi_telemetry_log:
            _pi_telemetry_log.append({
                **_pi_telemetry_log[-1],
                "status":    "REMEDIATING",
                "timestamp": event["timestamp"],
                "event":     event,
            })

    print(f"[Aegis Flask] 🛡️ Remediation complete | SSH OK: {ssh_result['success']}")
    return jsonify({"success": True, "event": event, "ssh": ssh_result})


@app.route("/api/pi/clear_rules", methods=["POST"])
def clear_rules():
    global _attacker_ip
    result = _ssh_run([
        "sudo iptables -F",
        "sudo iptables -X",
        "sudo iptables -P INPUT ACCEPT",
        "sudo iptables -P OUTPUT ACCEPT",
        "sudo iptables -P FORWARD ACCEPT",
        "sudo sysctl -w net.ipv4.tcp_syncookies=0",
        "sudo sysctl -w net.ipv4.tcp_synack_retries=5",
        "sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048",
        "echo 'Pi iptables cleared — ready for next demo'",
    ])
    _attacker_ip = None
    print("[Aegis Flask] Pi rules cleared — ready for next demo run")
    return jsonify({"success": result["success"], "detail": result})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║  Aegis-Twin · Flask + MQTT Server           ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  MQTT Broker : {MQTT_BROKER}:{MQTT_PORT:<24}║")
    print("║  Flask       : http://0.0.0.0:5000          ║")
    print("║  Health      : http://localhost:5000/health ║")
    print(f"║  Pi SSH Host : {PI_HOST:<30}║")
    print("╚══════════════════════════════════════════════╝")

    _mqtt_client = start_mqtt(MQTT_BROKER, MQTT_PORT)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)