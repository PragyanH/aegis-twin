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
    pip install flask flask-cors paho-mqtt
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from flask import Flask, jsonify, request
from flask_cors import CORS

from isolation_model import (
    add_baseline_sample,
    get_status,
    get_trust_score,
    load_model,
    score_sample,
    train_model,
)

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)

# ── Shared state file (bridge to Streamlit) ───────────────────────────────────

TELEMETRY_FILE = Path("telemetry.json")

# ── MQTT config ───────────────────────────────────────────────────────────────

MQTT_BROKER   = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT     = int(os.environ.get("MQTT_PORT", 1883))
TOPIC_SUB     = "aegis/telemetry"   # Pi publishes here
TOPIC_PUB     = "aegis/status"      # We publish trust score back to Pi

_mqtt_client: mqtt.Client | None = None

# ── In-memory state ───────────────────────────────────────────────────────────

_lock              = threading.Lock()
_phase             = "learning"
_learning_start    = time.time()
_pi_telemetry_log: list[dict] = []
LEARNING_DURATION  = 120

# Try to restore a previously trained model on startup
if load_model():
    _phase = "monitoring"
    print("[Aegis Flask] Restored trained model from disk → MONITORING phase")
else:
    print("[Aegis Flask] No saved model found → LEARNING phase")


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


# ── Core processing (shared by MQTT and HTTP) ─────────────────────────────────

def _process_telemetry(data: dict) -> dict:
    """Score incoming telemetry and return a full record dict."""
    global _phase, _pi_telemetry_log, _learning_start

    features_raw = data.get("network_features", {})
    features = [
        float(features_raw.get("pkt_size",  0.0)),
        float(features_raw.get("iat",       0.0)),
        float(features_raw.get("entropy",   0.0)),
        float(features_raw.get("symmetry",  0.0)),
    ]

    elapsed = time.time() - _learning_start

    if _phase == "learning":
        add_baseline_sample(features)
        if elapsed >= LEARNING_DURATION:
            try:
                summary = train_model()
                _phase  = "monitoring"
                print(f"[Aegis] Auto-trained after {elapsed:.0f}s | {summary}")
            except Exception as e:
                print(f"[Aegis] Auto-train failed: {e}")
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

    record = {
        "timestamp":        data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "device_id":        data.get("device_id", "UNKNOWN"),
        "device_name":      data.get("device_name", "Unknown Device"),
        "trust_score":      trust,
        "status":           status,
        "phase":            _phase,
        "elapsed_learning": round(elapsed, 1),
        "telemetry":        data.get("telemetry", {}),
        "network_features": features_raw,
        "model_status":     get_status(),
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
        status = get_status()
        return jsonify({
            "success":        False,
            "error":          str(e),
            "samples_so_far": status["baseline_samples"],
            "samples_needed": 100,
        }), 400


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


@app.route("/api/pi/reset", methods=["POST"])
def reset():
    global _phase, _learning_start, _pi_telemetry_log

    import isolation_model as _im
    from isolation_model import MODEL_PATH

    with _im._lock:
        _im._baseline_buffer = []
        _im._score_window.clear()
        _im._model      = None
        _im._is_trained = False
        _im._score_min  = -0.5
        _im._score_max  = -0.1

    if MODEL_PATH.exists():
        MODEL_PATH.unlink()
        print("[Aegis Flask] Deleted saved model.")

    with _lock:
        _phase            = "learning"
        _learning_start   = time.time()
        _pi_telemetry_log = []

    if TELEMETRY_FILE.exists():
        TELEMETRY_FILE.unlink()

    print("[Aegis Flask] Full reset complete → LEARNING phase")
    return jsonify({"success": True, "message": "Reset complete. Back to LEARNING phase."})


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


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║     Aegis-Twin  ·  Flask + MQTT Server      ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  MQTT Broker : {MQTT_BROKER}:{MQTT_PORT:<24}║")
    print("║  Flask       : http://0.0.0.0:5000          ║")
    print("║  Health      : http://localhost:5000/health ║")
    print("╚══════════════════════════════════════════════╝")

    _mqtt_client = start_mqtt(MQTT_BROKER, MQTT_PORT)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)