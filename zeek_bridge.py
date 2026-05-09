"""
zeek_bridge.py — Zeek auto-starter + log reader → MQTT feature publisher
=========================================================================
Runs on TEAMMATE 2's laptop (same machine as flask_server.py).

Automatically starts Zeek on the given interface, then reads Zeek's live
conn.log in real time, computes the 4 normalized network features, and
publishes them to MQTT every 3 seconds so the Isolation Forest in
flask_server.py can score them.

During a SYN flood:
  - conn.log explodes with half-open connections (state = "S0")
  - iat      → drops near 0.0  (extremely fast packets)
  - symmetry → drops near 0.0  (no ACKs, all half-open)
  - entropy  → spikes near 1.0 (--rand-source randomizes IPs)
  - pkt_size → drops near 0.0  (tiny SYN packets)
  → Isolation Forest sees anomaly → trust score drops below 30 → CRITICAL

Run:
    sudo python3 zeek_bridge.py --broker localhost --iface wlan0

    (sudo is needed because Zeek requires root to capture packets)

Requirements:
    pip install paho-mqtt
"""

from __future__ import annotations

import argparse
import atexit
import json
import math
import os
import signal
import subprocess
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# ── Config ───────────────────────────────────────────────────────────────────
ZEEK_LOG_DIR     = "/opt/zeek/logs/current"
CONN_LOG         = os.path.join(ZEEK_LOG_DIR, "conn.log")

TOPIC_PUBLISH    = "aegis/telemetry"
DEVICE_ID        = "RPI-IPCAM-01"
DEVICE_NAME      = "Entrance IP Security Camera"
PUBLISH_INTERVAL = 3.0   # seconds between feature publishes
WINDOW_SIZE      = 50    # number of recent conn.log entries to use

# ── Rolling window of recent connections ─────────────────────────────────────
_conn_window: deque = deque(maxlen=WINDOW_SIZE)

# ── Zeek process handle (so we can kill it on exit) ──────────────────────────
_zeek_proc: subprocess.Popen | None = None


# ── Zeek auto-start ───────────────────────────────────────────────────────────
def _start_zeek(iface: str) -> None:
    """
    Start Zeek in the background on the given network interface.
    Logs go to /opt/zeek/logs/current/ as usual.
    Kills Zeek automatically when this script exits (Ctrl+C or crash).
    """
    global _zeek_proc

    # First try zeekctl deploy (preferred — uses your node.cfg config)
    zeekctl = subprocess.run(
        ["which", "zeekctl"], capture_output=True, text=True
    ).stdout.strip()

    if zeekctl:
        print(f"[Zeek Bridge] 🦎 Starting Zeek via zeekctl deploy ...")
        try:
            subprocess.run(["zeekctl", "deploy"], check=True, timeout=30)
            print("[Zeek Bridge] ✅ Zeek started via zeekctl")
            # zeekctl manages its own process — no handle to store
            atexit.register(_stop_zeekctl)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[Zeek Bridge] ⚠️  zeekctl deploy failed ({e}), falling back to direct zeek...")

    # Fallback: run zeek directly
    zeek_bin = subprocess.run(
        ["which", "zeek"], capture_output=True, text=True
    ).stdout.strip() or "/usr/local/zeek/bin/zeek"

    print(f"[Zeek Bridge] 🦎 Starting Zeek directly on interface {iface} ...")
    _zeek_proc = subprocess.Popen(
        [zeek_bin, "-i", iface, "-C",
         "@load base/protocols/mqtt",          # enable MQTT parsing
         "@load base/frameworks/notice"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    print(f"[Zeek Bridge] ✅ Zeek started (PID {_zeek_proc.pid})")
    atexit.register(_stop_zeek)

    # Wait for conn.log to appear (up to 15 seconds)
    print(f"[Zeek Bridge] ⏳ Waiting for {CONN_LOG} to appear ...")
    for _ in range(30):
        if os.path.exists(CONN_LOG):
            print(f"[Zeek Bridge] ✅ conn.log found — beginning log tail")
            return
        time.sleep(0.5)

    print(f"[Zeek Bridge] ⚠️  conn.log not found after 15s — "
          "check that Zeek is writing to {ZEEK_LOG_DIR}")


def _stop_zeek() -> None:
    """Kill the Zeek subprocess on exit."""
    global _zeek_proc
    if _zeek_proc and _zeek_proc.poll() is None:
        print("\n[Zeek Bridge] 🛑 Stopping Zeek ...")
        _zeek_proc.terminate()
        try:
            _zeek_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _zeek_proc.kill()
        print("[Zeek Bridge] Zeek stopped.")


def _stop_zeekctl() -> None:
    """Stop Zeek via zeekctl on exit."""
    print("\n[Zeek Bridge] 🛑 Stopping Zeek via zeekctl ...")
    subprocess.run(["zeekctl", "stop"], capture_output=True)
    print("[Zeek Bridge] Zeek stopped.")


# ── Zeek conn.log parser ──────────────────────────────────────────────────────
def _parse_conn_line(line: str) -> dict | None:
    """
    Parse one TSV line from Zeek conn.log.
    Returns a dict with the fields we need, or None if unparseable.
    """
    if line.startswith("#"):
        return None  # skip header / comment lines
    fields = line.strip().split("\t")
    if len(fields) < 12:
        return None
    try:
        return {
            "ts":         float(fields[0]),
            "src_ip":     fields[2],
            "src_port":   int(fields[3])   if fields[3]  != "-" else 0,
            "dst_ip":     fields[4],
            "dst_port":   int(fields[5])   if fields[5]  != "-" else 0,
            "proto":      fields[6],
            "duration":   float(fields[8]) if fields[8]  not in ("-", "") else 0.0,
            "orig_bytes": int(fields[9])   if fields[9]  not in ("-", "") else 0,
            "resp_bytes": int(fields[10])  if len(fields) > 10 and fields[10] not in ("-", "") else 0,
            "conn_state": fields[11]       if len(fields) > 11 else "-",
        }
    except (ValueError, IndexError):
        return None


# ── Feature computation (conn.log only) ──────────────────────────────────────
def compute_features(conn_window: deque) -> dict:
    """
    Compute the 4 normalized features from conn.log rolling window only.

    Normal IP camera:  pkt_size~0.12, iat~0.35, entropy~0.18, symmetry~0.52
    SYN flood:         pkt_size~0.02, iat~0.01, entropy~0.95, symmetry~0.02
    """
    conns = list(conn_window)

    # ── pkt_size: average payload size from orig_bytes in conn.log ────────────
    if conns:
        avg_bytes = sum(c["orig_bytes"] + c["resp_bytes"] for c in conns) / len(conns)
        # Normalize: 0 bytes → 0.0, 1500 bytes (max Ethernet frame) → 1.0
        pkt_size = min(avg_bytes / 1500.0, 1.0)
    else:
        pkt_size = 0.12  # default normal

    # ── iat: inter-arrival time, normalized to [0, 1] ─────────────────────────
    if len(conns) >= 2:
        timestamps = sorted(c["ts"] for c in conns)
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        avg_iat = sum(iats) / len(iats)
        # Normalize: 0s → 0.0 (flooding), 10s → 1.0 (normal/slow)
        iat = min(avg_iat / 10.0, 1.0)
    else:
        iat = 0.35  # default normal

    # ── entropy: source IP entropy — spikes during --rand-source SYN flood ────
    if conns:
        src_counts = Counter(c["src_ip"] for c in conns)
        total = sum(src_counts.values())
        if total > 1:
            probs = [v / total for v in src_counts.values()]
            raw_entropy = -sum(p * math.log2(p) for p in probs if p > 0)
            # Normalize: 0 = single source, log2(50) ≈ 5.64 = all different
            entropy = min(raw_entropy / math.log2(max(len(src_counts), 2)), 1.0)
        else:
            entropy = 0.0
    else:
        entropy = 0.18  # default normal

    # ── symmetry: ratio of fully established vs total connections ─────────────
    # SYN flood → conn_state "S0" (SYN sent, no ACK ever) → symmetry near 0
    if conns:
        responded = sum(
            1 for c in conns
            if c["conn_state"] not in ("S0", "REJ", "RSTO", "RSTOS0", "-")
        )
        symmetry = responded / len(conns)
    else:
        symmetry = 0.52  # default normal

    return {
        "pkt_size": round(float(pkt_size), 4),
        "iat":      round(float(iat),      4),
        "entropy":  round(float(entropy),  4),
        "symmetry": round(float(symmetry), 4),
    }


# ── Log tailer ────────────────────────────────────────────────────────────────
def _tail_file(path: str):
    """
    Generator — yields new lines from a file as they appear.
    Retries if the file doesn't exist yet (Zeek may still be starting).
    """
    while True:
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(0, 2)  # seek to end — only read new entries
                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        time.sleep(0.2)
        except FileNotFoundError:
            print(f"[Zeek Bridge] ⏳ Waiting for {path} ...")
            time.sleep(2)


# ── MQTT setup ────────────────────────────────────────────────────────────────
def _build_mqtt_client(broker: str, port: int) -> mqtt.Client:
    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id="aegis-zeek-bridge",
            clean_session=True,
        )
    except AttributeError:
        client = mqtt.Client(client_id="aegis-zeek-bridge", clean_session=True)

    client.reconnect_delay_set(min_delay=1, max_delay=30)

    def on_connect(c, userdata, flags, rc):
        if rc == 0:
            print(f"[Zeek Bridge] ✅ Connected to MQTT broker {broker}:{port}")
        else:
            print(f"[Zeek Bridge] ❌ MQTT connection failed rc={rc}")

    client.on_connect = on_connect
    print(f"[Zeek Bridge] Connecting to MQTT broker {broker}:{port} ...")
    client.connect(broker, port, keepalive=60)
    client.loop_start()
    time.sleep(1.0)
    return client


# ── Main loop ─────────────────────────────────────────────────────────────────
def run(broker: str, port: int, iface: str) -> None:
    print("╔══════════════════════════════════════════════╗")
    print("║  Aegis-Twin · Zeek Bridge                   ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Interface : {iface:<32}║")
    print(f"║  conn.log  : {CONN_LOG:<32}║")
    print(f"║  Broker    : {broker}:{port:<26}║")
    print(f"║  Topic     : {TOPIC_PUBLISH:<32}║")
    print(f"║  Device    : {DEVICE_ID:<32}║")
    print("╚══════════════════════════════════════════════╝\n")

    # Auto-start Zeek before anything else
    _start_zeek(iface)

    # Connect to MQTT
    client = _build_mqtt_client(broker, port)

    # Background thread tailing conn.log
    def _read_conn():
        for line in _tail_file(CONN_LOG):
            conn = _parse_conn_line(line)
            if conn:
                _conn_window.append(conn)

    threading.Thread(target=_read_conn, daemon=True).start()

    print(f"[Zeek Bridge] 📡 Tailing conn.log... publishing every {PUBLISH_INTERVAL}s\n")

    last_publish = time.time()

    while True:
        now = time.time()
        if now - last_publish >= PUBLISH_INTERVAL:
            features = compute_features(_conn_window)

            payload = {
                "device_id":   DEVICE_ID,
                "device_name": DEVICE_NAME,
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "source":      "zeek",
                "telemetry": {
                    "cpu_percent":    0,
                    "memory_percent": 0,
                },
                "network_features": features,
            }

            client.publish(TOPIC_PUBLISH, json.dumps(payload), qos=1)

            ts = datetime.now().strftime("%H:%M:%S")
            conn_count = len(_conn_window)

            # Console state indicator
            if features["iat"] < 0.05 and features["symmetry"] < 0.1:
                state = "🚨 SYN FLOOD"
            elif features["entropy"] > 0.7:
                state = "⚠️  ANOMALY"
            else:
                state = "✅ NORMAL"

            print(
                f"[{ts}] {state:<16} | "
                f"pkt={features['pkt_size']:.3f} "
                f"iat={features['iat']:.3f} "
                f"ent={features['entropy']:.3f} "
                f"sym={features['symmetry']:.3f} "
                f"| window={conn_count} conns"
            )

            last_publish = now

        time.sleep(0.5)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis-Twin Zeek Bridge — auto-starts Zeek, reads conn.log, "
                    "publishes real network features to MQTT"
    )
    parser.add_argument(
        "--broker",
        default="localhost",
        help="MQTT broker IP address (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1883,
        help="MQTT broker port (default: 1883)",
    )
    parser.add_argument(
        "--iface",
        default="wlan0",
        help="Network interface for Zeek to monitor (default: wlan0)",
    )
    args = parser.parse_args()
    run(broker=args.broker, port=args.port, iface=args.iface)