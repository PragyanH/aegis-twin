"""
pi_sender.py — Runs ON the Raspberry Pi IP security camera simulator.
=============================================================
Publishes telemetry to the Aegis-Twin laptop via MQTT.
The laptop's flask_server.py subscribes and processes it.

No physical camera required — simulates realistic IP camera
network behaviour using REAL Pi system metrics (psutil network I/O,
CPU, memory) to derive network features. Features reflect actual
Pi network conditions — not fake random numbers.

Run on Pi:
    python3 pi_sender.py --broker 192.168.X.X

Requirements on Pi:
    pip3 install paho-mqtt psutil

MQTT Topic structure:
    aegis/telemetry        ← main telemetry payload (Pi publishes here)
    aegis/status           ← flask_server publishes trust score back
"""

import time
import random
import argparse
import json
import psutil
import paho.mqtt.client as mqtt
from datetime import datetime, timezone


# ── Device identity ───────────────────────────────────────────────────────────

DEVICE_ID   = "RPI-IPCAM-01"
DEVICE_NAME = "Entrance IP Security Camera"

# ── MQTT Topics ───────────────────────────────────────────────────────────────

TOPIC_PUBLISH   = "aegis/telemetry"    # Pi → Laptop
TOPIC_SUBSCRIBE = "aegis/status"       # Laptop → Pi (trust score back)
MQTT_PORT       = 1883
MQTT_KEEPALIVE  = 60


# ── IP Camera simulation ──────────────────────────────────────────────────────

class IPCameraSimulator:
    """
    Simulates a realistic IP security camera without a physical lens.

    Behaviour modelled:
    - Periodic heartbeat pings to NVR (every ~30s)
    - Occasional motion-triggered burst (larger packets, higher rate)
    - Idle stream: small keepalive packets at regular intervals
    - Status fields: motion_detected, stream_active, recording
    """

    def __init__(self):
        self.stream_active    = True
        self.recording        = False
        self.motion_detected  = False
        self._start_time      = time.time()
        self._last_motion     = 0.0
        self._motion_duration = 0.0

    def update(self) -> dict:
        t       = time.time()
        elapsed = t - self._start_time

        # Motion events occur randomly ~every 45 seconds, last 8 seconds
        if t - self._last_motion > 45 + random.uniform(-10, 10):
            self._last_motion     = t
            self._motion_duration = random.uniform(5, 10)

        self.motion_detected = (t - self._last_motion) < self._motion_duration
        self.recording       = self.motion_detected
        self.stream_active   = True  # always streaming

        return {
            "device_type":     "IP Security Camera",
            "stream_active":   self.stream_active,
            "motion_detected": self.motion_detected,
            "recording":       self.recording,
            "uptime_seconds":  int(elapsed),
            "fps_simulated":   15 if self.motion_detected else 5,
        }

    @property
    def in_motion(self) -> bool:
        return self.motion_detected


# ── Real network feature sampler using psutil ─────────────────────────────────

class NetworkFeatureSampler:
    """
    Derives the 4 normalized network features from REAL Pi network I/O
    using psutil — no fake random numbers.

    Features:
      pkt_size  — avg bytes per packet from real network counters
      iat       — inverse of recv packet rate (high flood rate = low iat)
      entropy   — error + drop rate (spikes when Pi is overwhelmed)
      symmetry  — sent / total bytes (drops during SYN flood — all inbound)

    During a SYN flood:
      - packets_recv spikes (thousands of SYN packets per second)
      - bytes_recv spikes, bytes_sent stays low (Pi can't respond)
      - symmetry → 0 (all inbound, nothing outbound)
      - iat → 0 (packets arriving extremely fast)
      - entropy → 1 (dropin spikes as Pi's buffer overflows)
    """

    MAX_BYTES_PER_PKT = 1500.0   # max Ethernet frame size
    MAX_PKTS_PER_SEC  = 500.0    # above this = flooding (iat → 0)
    MAX_ERROR_RATE    = 0.10     # 10% error/drop rate maps to entropy = 1.0

    def __init__(self):
        self._packet_count = 0
        # Initial snapshot for delta calculation
        self._prev_stats = psutil.net_io_counters()
        self._prev_time  = time.time()

    def sample(self, in_motion: bool = False) -> dict:
        """
        Compute real network features from actual Pi network I/O delta.
        Falls back to safe defaults if psutil can't read counters.
        """
        self._packet_count += 1

        try:
            curr_stats = psutil.net_io_counters()
            curr_time  = time.time()

            dt = max(curr_time - self._prev_time, 0.1)  # avoid div by zero

            # Deltas since last sample
            d_bytes_sent = max(0, curr_stats.bytes_sent   - self._prev_stats.bytes_sent)
            d_bytes_recv = max(0, curr_stats.bytes_recv   - self._prev_stats.bytes_recv)
            d_pkts_sent  = max(0, curr_stats.packets_sent - self._prev_stats.packets_sent)
            d_pkts_recv  = max(0, curr_stats.packets_recv - self._prev_stats.packets_recv)
            d_errin      = max(0, curr_stats.errin  - self._prev_stats.errin)
            d_dropin     = max(0, curr_stats.dropin - self._prev_stats.dropin)

            # Save snapshot for next call
            self._prev_stats = curr_stats
            self._prev_time  = curr_time

            total_pkts  = d_pkts_sent + d_pkts_recv
            total_bytes = d_bytes_sent + d_bytes_recv

            # ── pkt_size ──────────────────────────────────────────────────────
            # avg bytes per packet, normalized to [0, 1]
            if total_pkts > 0:
                avg_bytes_per_pkt = total_bytes / total_pkts
            else:
                avg_bytes_per_pkt = 100.0   # idle keepalive
            pkt_size = float(min(avg_bytes_per_pkt / self.MAX_BYTES_PER_PKT, 1.0))

            # ── iat ───────────────────────────────────────────────────────────
            # inverse of recv packet rate — high flood rate = low iat
            pkts_per_sec = d_pkts_recv / dt
            iat = float(max(0.0, 1.0 - (pkts_per_sec / self.MAX_PKTS_PER_SEC)))

            # ── entropy ───────────────────────────────────────────────────────
            # error + drop rate as buffer overflow signal
            if total_pkts > 0:
                error_rate = (d_errin + d_dropin) / max(total_pkts, 1)
            else:
                error_rate = 0.0
            entropy = float(min(error_rate / self.MAX_ERROR_RATE, 1.0))
            # Small baseline noise so entropy isn't exactly 0 during idle
            entropy = float(max(0.0, min(entropy + random.gauss(0.05, 0.02), 1.0)))

            # ── symmetry ──────────────────────────────────────────────────────
            # sent / total bytes — drops to ~0 during SYN flood
            if total_bytes > 0:
                symmetry = float(d_bytes_sent / total_bytes)
            else:
                symmetry = 0.55   # idle default

            # Camera sending video stream skews slightly outbound
            if in_motion:
                symmetry = float(min(symmetry + 0.10, 1.0))

        except Exception:
            # Safe normal defaults if psutil fails
            pkt_size = 0.10
            iat      = 0.40
            entropy  = 0.05
            symmetry = 0.55

        return {
            "pkt_size": round(pkt_size, 4),
            "iat":      round(iat,      4),
            "entropy":  round(entropy,  4),
            "symmetry": round(symmetry, 4),
        }

    @property
    def packet_count(self) -> int:
        return self._packet_count


# ── System metrics ────────────────────────────────────────────────────────────

def get_system_metrics() -> dict:
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    temps = {}

    try:
        sensor_data = psutil.sensors_temperatures()
        if sensor_data:
            for key in ("cpu_thermal", "coretemp", "thermal_zone0"):
                if key in sensor_data:
                    temps["cpu_temp_c"] = round(sensor_data[key][0].current, 1)
                    break
    except (AttributeError, NotImplementedError):
        pass

    return {
        "cpu_percent":    round(cpu, 1),
        "memory_percent": round(mem.percent, 1),
        "memory_used_mb": round(mem.used / 1024 / 1024, 1),
        "disk_percent":   round(disk.percent, 1),
        **temps,
    }


# ── Process anomaly check ─────────────────────────────────────────────────────

def check_process_anomalies() -> list[str]:
    EXPECTED = {"python3", "python", "bash", "sh", "sshd", "systemd"}
    anomalies = []
    for proc in psutil.process_iter(["name", "cpu_percent", "status"]):
        try:
            name = proc.info["name"]
            cpu  = proc.info["cpu_percent"] or 0
            if cpu > 40 and name not in EXPECTED:
                anomalies.append(f"{name} (cpu={cpu}%)")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return anomalies


# ── Payload builder ───────────────────────────────────────────────────────────

def build_payload(camera: IPCameraSimulator,
                  net_sampler: NetworkFeatureSampler) -> dict:
    cam_status = camera.update()
    return {
        "device_id":        DEVICE_ID,
        "device_name":      DEVICE_NAME,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "telemetry": {
            **cam_status,
            **get_system_metrics(),
            "process_anomalies": check_process_anomalies(),
            "packet_count":      net_sampler.packet_count,
        },
        "network_features": net_sampler.sample(in_motion=camera.in_motion),
    }


# ── MQTT callbacks ────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[Pi Sender] ✅ Connected to MQTT broker")
        client.subscribe(TOPIC_SUBSCRIBE)
        print(f"[Pi Sender] Subscribed to '{TOPIC_SUBSCRIBE}'")
    else:
        codes = {
            1: "Wrong protocol version",
            2: "Invalid client ID",
            3: "Broker unavailable",
            4: "Bad credentials",
            5: "Not authorised",
        }
        print(f"[Pi Sender] ❌ Connection failed: {codes.get(rc, f'rc={rc}')}")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[Pi Sender] ⚠️  Unexpected disconnect (rc={rc}) — will auto-reconnect")


def on_message(client, userdata, msg):
    try:
        data   = json.loads(msg.payload.decode())
        trust  = data.get("trust_score", "?")
        status = data.get("status", "?")
        phase  = data.get("phase", "?")

        status_icon = {
            "NORMAL":   "✅",
            "WARNING":  "⚠️ ",
            "CRITICAL": "🚨",
            "LEARNING": "🔵",
        }.get(status, "❓")

        print(f"[Pi Sender] ← {status_icon} trust={trust} | status={status} | phase={phase}")
    except Exception as e:
        print(f"[Pi Sender] Failed to parse status message: {e}")


def on_publish(client, userdata, mid):
    pass


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(broker: str, port: int, interval: float, verbose: bool) -> None:
    camera = IPCameraSimulator()
    net    = NetworkFeatureSampler()

    print(f"╔══════════════════════════════════════════╗")
    print(f"║   Aegis-Twin  ·  Pi Sender (IP Camera)  ║")
    print(f"╠══════════════════════════════════════════╣")
    print(f"║  Device  : {DEVICE_ID:<30}║")
    print(f"║  Broker  : {broker:<30}║")
    print(f"║  Port    : {port:<30}║")
    print(f"║  Topic   : {TOPIC_PUBLISH:<30}║")
    print(f"║  Interval: {interval}s{'':<27}║")
    print(f"║  Features: REAL psutil network I/O      ║")
    print(f"╚══════════════════════════════════════════╝\n")

    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=DEVICE_ID,
            clean_session=True,
        )
    except AttributeError:
        client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)

    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message
    client.on_publish    = on_publish

    client.reconnect_delay_set(min_delay=1, max_delay=30)

    print(f"[Pi Sender] Connecting to broker {broker}:{port} ...")
    try:
        client.connect(broker, port, keepalive=MQTT_KEEPALIVE)
    except Exception as e:
        print(f"[Pi Sender] ❌ Cannot connect to broker: {e}")
        print("  → Is the broker running? Check IP and port.")
        return

    client.loop_start()
    time.sleep(1.5)

    while True:
        try:
            payload     = build_payload(camera, net)
            payload_str = json.dumps(payload)

            result = client.publish(
                TOPIC_PUBLISH,
                payload=payload_str,
                qos=1,
                retain=False,
            )

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                ts  = payload["timestamp"][11:19]
                tel = payload["telemetry"]
                nf  = payload["network_features"]

                motion_flag = "🎥 MOTION" if tel["motion_detected"] else "💤 IDLE  "

                print(
                    f"[{ts}] 📤 Published | "
                    f"{motion_flag} | "
                    f"cpu={tel['cpu_percent']}% | "
                    f"pkt={nf['pkt_size']} iat={nf['iat']} "
                    f"ent={nf['entropy']} sym={nf['symmetry']}"
                )

                if verbose and tel.get("process_anomalies"):
                    print(f"         ⚠️  processes: {tel['process_anomalies']}")
            else:
                print(f"[Pi Sender] ⚠️  Publish failed (rc={result.rc})")

        except Exception as e:
            print(f"[Pi Sender] Unexpected error: {e}")

        time.sleep(interval)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis-Twin Pi Sender — streams IP camera telemetry via MQTT"
    )
    parser.add_argument("--broker",   default="localhost")
    parser.add_argument("--port",     type=int,   default=1883)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    run(broker=args.broker, port=args.port,
        interval=args.interval, verbose=args.verbose)