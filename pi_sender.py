"""
pi_sender.py — Runs ON the Raspberry Pi IP security camera simulator.
=============================================================
Publishes telemetry to the Aegis-Twin laptop via MQTT.
The laptop's flask_server.py subscribes and processes it.

No physical camera required — simulates realistic IP camera
network behaviour (motion events, stream bursts, heartbeat pings).

Run on Pi:
    python3 pi_sender.py --broker 192.168.X.X

Requirements on Pi:
    pip3 install paho-mqtt psutil

MQTT Topic structure:
    aegis/telemetry        ← main telemetry payload (Pi publishes here)
    aegis/status           ← flask_server publishes trust score back
"""

import time
import math
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
        t = time.time()
        elapsed = t - self._start_time

        # Motion events occur randomly ~every 45 seconds, last 8 seconds
        if t - self._last_motion > 45 + random.uniform(-10, 10):
            self._last_motion     = t
            self._motion_duration = random.uniform(5, 10)

        self.motion_detected = (t - self._last_motion) < self._motion_duration
        self.recording       = self.motion_detected
        self.stream_active   = True  # always streaming

        # Uptime in seconds
        uptime = int(elapsed)

        return {
            "device_type":      "IP Security Camera",
            "stream_active":    self.stream_active,
            "motion_detected":  self.motion_detected,
            "recording":        self.recording,
            "uptime_seconds":   uptime,
            "fps_simulated":    15 if self.motion_detected else 5,
        }

    @property
    def in_motion(self) -> bool:
        return self.motion_detected


# ── Network feature sampler ───────────────────────────────────────────────────

class NetworkFeatureSampler:
    """
    Generates realistic normalized network features for an IP camera.

    Normal camera behaviour:
    - Small keepalive packets during idle
    - Larger bursts during motion events (video stream spike)
    - Low entropy (structured RTSP/MQTT data)
    - Balanced symmetry (camera sends stream, NVR sends ACKs)
    """

    # Idle profile — no motion
    IDLE_PROFILE = {
        "pkt_size": (0.10, 0.03),   # small keepalives
        "iat":      (0.40, 0.08),   # regular heartbeat timing
        "entropy":  (0.15, 0.03),   # low entropy, structured data
        "symmetry": (0.55, 0.07),   # balanced stream + ACKs
    }

    # Motion burst profile — camera sends video frames
    MOTION_PROFILE = {
        "pkt_size": (0.55, 0.10),   # larger video frame packets
        "iat":      (0.12, 0.04),   # faster (15fps burst)
        "entropy":  (0.30, 0.05),   # slightly higher (compressed video)
        "symmetry": (0.40, 0.08),   # more outbound (stream heavy)
    }

    def __init__(self):
        self._packet_count = 0

    def sample(self, in_motion: bool = False) -> dict:
        self._packet_count += 1
        profile = self.MOTION_PROFILE if in_motion else self.IDLE_PROFILE
        features = {}
        for name, (mean, std) in profile.items():
            val = random.gauss(mean, std)
            features[name] = round(max(0.0, min(1.0, val)), 4)
        return features

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
    """Receive trust score / status back from flask_server via MQTT."""
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
    pass   # silent — publish confirmed


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
    print(f"╚══════════════════════════════════════════╝\n")

    # Set up MQTT client — CallbackAPIVersion fix for paho-mqtt >= 2.0
    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=DEVICE_ID,
            clean_session=True,
        )
    except AttributeError:
        # Older paho-mqtt versions don't have CallbackAPIVersion
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
                    f"stream={'ON' if tel['stream_active'] else 'OFF'} "
                    f"cpu={tel['cpu_percent']}%"
                )

                if verbose:
                    print(
                        f"         net → pkt={nf['pkt_size']} iat={nf['iat']} "
                        f"ent={nf['entropy']} sym={nf['symmetry']}"
                    )
                    if tel.get("process_anomalies"):
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
    parser.add_argument(
        "--broker",
        default="localhost",
        help="MQTT broker IP address (e.g. 192.168.1.42)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1883,
        help="MQTT broker port (default: 1883)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Seconds between publishes (default: 3.0)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print network features and process anomalies each tick"
    )
    args = parser.parse_args()

    run(broker=args.broker, port=args.port,
        interval=args.interval, verbose=args.verbose)