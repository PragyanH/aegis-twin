"""
pi_sender.py — Runs ON the Raspberry Pi thermostat simulator.
=============================================================
Publishes telemetry to the Aegis-Twin laptop via MQTT.
The laptop's flask_server.py subscribes and processes it.

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

DEVICE_ID   = "RPI-THERMOSTAT-01"
DEVICE_NAME = "Living Room Thermostat"

# ── MQTT Topics ───────────────────────────────────────────────────────────────

TOPIC_PUBLISH   = "aegis/telemetry"    # Pi → Laptop
TOPIC_SUBSCRIBE = "aegis/status"       # Laptop → Pi (trust score back)
MQTT_PORT       = 1883
MQTT_KEEPALIVE  = 60


# ── Thermostat simulation ─────────────────────────────────────────────────────

class ThermostatSimulator:
    def __init__(self, setpoint: float = 22.0):
        self.setpoint    = setpoint
        self.temp        = setpoint + random.uniform(-1, 1)
        self.humidity    = 55.0
        self.hvac_state  = "IDLE"
        self._start_time = time.time()

    def update(self) -> dict:
        t = time.time() - self._start_time

        self.temp = (
            self.setpoint
            + 1.5 * math.sin(t / 60)
            + random.gauss(0, 0.08)
        )
        self.humidity += random.gauss(0, 0.05)
        self.humidity  = max(30.0, min(80.0, self.humidity))

        deviation = self.temp - self.setpoint
        if deviation > 1.2:
            self.hvac_state = "COOLING"
        elif deviation < -1.2:
            self.hvac_state = "HEATING"
        else:
            self.hvac_state = "IDLE"

        return {
            "temperature_actual":   round(self.temp, 2),
            "temperature_setpoint": self.setpoint,
            "humidity":             round(self.humidity, 2),
            "hvac_state":           self.hvac_state,
        }


# ── Network feature sampler ───────────────────────────────────────────────────

class NetworkFeatureSampler:
    NORMAL_PROFILE = {
        "pkt_size": (0.12, 0.04),
        "iat":      (0.35, 0.07),
        "entropy":  (0.18, 0.04),
        "symmetry": (0.52, 0.08),
    }

    def __init__(self):
        self._packet_count = 0

    def sample(self) -> dict:
        self._packet_count += 1
        features = {}
        for name, (mean, std) in self.NORMAL_PROFILE.items():
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

def build_payload(thermostat: ThermostatSimulator,
                  net_sampler: NetworkFeatureSampler) -> dict:
    return {
        "device_id":        DEVICE_ID,
        "device_name":      DEVICE_NAME,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "telemetry": {
            **thermostat.update(),
            **get_system_metrics(),
            "process_anomalies": check_process_anomalies(),
            "packet_count":      net_sampler.packet_count,
        },
        "network_features": net_sampler.sample(),
    }


# ── MQTT callbacks ────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[Pi Sender] ✅ Connected to MQTT broker")
        # Subscribe to status topic so we can see trust score responses
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
    thermostat = ThermostatSimulator(setpoint=22.0)
    net        = NetworkFeatureSampler()

    print(f"╔══════════════════════════════════════════╗")
    print(f"║       Aegis-Twin  ·  Pi Sender (MQTT)   ║")
    print(f"╠══════════════════════════════════════════╣")
    print(f"║  Device  : {DEVICE_ID:<30}║")
    print(f"║  Broker  : {broker:<30}║")
    print(f"║  Port    : {port:<30}║")
    print(f"║  Topic   : {TOPIC_PUBLISH:<30}║")
    print(f"║  Interval: {interval}s{'':<27}║")
    print(f"╚══════════════════════════════════════════╝\n")

    # Set up MQTT client
    client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message
    client.on_publish    = on_publish

    # Auto-reconnect settings
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    print(f"[Pi Sender] Connecting to broker {broker}:{port} ...")
    try:
        client.connect(broker, port, keepalive=MQTT_KEEPALIVE)
    except Exception as e:
        print(f"[Pi Sender] ❌ Cannot connect to broker: {e}")
        print("  → Is the broker running? Check IP and port.")
        return

    # Start background MQTT network loop
    client.loop_start()

    # Give connection a moment to establish
    time.sleep(1.5)

    while True:
        try:
            payload     = build_payload(thermostat, net)
            payload_str = json.dumps(payload)

            result = client.publish(
                TOPIC_PUBLISH,
                payload=payload_str,
                qos=1,          # at-least-once delivery
                retain=False,
            )

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                ts  = payload["timestamp"][11:19]
                tel = payload["telemetry"]
                nf  = payload["network_features"]

                print(
                    f"[{ts}] 📤 Published | "
                    f"temp={tel['temperature_actual']}°C "
                    f"hvac={tel['hvac_state']:<7} "
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
        description="Aegis-Twin Pi Sender — streams thermostat telemetry via MQTT"
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