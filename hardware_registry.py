"""hardware_registry.py — Registry and calibration for real, physical hardware devices.

Unlike the mock IOT_REGISTRY in registry.py, this registry contains entries
for physical devices that are monitored via live Scapy packet capture.

The 'mac' and 'iface' fields are filled at runtime from the UI.
The 'baseline' is calibrated during a 30-second window via calibrate_baseline().
"""

from __future__ import annotations

import time

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

HARDWARE_REGISTRY: dict[str, dict] = {
    "HW-001": {
        "name":     "Android A23",
        "type":     "Android Smartphone",
        "sector":   "LIVE",
        "icon":     "📱",
        "mac":      "",          # filled at runtime from UI
        "iface":    "",          # filled at runtime from UI
        "baseline": [0.5, 0.5, 0.5, 0.5],   # updated by calibrate_baseline()
    }
}

# Duration of the calibration window in seconds
CALIBRATION_WINDOW: int = 30


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

def calibrate_baseline(mac: str) -> None:
    """Average get_features(mac) over CALIBRATION_WINDOW seconds and update baseline.

    Imports sniffer lazily to avoid a circular import if hardware_registry is
    imported before sniffer is initialised.
    """
    from sniffer import get_features  # lazy import

    samples: list[list[float]] = []
    deadline = time.time() + CALIBRATION_WINDOW

    print(f"[calibration] Starting {CALIBRATION_WINDOW}s baseline calibration for MAC={mac!r}")

    while time.time() < deadline:
        features = get_features(mac)
        # Only record once we have real data (not the default [0.5]*4)
        samples.append(features)
        time.sleep(0.5)

    if not samples:
        print("[calibration] No samples collected — baseline unchanged.")
        return

    # Element-wise mean
    n = len(samples)
    baseline = [
        round(sum(s[i] for s in samples) / n, 6)
        for i in range(4)
    ]

    # Update the in-memory registry entry for every device that uses this MAC
    for hw_id, info in HARDWARE_REGISTRY.items():
        if info.get("mac", "").lower() == mac.lower():
            info["baseline"] = baseline
            print(f"[calibration] [{hw_id}] Baseline updated → {baseline}")
