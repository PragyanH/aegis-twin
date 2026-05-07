"""sniffer.py — Background Scapy packet sniffer for live hardware monitoring.

Runs in a daemon thread so it never blocks Streamlit's main thread.
Extracts four normalized network features per packet:
  - Packet Size  (norm to [0,1], min=64, max=1500 bytes)
  - IAT          (Inter-Arrival Time, exponential-smoothed, min=0.0001s, max=2.0s)
  - Entropy      (Shannon entropy of raw payload bytes, normalized by /8.0)
  - Symmetry     (inbound / (inbound+outbound) over a 50-pkt rolling window)

All four features are further normalized via rolling min-max over a 200-sample
window and stored in LIVE_FEATURES[mac] protected by a threading.Lock.

Requires root/admin privileges (Scapy raw socket capture).
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from typing import Deque
import scapy
from scapy.all import sniff, get_if_list
from scapy.layers.l2 import Ether

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_lock = threading.Lock()

# LIVE_FEATURES[mac] = {
#   "features":      [pkt_size, iat, entropy, symmetry]  (all normalized [0,1])
#   "packet_count":  int
# }
LIVE_FEATURES: dict[str, dict] = {}

# Per-MAC rolling buffers (not exposed publicly)
_buffers: dict[str, "_SnifferState"] = {}


# ---------------------------------------------------------------------------
# MAC normalization (module-level so it can be used everywhere)
# ---------------------------------------------------------------------------

def _norm_mac(m: str) -> str:
    """Normalize a MAC address to lowercase colon-separated format."""
    return m.lower().replace("-", ":").replace(".", ":").strip()


# ---------------------------------------------------------------------------
# Interface resolution (Windows Npcap GUID mapping)
# ---------------------------------------------------------------------------

def _resolve_iface(iface: str) -> str:
    # If user already passed a NPF GUID, use it directly — skip all resolution
    if iface.startswith("\\Device\\NPF_") or iface.startswith(r"\Device\NPF_"):
        print(f"[sniffer] Using GUID directly: {iface}")
        return iface

    import platform
    if platform.system() != "Windows":
        return iface

    try:
        from scapy.arch.windows import get_windows_if_list
        from scapy.all import get_if_list
        scapy_ifaces = get_if_list()
        win_ifaces   = get_windows_if_list()

        # Pass 1: match friendly name/description to GUID, then find NPF device
        for w in win_ifaces:
            candidates = [
                w.get("name", "").lower(),
                w.get("description", "").lower(),
            ]
            if iface.lower() in candidates:
                guid = w.get("guid", "").upper().replace("{", "").replace("}", "")
                for s in scapy_ifaces:
                    if guid in s.upper():
                        print(f"[sniffer] Resolved '{iface}' -> '{s}' (GUID match)")
                        return s

        # Pass 2: find interface with active hotspot IP
        for w in win_ifaces:
            for ip in w.get("ips", []):
                if ip.startswith("172.21.") or ip.startswith("10."):
                    guid = w.get("guid", "").upper().replace("{", "").replace("}", "")
                    for s in scapy_ifaces:
                        if guid in s.upper():
                            print(f"[sniffer] Resolved '{iface}' -> '{s}' (IP {ip} fallback)")
                            return s

    except Exception as e:
        print(f"[sniffer] _resolve_iface error: {e}")

    print(f"[sniffer] WARNING: could not resolve '{iface}', using as-is")
    return iface


def list_interfaces() -> list[str]:
    """Return a list of interface name strings visible to Scapy (Windows only)."""
    import platform
    results = []
    if platform.system() != "Windows":
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []
    try:
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            results.append(
                f"name={i.get('name')}  desc={i.get('description')}  "
                f"ips={i.get('ips')}  guid={i.get('guid')}"
            )
    except Exception as e:
        results.append(f"Error: {e}")
    return results


class _SnifferState:
    """Holds all rolling state for a single MAC address."""

    WINDOW = 200   # rolling min-max window
    SYM_WIN = 50   # flow symmetry window

    # Normalization bounds
    MIN_PKT, MAX_PKT = 64.0, 1500.0
    MIN_IAT, MAX_IAT = 0.0001, 2.0

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Raw feature histories for rolling min-max
        self._pkt_hist:  Deque[float] = deque(maxlen=self.WINDOW)
        self._iat_hist:  Deque[float] = deque(maxlen=self.WINDOW)
        self._ent_hist:  Deque[float] = deque(maxlen=self.WINDOW)
        self._sym_hist:  Deque[float] = deque(maxlen=self.WINDOW)

        # Flow direction window for symmetry
        self._direction_win: Deque[str] = deque(maxlen=self.SYM_WIN)

        self._last_ts: float | None = None
        self.packet_count: int = 0

        # Current normalized output
        self.features: list[float] = [0.5, 0.5, 0.5, 0.5]

    # ------------------------------------------------------------------
    # Feature extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Shannon entropy of bytes, normalized by /8.0 → [0, 1]."""
        if not data:
            return 0.0
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        H = -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)
        return min(H / 8.0, 1.0)

    @staticmethod
    def _norm_clipped(value: float, lo: float, hi: float) -> float:
        if hi == lo:
            return 0.5
        return max(0.0, min(1.0, (value - lo) / (hi - lo)))

    @staticmethod
    def _rolling_minmax(value: float, buf: Deque[float], fallback_lo: float, fallback_hi: float) -> float:
        if len(buf) < 2:
            return _SnifferState._norm_clipped(value, fallback_lo, fallback_hi)
        return _SnifferState._norm_clipped(value, min(buf), max(buf))

    # ------------------------------------------------------------------
    # Main update — called per packet
    # ------------------------------------------------------------------

    def update(self, pkt_len: int, raw_payload: bytes, ts: float, direction: str) -> None:
        with self._lock:
            self.packet_count += 1

            # -- Packet Size --
            raw_pkt = float(pkt_len)
            self._pkt_hist.append(raw_pkt)
            norm_pkt = self._rolling_minmax(raw_pkt, self._pkt_hist, self.MIN_PKT, self.MAX_PKT)

            # -- IAT (exponential smooth on raw seconds) --
            now = ts
            if self._last_ts is None:
                raw_iat = self.MIN_IAT
            else:
                raw_iat = max(self.MIN_IAT, min(self.MAX_IAT, now - self._last_ts))
            self._last_ts = now
            self._iat_hist.append(raw_iat)
            norm_iat = self._rolling_minmax(raw_iat, self._iat_hist, self.MIN_IAT, self.MAX_IAT)

            # -- Shannon Entropy --
            raw_ent = self._shannon_entropy(raw_payload)
            self._ent_hist.append(raw_ent)
            norm_ent = self._rolling_minmax(raw_ent, self._ent_hist, 0.0, 1.0)

            # -- Flow Symmetry --
            self._direction_win.append(direction)
            inbound = sum(1 for d in self._direction_win if d == "in")
            total = len(self._direction_win)
            raw_sym = inbound / total if total > 0 else 0.5
            self._sym_hist.append(raw_sym)
            norm_sym = self._rolling_minmax(raw_sym, self._sym_hist, 0.0, 1.0)

            self.features = [
                round(norm_pkt, 6),
                round(norm_iat, 6),
                round(norm_ent, 6),
                round(norm_sym, 6),
            ]


# ---------------------------------------------------------------------------
# Packet callback factory
# ---------------------------------------------------------------------------

def _make_callback(mac: str) -> callable:
    mac_norm = _norm_mac(mac)

    def _callback(pkt) -> None:  # type: ignore[no-untyped-def]
        try:
            # Determine direction relative to the phone's MAC
            src_mac = _norm_mac(getattr(pkt, "src", ""))
            dst_mac = _norm_mac(getattr(pkt, "dst", ""))
            if src_mac != mac_norm and dst_mac != mac_norm:
                return  # not our device
            direction = "in" if dst_mac == mac_norm else "out"

            pkt_len = len(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

            # Raw payload bytes
            raw = bytes(pkt)

            state = _buffers.get(mac_norm)
            if state is None:
                return
            state.update(pkt_len, raw, ts, direction)

            # Push to shared dict
            with _lock:
                LIVE_FEATURES[mac_norm] = {
                    "features": list(state.features),
                    "packet_count": state.packet_count,
                }
        except Exception:
            pass  # never crash the sniffer thread on a bad packet

    return _callback, mac_norm


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_sniffer_threads: dict[str, threading.Thread] = {}


def start_sniffer(mac: str, iface: str) -> None:
    """Start a background daemon thread that sniffs traffic for *mac* on *iface*.

    If a sniffer for this MAC is already running, this is a no-op.
    Raises a clear message (printed to stdout) if Scapy lacks privileges.
    """
    mac_lower = _norm_mac(mac)  # normalize on entry (handles colons, hyphens, dots)
    resolved_iface = _resolve_iface(iface)  # resolve Windows GUID

    if mac_lower in _sniffer_threads and _sniffer_threads[mac_lower].is_alive():
        print(f"[sniffer] Already running for {mac_lower} on {resolved_iface}")
        return

    # Initialize state
    with _lock:
        _buffers[mac_lower] = _SnifferState()
        LIVE_FEATURES[mac_lower] = {"features": [0.5, 0.5, 0.5, 0.5], "packet_count": 0}

    callback, _mac_norm = _make_callback(mac_lower)

    def _run() -> None:
        try:
             # imported here so the rest of the app works without scapy
            print(f"[sniffer] Starting capture on iface={resolved_iface!r} for MAC={mac_lower!r}")
            sniff(
                iface=resolved_iface,
                prn=callback,
                store=False,
                filter=f"ether host {mac_lower}",
            )
        except PermissionError:
            print(
                "\n[sniffer] ❌  PermissionError: Scapy requires root/administrator privileges.\n"
                "  → On Windows: run 'streamlit run app.py' from an Administrator PowerShell.\n"
                "  → On Linux/macOS: run with 'sudo streamlit run app.py'.\n"
            )
        except Exception as exc:
            print(f"[sniffer] ❌  Unexpected error in sniffer thread: {exc}")

    t = threading.Thread(target=_run, name=f"aegis-sniffer-{mac_lower}", daemon=True)
    t.start()
    _sniffer_threads[mac_lower] = t
    print(f"[sniffer] Thread started: {t.name}")


def get_features(mac: str) -> list[float]:
    """Return the latest normalized [pkt_size, iat, entropy, symmetry] for *mac*.

    Returns [0.5, 0.5, 0.5, 0.5] if no data is available yet.
    """
    mac_lower = _norm_mac(mac)
    with _lock:
        entry = LIVE_FEATURES.get(mac_lower)
        if entry is None:
            return [0.5, 0.5, 0.5, 0.5]
        return list(entry["features"])


def get_packet_count(mac: str) -> int:
    """Return the total number of packets captured for *mac* so far."""
    mac_lower = _norm_mac(mac)
    with _lock:
        entry = LIVE_FEATURES.get(mac_lower)
        return entry["packet_count"] if entry else 0
