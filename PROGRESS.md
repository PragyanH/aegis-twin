# Aegis-Twin — Project Progress Log

**Date:** 10 March 2026  
**Session:** Initial Setup & Core Engine Build  
**Python:** 3.13.2 · **Environment:** `venv/`

---

## ✅ Session Summary

This session established the complete foundation of the Aegis-Twin cybersecurity
Digital Twin project — from a blank folder to a working anomaly detection core.

---

## 📦 Step 1 — Environment Setup

**File created:** `check_setup.py`

Set up a Python virtual environment (`venv/`) and installed all required
dependencies via pip.

| Library | Version | Role |
|---|---|---|
| `streamlit` | 1.55.0 | Dashboard / UI |
| `pandas` | 2.3.3 | Data manipulation |
| `plotly` | 6.6.0 | Interactive charts |
| `torch` (PyTorch) | 2.10.0+cpu | Deep learning (Digital Twin) |
| `scikit-learn` | 1.8.0 | ML utilities & preprocessing |
| `scipy` | 1.17.1 | Statistical functions (JSD) |
| `shap` | 0.51.0 | Explainability / feature attribution |

`check_setup.py` imports all seven libraries and prints their versions with
pass/fail status. All imports confirmed ✅.

**Activate the environment:**
```powershell
.\venv\Scripts\Activate.ps1
```

---

## 🧠 Step 2 — Digital Twin Core (`model.py`)

**File created:** `model.py`

Built the `LSTMAutoencoder` — the heart of the Aegis-Twin Digital Twin. The
model is trained on *normal* network traffic and learns to reconstruct it. At
inference time, traffic that deviates from learned normality produces a high
**Reconstruction Error (MSE)**, which serves as the primary anomaly signal.

### Architecture

```
Input  (batch, 10, 4)
    ↓
┌───────────────────────────────────┐
│  ENCODER                          │
│  LSTM  (4 → 64, 2 layers)         │
│  Linear(64 → 32)  ← bottleneck    │
└───────────────────────────────────┘
    ↓  latent vector (batch, 32)
┌───────────────────────────────────┐
│  DECODER                          │
│  Linear(32 → 64)                  │
│  Repeat × 10  (seq_len)           │
│  LSTM  (64 → 64, 2 layers)        │
│  Linear(64 → 4)                   │
└───────────────────────────────────┘
    ↓
Output (batch, 10, 4)  — reconstructed sequence
```

### Input Features (4 per packet)

| Index | Feature | Description |
|---|---|---|
| 0 | Packet Size | Size of the network packet in bytes |
| 1 | IAT | Inter-Arrival Time between packets (seconds) |
| 2 | Payload Entropy | Shannon entropy of packet payload (bits) |
| 3 | Flow Symmetry | Ratio of upload/download symmetry (0–1) |

### Key Hyperparameters

| Parameter | Value |
|---|---|
| Sequence length (`seq_len`) | 10 packets per window |
| Hidden size | 64 |
| Latent (bottleneck) size | 32 |
| LSTM layers | 2 |
| Dropout | 0.2 |

### Key Methods

| Method | Description |
|---|---|
| `forward(x)` | Encodes then decodes — returns reconstructed sequence |
| `reconstruction_error(x)` | Returns per-sample MSE anomaly score `(batch,)` |

### Test block output (`python model.py`)
```
Input sequence shape : (1, 10, 4)
  (batch=1, seq_len=10, features=4)

Reconstructed shape  : (1, 10, 4)

Reconstruction Error (MSE) : 1.051176

Model Test Successful!
```

---

## ⚙️ Step 3 — Anomaly Detection Engine (`engine.py`)

**File created:** `engine.py`

Built the analytical layer that sits between the Digital Twin and the dashboard.
Takes raw model outputs and produces human-readable trust scores.

### Function 1 — `calculate_jsd(p, q)`

Computes the **Jensen-Shannon Divergence** between two probability distributions
using `scipy.stats.entropy`. JSD is a symmetric, bounded measure of how
different two distributions are.

- Uses **base-2 logarithms** → result is always in **[0, 1]**
- `0.0` = identical distributions
- `1.0` = maximally different distributions
- Auto-normalises inputs; raises `ValueError` on shape/sign mismatch

```
M = (P + Q) / 2
JSD = ½ · KL(P ‖ M) + ½ · KL(Q ‖ M)
```

### Function 2 — `calculate_trust_score(reconstruction_error, jsd_value)`

Returns a composite **Trust Score from 0 to 100**. Starts at 100 and applies
proportional penalties when either anomaly signal exceeds its threshold.

| Signal | Threshold | Penalty Rate |
|---|---|---|
| Reconstruction Error (MSE) | `> 0.10` | `× 200` pts per unit excess |
| Jensen-Shannon Divergence | `> 0.30` | `× 100` pts per unit excess |

Score is **clamped to [0, 100]** — never goes negative.

### Scenario Test output (`python engine.py`)

```
=======================================================
  Aegis-Twin · Trust Score Scenario Test
=======================================================

  Scenario : ✅  HEALTHY  — Normal traffic
  Reconstruction Error (MSE) : 0.02
  Jensen-Shannon Divergence  : 0.05
  Trust Score                : 100.00 / 100
  [████████████████████]

  Scenario : 🚨  HACKED   — Anomalous traffic
  Reconstruction Error (MSE) : 0.45
  Jensen-Shannon Divergence  : 0.65
  Trust Score                : 0.00 / 100
  [░░░░░░░░░░░░░░░░░░░░]

=======================================================
```

---

## 🗂️ Project File Structure

```
Aegis_Twin_Project/
│
├── venv/                  # Python virtual environment
│
├── model.py               # 🧠 Digital Twin — LSTMAutoencoder
├── engine.py              # ⚙️  Anomaly detection engine (JSD + Trust Score)
├── check_setup.py         # ✅  Dependency verification script
└── PROGRESS.md            # 📋  This file
```

---

## 🔜 Suggested Next Steps

- [ ] **`data.py`** — Data loader / pre-processor for real PCAP or CSV network logs
- [ ] **Training loop** — Script to train the LSTMAutoencoder on labelled normal traffic
- [ ] **`app.py`** — Streamlit dashboard: live trust score gauge, JSD trend chart, alert log
- [ ] **Threshold tuning** — Calibrate `MSE_THRESHOLD` and `JSD_THRESHOLD` on real data
- [ ] **SHAP integration** — Use `shap` to explain *which* features are driving anomalies
