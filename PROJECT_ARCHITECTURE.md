# Aegis-Twin — Project Architecture (Single Source of Truth)

> This document is the authoritative reference for how Aegis-Twin works today. It is written for both humans and AI agents who need to understand the system without manually reading every file.

---

## 1. Project Overview

### What the project does
Aegis-Twin is a **cybersecurity digital twin dashboard** that simulates an enterprise IoT fleet and evaluates the “trust” of each device’s network traffic. The system generates synthetic traffic features, runs them through a **trained LSTM autoencoder**, and produces a **Trust Score** that indicates whether the device behavior matches its learned baseline.

### Main problem it solves
It demonstrates how to detect anomalies in a fleet of IoT devices using a **Digital Twin** approach: model normal behavior, measure deviations, and surface actionable alerts in a dashboard.

### Type of system
- **Type:** Interactive dashboard (single-process UI application)
- **Framework:** Streamlit (Python)
- **Domain:** Cybersecurity anomaly detection / digital twin

### Main technologies and frameworks used
- **Python 3.13**
- **Streamlit**: Web UI framework for interactive dashboards
- **PyTorch**: Deep learning library (LSTM autoencoder)
- **NumPy / Pandas**: Numeric & tabular data handling
- **Plotly**: Interactive charts in the dashboard
- **SciPy**: Statistical computations (Jensen-Shannon divergence)

---

## 2. High Level Architecture

### Components

- **Frontend (Streamlit app)**: `app.py`
  - Provides an interactive UI for selecting devices, injecting traffic parameters, and viewing anomaly indicators.

- **Digital Twin Model**: `model.py`
  - Implements an LSTM-based autoencoder to learn “normal” traffic sequences.

- **Analytics Engine**: `engine.py`
  - Converts model outputs into human-friendly metrics (JSD, Trust Score).

- **State Management**: Streamlit session state
  - Stores active page, selected device, device health, packet history, threat logs, and remediation history.

- **Data Source**: Synthetic / manual input
  - Simulated traffic is generated from sliders and random numbers. There is no database backend.

### Component relationships

1. **User interacts with Streamlit UI** (`app.py`).
2. UI collects device baseline + runtime feature values.
3. Streamlit passes the feature vector into the model (`LSTMAutoencoder`) from `model.py`.
4. Model computes a reconstruction error (MSE) via `reconstruction_error()`.
5. Engine functions from `engine.py` compute Jensen-Shannon Divergence and a Trust Score.
6. UI updates: status indicator, charts, logs, health state.

### Request/response & data flow

This is not a web client/server architecture; it is a single-process Streamlit application. The “request/response” pattern is event-driven inside Streamlit:

- **User input** → Streamlit reruns script → UI state recomputed
- **Model inference** happens during rerun
- **UI updates** are rendered in-browser via Streamlit’s reactivity

Data flows in-memory through:
- `st.session_state` (persistent between reruns)
- local variables in `app.py` (computed each render)

---

## 3. Application Flow

### Startup
1. User runs: `streamlit run app.py`
2. Streamlit initializes the Python process.
3. `app.py` is executed top-to-bottom.
4. `load_aegis_engine()` is called once via `@st.cache_resource` to instantiate the LSTM autoencoder.

### Interaction Flow (Fleet → Device Dashboard)

1. **Fleet Overview** (default page)
   - Shows a grid of devices defined in `IOT_REGISTRY`.
   - Each device card shows status and a "View Digital Twin" button.
   - Clicking a device sets `st.session_state.active_device` and `page` to `dashboard`, then reruns.

2. **Device Dashboard** (drill-down view)
   - Sidebar: device identity card plus sliders for injecting traffic feature values.
   - Main area: trust gauge, packet stream table, feature drift radar, threat log.
   - Each rerun recalculates the model output and updates UI.

### Model + Engine Execution (per rerun)
1. Collect feature vector from sliders: `[pkt_size, iat, entropy, symmetry]`.
2. Create a tensor shaped `(1, 10, 4)` by repeating the feature vector 10 times (a fixed sequence length).
3. Call `autoencoder.reconstruction_error(tensor)` → returns MSE.
4. Call `calculate_jsd(current_features, dev_baseline)` → returns Jensen-Shannon Divergence.
5. Call `calculate_trust_score(mse, jsd)` → returns Trust Score (0–100).
6. Determine health state (`Healthy`/`Compromised`) based on Trust Score >= 50.
7. Update session state (health status, packet log, threat log, remediation log).

### Alerts and Remediation
- If the device is compromised:
  - Flashing UI and red indicators appear.
  - A remediation button allows “resetting” the device (sets values back to baseline, clears logs, marks health healthy).

---

## 4. Folder Structure Explanation

```
.\
├── app.py          # Streamlit dashboard (UI + orchestration)
├── engine.py       # Scoring logic (JSD + Trust Score)
├── model.py        # LSTM autoencoder (digital twin)
├── check_setup.py  # Dependency verification script
├── PROGRESS.md     # Project progress log (documentation)
├── pyrightconfig.json  # Type-checking configuration
└── venv/           # Python virtual environment (not checked in)
```

### Why each file exists
- `app.py`: Entrypoint; implements UI, state, and orchestration across modules.
- `engine.py`: Isolates business rules for scoring; keeps the model agnostic of applied scoring heuristics.
- `model.py`: Contains the neural network definition, allowing training / inference separately.
- `check_setup.py`: Utility to verify that required dependencies are installed.
- `PROGRESS.md`: Development log; not part of runtime.
- `pyrightconfig.json`: Configures static type checking for tools like Pyright.

---

## 5. File-by-File Explanation

### File: `app.py`

**Simple Explanation:**
This is the UI application. It creates the dashboard, shows the fleet of devices, allows you to pick a device, tweak its “network traffic” values, and see whether the device is considered safe or compromised.

**Technical Explanation:**
- Uses `streamlit` as the front-end framework.
- Defines an in-memory `IOT_REGISTRY` dict containing a static fleet of 10 devices. Each device has:
  - `name`, `type`, `sector`, `baseline` feature vector, and `icon`.
- Maintains persistent UI state with `st.session_state`, including:
  - `page`: either `fleet` or `dashboard`
  - `active_device`: selected device ID
  - `device_health`: map from device IDs to `Healthy`/`Compromised`
  - `packet_history`: a pandas DataFrame representing recent “packet records”
  - `threat_log` and `remediation_log`
- Uses `@st.cache_resource` on `load_aegis_engine()` to cache the `LSTMAutoencoder` instance.
- When a device is selected, it renders a drilldown dashboard:
  - Sidebar: sliders for `Pkt Size`, `IAT`, `Entropy`, `Symmetry`.
  - Generates a synthetic sequence by repeating a 4-feature vector 10 times.
  - Runs inference through the model and uses `engine.calculate_jsd` and `engine.calculate_trust_score`.
  - Determines status (`SAFE`/`COMPROMISED`) based on a hard threshold (trust >= 50).
  - Updates charts and logs: Plotly gauge, radar plot, packet table, threat log.
  - Supports “Live Scan Mode” using `time.sleep(1)` + `st.rerun()` to continuously update.

**Dependencies imported:**
- `streamlit`, `numpy`, `pandas`, `plotly.graph_objects`, `time`, `datetime`, `random`, `torch`
- Local modules: `engine.calculate_trust_score`, `engine.calculate_jsd`, `model.LSTMAutoencoder`

**What depends on this file:**
- This file is the entrypoint; nothing else imports it. The rest of the system is driven by it.

---

### File: `model.py`

**Simple Explanation:**
This file defines the neural network model that learns how normal traffic behaves. During execution, it attempts to reconstruct traffic sequences; larger reconstruction error flags an anomaly.

**Technical Explanation:**
- Defines an LSTM autoencoder architecture:
  - `Encoder`: LSTM → final hidden state → linear projection to latent vector.
  - `Decoder`: linear projection from latent → repeated hidden vector → LSTM → linear projection to reconstruct original features.
  - `LSTMAutoencoder`: wraps encoder + decoder and provides `reconstruction_error()` which returns per-sample MSE.
- Constants configure model shape:
  - `INPUT_FEATURES = 4`
  - `SEQ_LEN = 10`
  - `HIDDEN_SIZE = 64`, `LATENT_SIZE = 32`, `NUM_LAYERS = 2`, `DROPOUT = 0.2`
- `reconstruction_error()` computes MSE per sample across sequence + feature dims.
- Includes a runnable test block (via `if __name__ == "__main__"`) that demonstrates the model output shapes.

**Dependencies imported:**
- `torch`, `torch.nn`, `torch.nn.functional`

**What depends on this file:**
- `app.py` imports `LSTMAutoencoder`.

---

### File: `engine.py`

**Simple Explanation:**
This file converts raw model output into a “trust score” that the UI uses to decide whether a device is safe. It also computes a measure of distribution drift.

**Technical Explanation:**
- Implements two key functions:
  - `calculate_jsd(p, q)`: Jensen-Shannon Divergence (JSD) between two distributions.
    - Normalizes inputs to sum to 1.
    - Computes mixture distribution `m = (p + q) / 2`.
    - Uses `scipy.stats.entropy` with base-2 and clamps output to [0, 1].
  - `calculate_trust_score(reconstruction_error, jsd_value)`: computes a 0–100 score.
    - Starts from 100.
    - Applies a penalty when:
      - `reconstruction_error > 0.10` (penalty = (error - 0.10) × 200)
      - `jsd_value > 0.30` (penalty = (jsd - 0.30) × 100)
    - Clamps output to [0, 100].
- Contains CLI scenario test block for manual verification.

**Dependencies imported:**
- `numpy` and `scipy.stats.entropy`

**What depends on this file:**
- `app.py` imports both `calculate_jsd` and `calculate_trust_score`.

---

### File: `check_setup.py`

**Simple Explanation:**
A helper script that verifies the required Python packages are installed.

**Technical Explanation:**
- Imports a fixed list of packages and prints pass/fail status with versions.
- Designed to be run from the command line: `python check_setup.py`.
- Not used by the main dashboard.

**Dependencies imported:**
- `sys` (standard library)

---

## 6. Key Modules and Their Responsibilities

### UI / Orchestration (`app.py`)
- Responsible for
  - Application layout and styling
  - Device selection and navigation
  - Collecting user inputs (feature sliders, scan toggle)
  - Feeding inputs into the digital twin and engine
  - Displaying charts (Plotly) and logs (pandas DataFrame)
  - Managing state using `st.session_state`
- Does not perform offline training, persistence, or any network I/O.

### Digital Twin Model (`model.py`)
- Defines the LSTM autoencoder that acts as the digital twin.
- Responsible for generating an anomaly score (MSE) for a sequence.
- Is intentionally self-contained and has no external dependencies other than PyTorch.

### Scoring Engine (`engine.py`)
- Responsible for translating model output and baseline drift into a human-friendly metric (Trust Score).
- Provides statistical divergence logic (JSD) to compare current traffic against baseline.
- Encapsulates thresholds and penalty scaling constants.

### State & Runtime Data
- `st.session_state` is the only “database” in the system.
- Stores:
  - Which page is active (`fleet` vs `dashboard`)
  - Selected device ID
  - Per-device health status
  - Time-series packet logs (as pandas DataFrame)
  - Threat log (list of dicts)
  - Remediation history (list of dicts)

---

## 7. Data Models / Schemas

### In-memory IoT Registry
- Defined in `app.py` as `IOT_REGISTRY`.
- Schema per device:
  - `name` (string)
  - `type` (string)
  - `sector` (string)
  - `baseline` (list[float]) — 4 baseline feature values
  - `icon` (string, emoji)

### Feature Vector
Each device’s traffic is represented as a 4-element feature vector:
1. Packet Size (normalized 0–1)
2. Inter-Arrival Time (normalized 0–1)
3. Payload Entropy (normalized 0–1)
4. Flow Symmetry (normalized 0–1)

### Synthetic Packet Record (Packet History)
Stored as a pandas DataFrame with columns:
- `Time` (string HH:MM:SS)
- `Pkt Size` (float)
- `IAT` (float)
- `Entropy` (float)
- `Symmetry` (float)
- `Status` ("Safe" or "Alert")

### Threat Log / Remediation Log
- A list of dictionaries, each with keys like `time`, `msg`, `Timestamp`, `Device ID`, etc.

### Model Input / Output (PyTorch tensors)
- Inference input: tensor shape `(1, 10, 4)`
- Reconstruction output: tensor shape `(1, 10, 4)`
- Reconstruction loss: scalar MSE (`float`)

---

## 8. External Dependencies

### `streamlit`
- Provides the entire UI framework.
- Used for layout, widgets (sliders, buttons, toggles), and state management.

### `torch` (PyTorch)
- Implements the LSTM autoencoder.
- Used for model definition, forward pass, and computing MSE.

### `numpy`
- Numeric arrays & conversions.
- Used to assemble feature vectors, compute distributions.

### `pandas`
- Used to store/format packet history as a DataFrame and to render tables.

### `plotly`
- Used for interactive charts (gauge and radar plots).

### `scipy`
- Used to compute Jensen-Shannon Divergence via `scipy.stats.entropy`.

### `scikit-learn` and `shap`
- Listed as dependencies in `check_setup.py` but not currently used in runtime. They are likely planned for future extensions.

---

## 9. Current System Limitations

### Missing Features
- **No persistence**: All state is in-memory. Refreshing the browser resets all state.
- **No data collection / training pipeline**: The model is never trained in this repo; it is instantiated with random weights.
- **No real traffic ingestion**: Traffic features are manual slider inputs + random synthetic values.
- **No authentication**: Anyone running the app has full access.

### Technical Debt & Improvements
- **Hardcoded thresholds** in `engine.py` (e.g., `MSE_THRESHOLD = 0.10`) are not tunable via UI or config.
- The `LSTMAutoencoder` is not saved/loaded from disk; weights are reset on every run.
- `app.py` uses `time.sleep(1)` + `st.rerun()` for live updates, which is a crude implementation that can be improved with Streamlit’s `st.experimental_rerun` or `st.autorefresh`.
- `IOT_REGISTRY` is static; better to load from JSON/YAML or a database.
- No unit tests / CI.

---

## 10. Extension Guide for Future AI Agents

### Where to add new features
- **New dashboard panels**: modify `app.py` under the `dashboard` section.
- **New devices**: add entries to `IOT_REGISTRY` or implement a loader.
- **New anomaly signals**: add functions to `engine.py` (e.g., additional statistical metrics) and surface them in the UI.

### Where business logic should live
- **Model & inference logic**: `model.py`.
- **Scoring and decision logic**: `engine.py`.
- **Orchestration/UI logic**: `app.py`.

### Where UI components should go
- Keep UI markup in `app.py`.
- If the UI grows, consider splitting into modules (e.g., `ui/fleet.py`, `ui/dashboard.py`) and importing them into `app.py`.

### Safely modifying the architecture
1. **Start with tests**: add unit tests for `calculate_jsd` and `calculate_trust_score` (existing behavior should be preserved).
2. **Keep state changes isolated**: `st.session_state` keys should be namespaced (e.g., prefix with `aegis_`) if you add new state variables.
3. **Avoid global mutable state**: keep `IOT_REGISTRY` immutable; treat it as read-only data.
4. **Model persistence**: add a `models/` folder and implement `save()`/`load()` methods for `LSTMAutoencoder`.

---

## 11. Glossary

- **Digital Twin**: A software model that mirrors the behaviour of a physical system (in this case, network traffic patterns) and can be used to detect deviations.
- **LSTM Autoencoder**: A neural network that compresses a time series using LSTM encoder/decoder and reconstructs it; reconstruction error indicates anomaly.
- **Reconstruction Error (MSE)**: Mean squared error between input and reconstructed output; used as an anomaly signal.
- **Jensen-Shannon Divergence (JSD)**: A symmetric measure of difference between two probability distributions.
- **Trust Score**: A 0–100 score combining MSE and JSD to indicate how much the system trusts current traffic.
- **Streamlit Session State**: A key-value store provided by Streamlit to persist state across reruns in the same browser session.
- **`st.cache_resource`**: Streamlit decorator that caches an object (such as a model instance) between reruns.

---

> 📌 **Note:** This doc is intended to be updated as the project grows. If you add new modules, extend this file with new sections that maintain the same structured format.
