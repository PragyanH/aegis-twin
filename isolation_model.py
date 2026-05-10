"""
isolation_model.py — Isolation Forest anomaly detector for Aegis-Twin
=======================================================================
Replaces the LSTM Autoencoder for real hardware deployment on Raspberry Pi.
Trained on ~2 min of normal thermostat traffic, scores live windows.

Features (must match sniffer.py output):
  0 – packet_size     (normalized 0-1)
  1 – iat             (inter-arrival time, normalized 0-1)
  2 – entropy         (payload entropy, normalized 0-1)
  3 – symmetry        (flow symmetry ratio 0-1)
"""

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from pathlib import Path
from collections import deque
import threading
import time

# ── Config ───────────────────────────────────────────────────────────────────

MODEL_PATH         = Path("aegis_isolation_forest.pkl")
CONTAMINATION      = 0.05   # expect ~5% anomalies during training
N_ESTIMATORS       = 100
WINDOW_SIZE        = 20     # rolling window of samples for smoothing
MIN_TRAIN_SAMPLES  = 20     # Lowered from 100 for faster testing/force training

# ── Shared state ─────────────────────────────────────────────────────────────

_lock = threading.Lock()
_model: IsolationForest | None = None
_is_trained        = False
_baseline_buffer:  list[list[float]] = []
_score_window:     deque = deque(maxlen=WINDOW_SIZE)
_score_min: float  = -0.5   # fallback defaults, overwritten after training
_score_max: float  = -0.1

# ── Training progress state ───────────────────────────────────────────────────
_training_in_progress   = False
_training_start_time    = None
_training_status        = "idle"  # idle, in_progress, completed, failed
_training_last_summary  = None


# ── Baseline collection ───────────────────────────────────────────────────────

def add_baseline_sample(features: list[float]) -> None:
    """Add a feature vector to the baseline buffer during learning phase."""
    global _baseline_buffer
    with _lock:
        _baseline_buffer.append(features)


# ── Training ──────────────────────────────────────────────────────────────────

def estimate_training_time(num_samples: int) -> dict:
    """
    Estimate training time based on number of samples.
    Returns estimated seconds and formatted string.
    """
    # Isolation Forest scales roughly linearly with samples for this size
    # Empirically: ~0.005 sec per sample for N_ESTIMATORS=100 on Pi/x86
    base_time = 0.005 * num_samples
    
    return {
        "estimated_seconds": max(1, int(base_time)),
        "estimated_minutes": round(base_time / 60, 2),
        "formatted": f"{max(1, int(base_time))}s" if base_time < 60 else f"{round(base_time / 60, 1)}m"
    }


def train_model() -> dict:
    """
    Train Isolation Forest on collected baseline samples with train/test split.
    Call this after ~2 minutes of normal traffic collection.
    Returns training summary dict with test scores.
    """
    global _model, _is_trained, _score_min, _score_max, _training_in_progress
    global _training_status, _training_start_time, _training_last_summary

    with _lock:
        data = np.array(_baseline_buffer, dtype=np.float32)

    if len(data) < MIN_TRAIN_SAMPLES:
        raise ValueError(
            f"Not enough baseline samples: {len(data)} < {MIN_TRAIN_SAMPLES}. "
            "Let the device run longer in baseline mode."
        )

    # Mark training as in progress
    with _lock:
        _training_in_progress = True
        _training_start_time = time.time()
        _training_status = "in_progress"

    try:
        # Split data: 80% train, 20% test
        X_train, X_test = train_test_split(
            data, test_size=0.2, random_state=42
        )

        model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,   # use all cores (Raspberry Pi has 4)
        )
        model.fit(X_train)

        # Compute real score bounds from training data
        train_scores = -model.score_samples(X_train)
        test_scores = -model.score_samples(X_test)
        
        p5  = float(np.percentile(train_scores, 5))    # floor: most normal end
        p95 = float(np.percentile(train_scores, 95))   # ceiling: edge of normal

        # Calculate test metrics
        test_mean = float(np.mean(test_scores))
        test_std = float(np.std(test_scores))
        test_min = float(np.min(test_scores))
        test_max = float(np.max(test_scores))
        
        # Detection rate on test set (anomalies detected)
        test_predictions = model.predict(X_test)
        anomaly_count = int(np.sum(test_predictions == -1))
        anomaly_rate = (anomaly_count / len(X_test)) * 100

        elapsed = time.time() - _training_start_time

        with _lock:
            _model      = model
            _is_trained = True
            _score_min  = p5
            _score_max  = p95
            _training_status = "completed"

        # Save model + bounds together
        joblib.dump(
            {"model": model, "score_min": _score_min, "score_max": _score_max},
            MODEL_PATH,
        )

        summary = {
            "success":              True,
            "samples_total":        len(data),
            "samples_trained":      len(X_train),
            "samples_tested":       len(X_test),
            "training_time_sec":    round(elapsed, 2),
            "score_min":            _score_min,
            "score_max":            _score_max,
            "train_score_mean":     float(np.mean(train_scores)),
            "train_score_std":      float(np.std(train_scores)),
            "test_score_mean":      test_mean,
            "test_score_std":       test_std,
            "test_score_min":       test_min,
            "test_score_max":       test_max,
            "test_anomaly_rate":    round(anomaly_rate, 2),
            "threshold_suggested":  float(p95),
        }

        with _lock:
            _training_last_summary = summary

        print(
            f"[IsolationForest] Trained in {elapsed:.2f}s on {len(X_train)} samples\n"
            f"  Test Results:\n"
            f"    Score Mean: {test_mean:.4f}, Std: {test_std:.4f}\n"
            f"    Score Range: [{test_min:.4f}, {test_max:.4f}]\n"
            f"    Anomaly Rate: {anomaly_rate:.2f}%\n"
            f"  Bounds: [{p5:.4f}, {p95:.4f}]"
        )

        return summary

    except Exception as e:
        with _lock:
            _training_status = "failed"
            _training_in_progress = False
        print(f"[IsolationForest] Training failed: {e}")
        raise
    finally:
        with _lock:
            _training_in_progress = False


# ── Load from disk ────────────────────────────────────────────────────────────

def load_model() -> bool:
    """Load a previously saved model + bounds from disk."""
    global _model, _is_trained, _score_min, _score_max
    if MODEL_PATH.exists():
        saved = joblib.load(MODEL_PATH)
        with _lock:
            _model      = saved["model"]
            _score_min  = saved["score_min"]
            _score_max  = saved["score_max"]
            _is_trained = True
        print(
            f"[IsolationForest] Loaded model from {MODEL_PATH}\n"
            f"  score_min = {_score_min:.4f} | score_max = {_score_max:.4f}"
        )
        return True
    return False


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_sample(features: list[float]) -> dict:
    """
    Score a single feature vector against the trained model.

    Returns:
        {
            "anomaly_score":  float (0.0–1.0, higher = more anomalous),
            "is_anomaly":     bool,
            "raw_score":      float (raw IF output, more negative = more anomalous),
            "smoothed_score": float (rolling average over last WINDOW_SIZE samples),
            "model_ready":    bool
        }
    """
    global _score_window

    if not _is_trained or _model is None:
        return {
            "anomaly_score":  0.0,
            "is_anomaly":     False,
            "raw_score":      0.0,
            "smoothed_score": 0.0,
            "model_ready":    False,
        }

    x = np.array([features], dtype=np.float32)

    with _lock:
        raw   = float(_model.score_samples(x)[0])
        label = int(_model.predict(x)[0])    # -1 = anomaly, 1 = normal
        s_min = _score_min
        s_max = _score_max

    neg_raw = -raw   # flip sign: higher value = more anomalous

    # Normalize using YOUR data's actual p5–p95 bounds
    span = s_max - s_min
    if span < 1e-6:
        # Degenerate case: all training scores were identical
        anomaly_score = 0.0
    else:
        anomaly_score = float(np.clip((neg_raw - s_min) / span, 0.0, 1.0))

    _score_window.append(anomaly_score)

    return {
        "anomaly_score":  anomaly_score,
        "is_anomaly":     label == -1,
        "raw_score":      raw,
        "smoothed_score": float(np.mean(_score_window)),
        "model_ready":    True,
    }


# ── Trust score (high-level) ──────────────────────────────────────────────────

def get_trust_score(features: list[float]) -> float:
    """
    Score features and return a trust score in range 0–100.

    During learning phase (model not trained): returns 95.0.
    After training: 100 - (smoothed_anomaly_score * 100), clamped to [0, 100].
    """
    result = score_sample(features)

    if not result["model_ready"]:
        return 95.0   # learning phase — show near-perfect trust

    smoothed = result.get("smoothed_score", result["anomaly_score"])
    trust = 100.0 - (smoothed * 100.0)
    return round(float(np.clip(trust, 0.0, 100.0)), 2)


# ── Status ────────────────────────────────────────────────────────────────────

def get_status() -> dict:
    """Return current model status — useful for dashboard display."""
    return {
        "is_trained":        _is_trained,
        "baseline_samples":  len(_baseline_buffer),
        "model_path":        str(MODEL_PATH),
        "ready_to_train":    len(_baseline_buffer) >= MIN_TRAIN_SAMPLES,
        "score_min":         _score_min,
        "score_max":         _score_max,
    }


def get_training_status() -> dict:
    """Get current training progress and status."""
    with _lock:
        in_progress = _training_in_progress
        status = _training_status
        start_time = _training_start_time
        summary = _training_last_summary
        baseline_count = len(_baseline_buffer)
        is_trained = _is_trained
    
    # Map trained state to monitoring status if idle
    display_status = status
    if status == "idle" and is_trained:
        display_status = "monitoring"
    elif status == "idle" and baseline_count > 0:
        display_status = "learning"

    result = {
        "status": display_status,
        "in_progress": in_progress,
        "baseline_samples": baseline_count,
        "ready_to_train": baseline_count >= MIN_TRAIN_SAMPLES,
        "min_samples_required": MIN_TRAIN_SAMPLES,
        "is_trained": is_trained
    }
    
    if in_progress and start_time:
        elapsed = time.time() - start_time
        result["elapsed_seconds"] = round(elapsed, 2)
    
    if summary:
        result["last_summary"] = summary
    
    return result


def reset_training() -> bool:
    """Reset the model and training buffer to start fresh."""
    global _baseline_buffer, _is_trained, _model, _training_last_summary, _training_status
    with _lock:
        _baseline_buffer = []
        _is_trained = False
        _model = None
        _training_last_summary = None
        _training_status = "idle"
        _score_window.clear()
        
    # Delete model file if it exists
    if MODEL_PATH.exists():
        try:
            MODEL_PATH.unlink()
            print(f"[IsolationForest] Deleted model file: {MODEL_PATH}")
            return True
        except Exception as e:
            print(f"[IsolationForest] Error deleting model file: {e}")
            return False
    return True


def get_training_estimate(num_samples: int = None) -> dict:
    """Get time estimate for training based on sample count."""
    with _lock:
        samples = num_samples or len(_baseline_buffer)
    
    if samples < MIN_TRAIN_SAMPLES:
        return {
            "can_train": False,
            "estimated_seconds": 0,
            "message": f"Need {MIN_TRAIN_SAMPLES - samples} more samples"
        }
    
    estimate = estimate_training_time(samples)
    return {
        "can_train": True,
        "estimated_seconds": estimate["estimated_seconds"],
        "estimated_minutes": estimate["estimated_minutes"],
        "formatted": estimate["formatted"],
        "sample_count": samples,
    }


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Isolation Forest — Self Test")
    print("=" * 55)

    # Simulate 150 normal samples
    rng = np.random.default_rng(42)
    normal_data = rng.normal(loc=[0.15, 0.30, 0.20, 0.50], scale=0.05, size=(150, 4))
    normal_data = np.clip(normal_data, 0, 1).tolist()

    for sample in normal_data:
        add_baseline_sample(sample)

    summary = train_model()
    print(f"\nTraining summary: {summary}\n")

    # Score a normal sample
    normal_sample  = [0.15, 0.30, 0.20, 0.50]
    attack_sample  = [0.05, 0.01, 0.90, 0.05]   # port scan profile

    r_normal = score_sample(normal_sample)
    r_attack = score_sample(attack_sample)

    print(f"Normal sample  → anomaly_score={r_normal['anomaly_score']:.3f}  "
          f"trust={get_trust_score(normal_sample):.1f}")
    print(f"Attack sample  → anomaly_score={r_attack['anomaly_score']:.3f}  "
          f"trust={get_trust_score(attack_sample):.1f}")
    print("\nSelf-test complete.")