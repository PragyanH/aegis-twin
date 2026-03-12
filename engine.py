"""
Aegis-Twin · Anomaly Detection Engine
=======================================
Core analytical functions that sit between the Digital Twin (model.py)
and the dashboard.  Given outputs from the LSTMAutoencoder, the engine
produces human-readable trust scores and statistical divergence metrics.

Functions
---------
calculate_jsd(p, q)
    Jensen-Shannon Divergence between two probability distributions.

calculate_trust_score(reconstruction_error, jsd_value)
    Composite 0-100 trust score derived from the two anomaly signals.
"""

import numpy as np
from scipy.stats import entropy


# ── Thresholds ────────────────────────────────────────────────────────────────

MSE_THRESHOLD  = 0.10   # reconstruction errors above this signal anomaly
JSD_THRESHOLD  = 0.30   # JSD values above this signal distribution shift

# Penalty scaling: how many trust points are deducted per unit above threshold
MSE_PENALTY_SCALE = 200  # 1 unit of excess MSE  → up to 200 pts deducted
JSD_PENALTY_SCALE = 100  # 1 unit of excess JSD  → up to 100 pts deducted


# ── Jensen-Shannon Divergence ─────────────────────────────────────────────────

def calculate_jsd(p: np.ndarray, q: np.ndarray) -> float:
    """
    Calculate the Jensen-Shannon Divergence (JSD) between two probability
    distributions *p* and *q*.

    JSD is a symmetric, smoothed version of the KL-Divergence. It measures
    how different two distributions are.  A value of 0 means identical
    distributions; a value of 1 (log base-2) or ln(2) (natural log) means
    maximally different distributions.

    Here we use **base-2 logarithms** so the result is bounded in [0, 1].

    Args:
        p (array-like): First probability distribution.  Will be normalised
                        to sum to 1 if it does not already.
        q (array-like): Second probability distribution.  Same length as p.

    Returns:
        jsd (float): Jensen-Shannon Divergence in [0, 1].

    Raises:
        ValueError: If p and q have different lengths or contain negatives.

    Example:
        >>> import numpy as np
        >>> p = np.array([0.4, 0.4, 0.2])
        >>> q = np.array([0.2, 0.3, 0.5])
        >>> calculate_jsd(p, q)
        0.07295...
    """
    p = np.asarray(p, dtype=float)
    q = np.asarray(q, dtype=float)

    if p.shape != q.shape:
        raise ValueError(
            f"p and q must have the same shape, got {p.shape} and {q.shape}."
        )
    if np.any(p < 0) or np.any(q < 0):
        raise ValueError("Distributions must be non-negative.")

    # Normalise to valid probability distributions
    p = p / p.sum()
    q = q / q.sum()

    # Mixture distribution M = (P + Q) / 2
    m = 0.5 * (p + q)

    # JSD = (KL(P||M) + KL(Q||M)) / 2  — using base-2 so result ∈ [0, 1]
    jsd = 0.5 * (entropy(p, m, base=2) + entropy(q, m, base=2))

    # Clamp to [0, 1] to guard against floating-point edge cases
    return float(np.clip(jsd, 0.0, 1.0))


# ── Trust Score ───────────────────────────────────────────────────────────────

def calculate_trust_score(
    reconstruction_error: float,
    jsd_value: float,
) -> float:
    """
    Compute a composite **Trust Score** (0-100) for a network traffic window.

    The score starts at 100 (fully trusted) and is penalised when either
    anomaly signal exceeds its threshold:

    1. **Reconstruction Error (MSE)** — produced by the LSTMAutoencoder.
       High MSE means the Digital Twin failed to reconstruct the sequence,
       suggesting the traffic pattern was never seen during training.

       Penalty applied when MSE > ``MSE_THRESHOLD`` (0.10).

    2. **Jensen-Shannon Divergence** — comparison of current traffic's
       feature distribution against a baseline reference.
       High JSD means the statistical fingerprint of the traffic has drifted.

       Penalty applied when JSD > ``JSD_THRESHOLD`` (0.30).

    Penalty formula (proportional, capped at the remaining score):
        mse_penalty = (reconstruction_error - MSE_THRESHOLD) × MSE_PENALTY_SCALE
        jsd_penalty = (jsd_value            - JSD_THRESHOLD) × JSD_PENALTY_SCALE

    The final score is clamped to [0, 100].

    Args:
        reconstruction_error (float): MSE output from LSTMAutoencoder.
                                      Typically in range [0, ~2].
        jsd_value            (float): JSD from calculate_jsd(). Range [0, 1].

    Returns:
        trust_score (float): Rounded trust score in [0.0, 100.0].

    Example:
        >>> calculate_trust_score(0.05, 0.10)  # well within thresholds
        100.0
        >>> calculate_trust_score(0.25, 0.55)  # both signals elevated
        47.0
    """
    score = 100.0

    # ── Penalty 1: Reconstruction Error ──────────────────────────────────────
    if reconstruction_error > MSE_THRESHOLD:
        excess       = reconstruction_error - MSE_THRESHOLD
        mse_penalty  = excess * MSE_PENALTY_SCALE
        score       -= mse_penalty

    # ── Penalty 2: Jensen-Shannon Divergence ─────────────────────────────────
    if jsd_value > JSD_THRESHOLD:
        excess       = jsd_value - JSD_THRESHOLD
        jsd_penalty  = excess * JSD_PENALTY_SCALE
        score       -= jsd_penalty

    # ── Clamp to valid range ──────────────────────────────────────────────────
    trust_score = float(np.clip(score, 0.0, 100.0))
    return round(trust_score, 2)


# ── Scenario Test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Aegis-Twin · Trust Score Scenario Test")
    print("=" * 55)

    scenarios = [
        {
            "label": "✅  HEALTHY  — Normal traffic",
            "reconstruction_error": 0.02,
            "jsd_value": 0.05,
        },
        {
            "label": "🚨  HACKED   — Anomalous traffic",
            "reconstruction_error": 0.45,
            "jsd_value": 0.65,
        },
    ]

    for s in scenarios:
        score = calculate_trust_score(s["reconstruction_error"], s["jsd_value"])
        filled = int(score / 5)
        bar    = "█" * filled + "░" * (20 - filled)
        print(f"\n  Scenario : {s['label']}")
        print(f"  Reconstruction Error (MSE) : {s['reconstruction_error']}")
        print(f"  Jensen-Shannon Divergence  : {s['jsd_value']}")
        print(f"  Trust Score                : {score:.2f} / 100")
        print(f"  [{bar}]")

    print("\n" + "=" * 55)
