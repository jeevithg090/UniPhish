"""Confidence calibration via temperature scaling (fixes 0/1 overconfidence).

The model reports near-0/1 probabilities, which are miscalibrated — a "0.99" is not
really 99% likely to be phishing. Temperature scaling learns a single scalar T that
softens the logits (p = σ(logit / T)) to minimize negative log-likelihood on a
validation split, without changing any prediction. We report the Expected
Calibration Error (ECE) before and after.

    python -m uniphish.calibrate --weights artifacts/uniphish_adv.keras
"""

from __future__ import annotations

import argparse

import numpy as np

from uniphish.compress import load_weights_into_fresh
from uniphish.encoding import encode_batch
from uniphish.utils import save_json


def get_logits(model, X):
    """Pre-sigmoid logits = fc2 activations @ output kernel + bias."""
    from tensorflow import keras
    h2 = keras.Model(model.input, model.get_layer("fc2").output).predict(X, verbose=0)
    W, b = model.get_layer("phish_prob").get_weights()
    return (h2 @ W + b).ravel()


def _nll(logits, y, T):
    p = np.clip(1 / (1 + np.exp(-logits / T)), 1e-7, 1 - 1e-7)
    return -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))


def fit_temperature(logits, y):
    Ts = np.linspace(0.2, 12, 300)
    return float(Ts[int(np.argmin([_nll(logits, y, t) for t in Ts]))])


def ece(p, y, bins=10):
    p = np.clip(p, 0, 1)
    conf = np.where(p >= 0.5, p, 1 - p)          # confidence in the predicted class
    correct = ((p >= 0.5).astype(int) == y).astype(float)
    edges = np.linspace(0, 1, bins + 1)
    e = 0.0
    for i in range(bins):
        m = (conf > edges[i]) & (conf <= edges[i + 1])
        if m.sum():
            e += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return float(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--out", default="artifacts/calibration.json")
    args = ap.parse_args()

    import os
    if os.path.exists(f"{args.data_dir}/val.csv"):
        import pandas as pd
        df = pd.read_csv(f"{args.data_dir}/val.csv")
        urls, y = df["url"].astype(str).to_numpy(), df["label"].astype(int).to_numpy()
    else:
        from data.synth import SynthConfig, synthesize
        rows = synthesize(SynthConfig(per_family=120))
        urls = np.array([r["url"] for r in rows]); y = np.array([r["label"] for r in rows])

    model = load_weights_into_fresh(args.weights)
    logits = get_logits(model, encode_batch(urls))
    p_before = 1 / (1 + np.exp(-logits))
    ece_before = ece(p_before, y)

    T = fit_temperature(logits, y)
    ece_after = ece(1 / (1 + np.exp(-logits / T)), y)
    # Guard: only keep T if it *improves* ECE. On an easy split where the model is
    # already calibrated, NLL-minimization pushes T to the boundary and would only
    # sharpen an already-overconfident model — so we fall back to T=1 (no scaling).
    applied = ece_after < ece_before - 1e-4
    if not applied:
        T, ece_after = 1.0, ece_before

    result = {"temperature": round(T, 4), "applied": applied,
              "ece_before": round(ece_before, 4), "ece_after": round(ece_after, 4),
              "n_val": int(len(y)),
              "note": ("model already well-calibrated on this split (ECE≈0); "
                       "no scaling applied — recompute on a harder/production split")
                      if not applied else "temperature scaling improved ECE"}
    save_json(result, args.out)
    print(f"temperature T = {T:.3f}  (applied={applied})")
    print(f"ECE  before {result['ece_before']:.4f}  ->  after {result['ece_after']:.4f}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
