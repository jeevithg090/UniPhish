"""Evaluate a trained UniPhish model — Section VI metrics.

Computes overall + per-script-family accuracy / precision / recall / F1 / AUC,
the security-critical false-negative & false-positive rates, per-family confusion
matrices, and the adversarial robustness sweep. Writes a structured results.json
that the figure scripts consume (replacing their hardcoded numbers).
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd
from sklearn.metrics import (auc, confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)
from tensorflow import keras

from uniphish.dataset import load_split
from uniphish.encoding import encode_batch
from uniphish.utils import save_json


def _rates(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fnr = fn / (fn + tp) if (fn + tp) else 0.0   # phishing missed (security-critical)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0   # legit wrongly flagged
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
            "fnr": float(fnr), "fpr": float(fpr)}


def _metrics(y_true, prob, thr=0.5):
    y_pred = (prob >= thr).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary",
                                                  zero_division=0, labels=[0, 1])
    out = {"accuracy": float((y_pred == y_true).mean()),
           "precision": float(p), "recall": float(r), "f1": float(f1)}
    try:
        out["auc"] = float(roc_auc_score(y_true, prob))
    except ValueError:
        out["auc"] = None
    out.update(_rates(y_true, y_pred))
    return out


def evaluate(model_path: str, data_dir: str, out: str = "results/results.json"):
    model = keras.models.load_model(model_path)
    test = load_split(f"{data_dir}/test.csv")
    prob = model.predict(test.X, verbose=0).ravel()
    y = test.y.astype(int)

    results = {"model": model_path, "overall": _metrics(y, prob), "by_family": {}}
    f1s = []
    for fam in sorted(np.unique(test.families)):
        m = test.families == fam
        fam_metrics = _metrics(y[m], prob[m])
        cm = confusion_matrix(y[m], (prob[m] >= 0.5).astype(int), labels=[0, 1])
        fam_metrics["confusion"] = cm.tolist()
        results["by_family"][fam] = fam_metrics
        f1s.append(fam_metrics["f1"])
    results["macro_f1"] = float(np.mean(f1s))
    results["macro_accuracy"] = float(np.mean([v["accuracy"] for v in results["by_family"].values()]))

    # Adversarial robustness sweep
    adv_path = f"{data_dir}/adversarial_test.csv"
    try:
        adv = pd.read_csv(adv_path)
        sweep = {"clean": results["overall"]["accuracy"]}
        for rate, g in adv.groupby("sub_rate"):
            Xa = encode_batch(g["url"].astype(str).to_numpy())
            pa = model.predict(Xa, verbose=0).ravel()
            ya = g["label"].astype(int).to_numpy()
            sweep[f"{int(rate*100)}%"] = float(((pa >= 0.5).astype(int) == ya).mean())
        results["adversarial_sweep"] = sweep
    except FileNotFoundError:
        pass

    # Cross-dataset generalization: pure-real holdout NOT seen in training.
    # This is the honest number — expect it well below the in-distribution test.
    real_path = f"{data_dir}/real_test.csv"
    if os.path.exists(real_path):
        rt = load_split(real_path)
        rp = model.predict(rt.X, verbose=0).ravel()
        results["cross_dataset_real"] = _metrics(rt.y.astype(int), rp)
        results["cross_dataset_real"]["n"] = int(len(rt))

    save_json(results, out)
    print(f"[in-distribution]  macro_f1={results['macro_f1']:.4f}  macro_acc={results['macro_accuracy']:.4f}")
    print(f"[in-distribution]  overall FNR={results['overall']['fnr']:.4f}  FPR={results['overall']['fpr']:.4f}")
    if "adversarial_sweep" in results:
        print("adversarial:", {k: round(v, 3) for k, v in results["adversarial_sweep"].items()})
    if "cross_dataset_real" in results:
        c = results["cross_dataset_real"]
        print(f"[CROSS-DATASET real, n={c['n']}]  acc={c['accuracy']:.4f}  f1={c['f1']:.4f}  "
              f"FNR={c['fnr']:.4f}  FPR={c['fpr']:.4f}   <- the honest generalization number")
    print(f"wrote {out}")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--out", default="results/results.json")
    args = ap.parse_args()
    evaluate(args.model, args.data_dir, args.out)


if __name__ == "__main__":
    main()
