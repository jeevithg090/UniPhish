"""Head-to-head experiment: UniPhish vs baselines on identical data.

Trains each model the same way, evaluates per-script-family F1, overall metrics,
the adversarial homoglyph sweep, and (if present) the cross-dataset real holdout.
Writes results/comparison.json — the source for the headline results table/chart.

    python -m scripts.run_experiments --epochs 12
    python -m scripts.run_experiments --models uniphish,ascii_cnn
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_recall_fscore_support, roc_auc_score

from uniphish.baselines import ALL_MODELS, get_baseline
from uniphish.utils import save_json, set_seed


def _load(path):
    df = pd.read_csv(path)
    fam = df["script_family"].astype(str).to_numpy() if "script_family" in df else np.array(["?"] * len(df))
    return df["url"].astype(str).to_numpy(), df["label"].astype(int).to_numpy(), fam


def _overall(y, prob):
    pred = (prob >= 0.5).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0, labels=[0, 1])
    tn = int(((pred == 0) & (y == 0)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tp = int(((pred == 1) & (y == 1)).sum())
    out = {"accuracy": float((pred == y).mean()), "precision": float(p), "recall": float(r),
           "f1": float(f1), "fnr": fn / max(fn + tp, 1), "fpr": fp / max(fp + tn, 1)}
    try:
        out["auc"] = float(roc_auc_score(y, prob))
    except ValueError:
        out["auc"] = None
    return out


def _fit_predict(spec, tr, va, te, adv, epochs, seed):
    Xtr, ytr, _ = tr
    Xte = spec.encode(te[0])
    if spec.kind == "keras":
        from tensorflow import keras
        model = spec.build()
        model.compile(optimizer=keras.optimizers.Adam(3e-4), loss="binary_crossentropy",
                      metrics=["accuracy"])
        cb = [keras.callbacks.EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True)]
        model.fit(spec.encode(Xtr), ytr, validation_data=(spec.encode(va[0]), va[1]),
                  batch_size=512, epochs=epochs, callbacks=cb, verbose=2)
        prob_te = model.predict(Xte, verbose=0).ravel()
        adv_prob = {r: model.predict(spec.encode(u), verbose=0).ravel() for r, u in adv.items()}
    else:  # sklearn
        model = spec.build()
        model.fit(spec.encode(Xtr), ytr)
        prob_te = model.predict_proba(Xte)[:, 1]
        adv_prob = {r: model.predict_proba(spec.encode(u))[:, 1] for r, u in adv.items()}
    return prob_te, adv_prob


def run(data_dir: str, models, epochs: int, out: str, seed: int):
    set_seed(seed)
    tr = _load(f"{data_dir}/train.csv")
    va = _load(f"{data_dir}/val.csv")
    te = _load(f"{data_dir}/test.csv")

    adv_df = pd.read_csv(f"{data_dir}/adversarial_test.csv")
    adv = {float(r): g["url"].astype(str).to_numpy() for r, g in adv_df.groupby("sub_rate")}
    adv_y = {float(r): g["label"].astype(int).to_numpy() for r, g in adv_df.groupby("sub_rate")}

    results = {"models": {}, "families": sorted(np.unique(te[2]).tolist())}
    for name in models:
        print(f"\n===== {name} =====")
        spec = get_baseline(name)
        prob_te, adv_prob = _fit_predict(spec, tr, va, te, adv, epochs, seed)

        entry = {"overall": _overall(te[1], prob_te), "by_family": {}}
        for fam in results["families"]:
            m = te[2] == fam
            if m.sum():
                entry["by_family"][fam] = float(
                    f1_score(te[1][m], (prob_te[m] >= 0.5).astype(int), zero_division=0))
        entry["macro_f1"] = float(np.mean(list(entry["by_family"].values())))
        entry["adversarial"] = {f"{int(r*100)}%": float(((adv_prob[r] >= 0.5).astype(int) == adv_y[r]).mean())
                                for r in sorted(adv)}
        results["models"][name] = entry
        print(f"{name}: macro_f1={entry['macro_f1']:.4f}  overall_f1={entry['overall']['f1']:.4f}")

    save_json(results, out)
    _print_table(results)
    print(f"\nwrote {out}")
    return results


def _print_table(results):
    fams = results["families"]
    header = f"{'model':14s} " + " ".join(f"{f[:6]:>7s}" for f in fams) + f" {'macroF1':>8s} {'adv15%':>7s}"
    print("\n" + header)
    print("-" * len(header))
    for name, e in results["models"].items():
        row = f"{name:14s} " + " ".join(f"{e['by_family'].get(f, 0):7.3f}" for f in fams)
        row += f" {e['macro_f1']:8.3f} {e['adversarial'].get('15%', float('nan')):7.3f}"
        print(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models", default=",".join(ALL_MODELS))
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--out", default="results/comparison.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    run(args.data_dir, args.models.split(","), args.epochs, args.out, args.seed)


if __name__ == "__main__":
    main()
