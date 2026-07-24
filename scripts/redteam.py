"""Red-team the detector: measure evasion rates and rules-layer recovery (Track E).

For a set of phishing URLs the model already flags, apply each evasion attack and
measure (a) how much the raw model's detection drops (evasion) and (b) whether the
fused risk score (model + enrichment rules) still catches it. Writes
results/robustness.json and prints a table for the model card / README.

    python -m scripts.redteam --n 200
"""

from __future__ import annotations

import argparse
import os
import random

from uniphish.attacks import ATTACKS
from uniphish.enrich import fused_risk
from uniphish.infer import UniPhishScorer
from uniphish.utils import save_json, set_seed


def _phishing_urls(n, data_dir, seed):
    path = f"{data_dir}/test.csv"
    if os.path.exists(path):
        import pandas as pd
        df = pd.read_csv(path)
        urls = df[df.label == 1]["url"].astype(str).tolist()
        if urls:
            random.Random(seed).shuffle(urls)
            return urls[:n]
    from data.synth import SynthConfig, synthesize
    rows = synthesize(SynthConfig(per_family=max(10, n // 3), seed=seed))
    return [r["url"] for r in rows if r["label"] == 1][:n]


def _detect_rate(scorer, urls):
    probs = [r["prob"] for r in scorer.scan_batch(urls)]
    return sum(p >= 0.5 for p in probs) / len(probs), probs


def _fused_catch_rate(urls, probs):
    caught = sum(fused_risk(p, u)["tier"] != "safe" for u, p in zip(urls, probs))
    return caught / len(urls)


def run(model, n, data_dir, out, seed):
    set_seed(seed)
    scorer = UniPhishScorer(model)
    rng = random.Random(seed)
    urls = _phishing_urls(n, data_dir, seed)
    base_det, _ = _detect_rate(scorer, urls)
    print(f"phishing URLs: {len(urls)}   baseline model detection: {base_det:.3f}\n")

    results = {"n": len(urls), "baseline_detection": round(base_det, 4), "attacks": {}}
    rows = []
    for name, fn in ATTACKS.items():
        adv = [fn(u, rng=rng) for u in urls]
        det, probs = _detect_rate(scorer, adv)
        fused = _fused_catch_rate(adv, probs)
        results["attacks"][name] = {"model_detection": round(det, 4),
                                    "evasion": round(base_det - det, 4),
                                    "fused_detection": round(fused, 4)}
        rows.append((name, det, base_det - det, fused))

    save_json(results, out)
    print(f"{'attack':18s} {'model_det':>10s} {'evasion':>9s} {'fused_det':>10s}")
    print("-" * 50)
    for name, det, ev, fused in sorted(rows, key=lambda r: -r[2]):
        print(f"{name:18s} {det:10.3f} {ev:9.3f} {fused:10.3f}")
    print(f"\nwrote {out}")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--out", default="results/robustness.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    run(args.model, args.n, args.data_dir, args.out, args.seed)


if __name__ == "__main__":
    main()
