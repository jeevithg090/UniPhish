"""Build the MultiPhishDB-style dataset (Section III of the paper).

Pipeline (mirrors the paper's four-stage annotation pipeline where applicable):
  1. Gather rows: synthetic (always) + real public feeds (optional, best-effort).
  2. Normalize + SHA-256 deduplicate.
  3. Per-(domain, class) cap of `per_domain_cap` to prevent domain memorization.
  4. Stratified 80/10/10 split by (script_family, label).
  5. Adversarial test set: homoglyph substitutions at {5,10,15,20}% on test phishing.

Outputs CSVs + dataset_stats.json under --out.

Usage:
  python -m data.build_dataset --small          # quick demo / CI (~1.2K URLs)
  python -m data.build_dataset --per-family 40000 --include-real
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
from typing import List

import pandas as pd

from data.synth import SynthConfig, synthesize
from uniphish.homoglyphs import HomoglyphMap

# 2-level public suffixes we should treat as part of the TLD when capping domains.
_TWO_LEVEL_TLDS = {"com.tr", "com.br", "co.in", "com.cn", "co.kr", "com.bd",
                    "co.tz", "com.qa", "co.uk", "com.au"}


def _normalize(url: str) -> str:
    u = url.strip()
    for sch in ("https://", "http://"):
        if u.lower().startswith(sch):
            u = sch + u[len(sch):]
            break
    return u.rstrip("/").lower()


def _registrable_domain(url: str) -> str:
    netloc = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    labels = netloc.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else netloc


def _dedup(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["_norm"] = df["url"].map(_normalize)
    df["_hash"] = df["_norm"].map(lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest())
    df = df.drop_duplicates("_hash")
    return df


def _cap_domains(df: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    df = df.copy()
    df["_dom"] = df["url"].map(_registrable_domain)
    # shuffle, then keep the first `cap` rows of each (domain, class) group
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df["_rank"] = df.groupby(["_dom", "label"]).cumcount()
    return df[df["_rank"] < cap].drop(columns="_rank").reset_index(drop=True)


def _stratified_split(df: pd.DataFrame, fracs, seed: int):
    train, val, test = [], [], []
    for _, g in df.groupby(["script_family", "label"]):
        g = g.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        n = len(g)
        n_tr = int(fracs[0] * n)
        n_va = int(fracs[1] * n)
        train.append(g.iloc[:n_tr])
        val.append(g.iloc[n_tr:n_tr + n_va])
        test.append(g.iloc[n_tr + n_va:])
    return (pd.concat(train).sample(frac=1, random_state=seed).reset_index(drop=True),
            pd.concat(val).reset_index(drop=True),
            pd.concat(test).reset_index(drop=True))


def _build_adversarial(test: pd.DataFrame, rates, seed: int) -> pd.DataFrame:
    """Apply homoglyph substitution to test PHISHING URLs at each rate."""
    homo = HomoglyphMap.builtin()
    rng = random.Random(seed)
    rows: List[dict] = []
    phish = test[test.label == 1]
    for rate in rates:
        for _, r in phish.iterrows():
            rows.append({
                "url": homo.substitute(r["url"], rate=rate, rng=rng),
                "label": 1, "script_family": r["script_family"],
                "technique": "homoglyph_adv", "source": "adversarial", "sub_rate": rate,
            })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/processed")
    ap.add_argument("--per-family", type=int, default=8000)
    ap.add_argument("--small", action="store_true", help="tiny dataset for CI/demo")
    ap.add_argument("--per-domain-cap", type=int, default=50)
    ap.add_argument("--include-real", action="store_true",
                    help="attempt to blend real public feeds (best-effort, needs network)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    per_family = 200 if args.small else args.per_family
    os.makedirs(args.out, exist_ok=True)

    cols = ["url", "label", "script_family", "technique", "source"]

    print(f"Synthesizing {per_family} URLs/family x 6 families ...")
    rows = synthesize(SynthConfig(per_family=per_family, seed=args.seed))
    df = pd.DataFrame(rows)[cols]

    # Real public feeds: blend most into the training pool; hold out 30% as a
    # pure-real CROSS-DATASET test (the honest generalization metric).
    real_holdout = None
    if args.include_real:
        try:
            from data.sources import fetch_real
            real = fetch_real(seed=args.seed)
            if real is not None and len(real):
                real = _dedup(real[cols])[cols].sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
                k = max(1, int(0.30 * len(real)))
                real_holdout = real.iloc[:k].copy()
                df = pd.concat([df, real.iloc[k:]], ignore_index=True)
                print(f"Blended {len(real) - k} real URLs; held out {k} for cross-dataset test")
        except Exception as e:  # network/credentials optional
            print(f"[warn] real feeds skipped: {e}")

    n0 = len(df)
    df = _dedup(df)
    print(f"Dedup: {n0} -> {len(df)}")
    df = _cap_domains(df, args.per_domain_cap, args.seed)
    print(f"After per-domain cap ({args.per_domain_cap}): {len(df)}")

    train, val, test = _stratified_split(df[cols], (0.8, 0.1, 0.1), args.seed)
    adv = _build_adversarial(test, [0.05, 0.10, 0.15, 0.20], args.seed)

    train.to_csv(f"{args.out}/train.csv", index=False)
    val.to_csv(f"{args.out}/val.csv", index=False)
    test.to_csv(f"{args.out}/test.csv", index=False)
    adv.to_csv(f"{args.out}/adversarial_test.csv", index=False)
    if real_holdout is not None:
        real_holdout[cols].to_csv(f"{args.out}/real_test.csv", index=False)
        print(f"Wrote {len(real_holdout)} real cross-dataset URLs to real_test.csv")

    stats = {
        "total": int(len(df)),
        "splits": {"train": len(train), "val": len(val), "test": len(test),
                    "adversarial": len(adv),
                    "real_test": int(len(real_holdout)) if real_holdout is not None else 0},
        "by_source": df.groupby("source").size().to_dict(),
        "by_family": df.groupby("script_family").size().to_dict(),
        "phish_ratio": float(df.label.mean()),
        "by_technique": df[df.label == 1].groupby("technique").size().to_dict(),
    }
    import json
    with open(f"{args.out}/dataset_stats.json", "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)

    print("\n=== dataset_stats.json ===")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    print(f"\nWrote train/val/test/adversarial CSVs to {args.out}/")


if __name__ == "__main__":
    main()
