"""Generate publication-style figures from the recorded results JSONs.

Reads whatever exists under results/ and writes PNGs to reports/ — a visual
summary for the README / portfolio. Skips any figure whose source JSON is absent.

    python -m scripts.make_report
"""

from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = "results"
OUT = "reports"


def _load(name):
    p = os.path.join(R, name)
    return json.load(open(p)) if os.path.exists(p) else None


def comparison_fig(d):
    fams = d["families"]
    models = list(d["models"])
    x = range(len(fams))
    fig, ax = plt.subplots(figsize=(9, 4.5))
    w = 0.8 / len(models)
    for i, m in enumerate(models):
        vals = [d["models"][m]["by_family"].get(f, 0) for f in fams]
        ax.bar([xi + i * w for xi in x], vals, w, label=m)
    ax.set_xticks([xi + 0.4 - w / 2 for xi in x])
    ax.set_xticklabels([f[:8] for f in fams], rotation=20)
    ax.set_ylim(0.9, 1.001); ax.set_ylabel("F1")
    ax.set_title("Per-script-family F1 by model (honest: all tie on realistic data)")
    ax.legend(fontsize=8, ncol=len(models))
    fig.tight_layout(); fig.savefig(f"{OUT}/comparison.png", dpi=140); plt.close(fig)


def adversarial_fig(d):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for m, e in d["models"].items():
        adv = e.get("adversarial", {})
        rates = sorted(adv, key=lambda s: int(s.strip("%")))
        ax.plot([int(r.strip("%")) for r in rates], [adv[r] for r in rates], marker="o", label=m)
    ax.set_xlabel("homoglyph substitution rate (%)"); ax.set_ylabel("accuracy")
    ax.set_title("Adversarial robustness"); ax.legend(fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(f"{OUT}/adversarial.png", dpi=140); plt.close(fig)


def redteam_fig(d):
    atk = d["attacks"]
    names = sorted(atk, key=lambda n: -atk[n]["evasion"])
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(names, [atk[n]["evasion"] * 100 for n in names], color="#ef4444", label="model evasion %")
    ax.plot(names, [(1 - atk[n]["fused_detection"]) * 100 for n in names], "o-",
            color="#334155", label="miss after fused rules %")
    ax.set_ylabel("%"); ax.set_title("Red-team: evasion vs rules-layer recovery")
    ax.set_xticklabels(names, rotation=25, ha="right"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(f"{OUT}/redteam.png", dpi=140); plt.close(fig)


def latency_fig(d):
    models = d["models"]
    names = list(models)
    fig, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.bar(names, [models[m]["size_mb"] for m in names], color="#93c5fd", label="size (MB)")
    ax1.set_ylabel("size (MB)")
    ax2 = ax1.twinx()
    ax2.plot(names, [models[m]["latency_ms"] for m in names], "D-", color="#dc2626", label="latency (ms)")
    ax2.set_ylabel("latency (ms/URL)")
    ax1.set_title("Model size vs CPU latency")
    fig.tight_layout(); fig.savefig(f"{OUT}/latency.png", dpi=140); plt.close(fig)


def main():
    os.makedirs(OUT, exist_ok=True)
    made = []
    for name, fn, src in [("comparison", comparison_fig, "comparison.json"),
                          ("adversarial", adversarial_fig, "comparison.json"),
                          ("redteam", redteam_fig, "robustness.json"),
                          ("latency", latency_fig, "latency.json")]:
        d = _load(src)
        if d:
            try:
                fn(d); made.append(f"{OUT}/{name}.png")
            except Exception as e:
                print(f"[skip {name}] {e}")
    print("wrote:", *made, sep="\n  ") if made else print("no results JSONs found")


if __name__ == "__main__":
    main()
