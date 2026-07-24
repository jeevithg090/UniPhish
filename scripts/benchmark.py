"""Measure real model size + CPU inference latency (paper Table VII, honestly).

Reports for the full Keras model and the TFLite artifact:
  - on-disk size (MB)
  - single-URL latency (ms), median over N calls, warm-up discarded

    python -m scripts.benchmark --weights artifacts/uniphish_adv.keras \
        --tflite artifacts/uniphish.tflite
"""

from __future__ import annotations

import argparse
import os
import time

import numpy as np

from uniphish.compress import load_weights_into_fresh
from uniphish.encoding import encode_batch
from uniphish.utils import save_json

SAMPLE_URLS = [
    "https://www.sbi.co.in/",
    "https://paypa1.xyz/login",
    "https://аpple.com/verify",
    "https://alrajhi-secure-login.top/signin",
    "https://नमस्ते-bank-verify.top/login",
]


def _mb(path: str) -> float:
    return os.path.getsize(path) / 1e6


def bench_keras(model, n=1000, warmup=100) -> float:
    X = encode_batch([SAMPLE_URLS[0]])
    for _ in range(warmup):
        model(X, training=False)
    times = []
    for i in range(n):
        x = encode_batch([SAMPLE_URLS[i % len(SAMPLE_URLS)]])
        t = time.perf_counter()
        model(x, training=False)
        times.append((time.perf_counter() - t) * 1000)
    return float(np.median(times))


def bench_tflite(path: str, n=1000, warmup=100) -> float:
    import tensorflow as tf

    interp = tf.lite.Interpreter(model_path=path, num_threads=1)
    interp.allocate_tensors()
    ii = interp.get_input_details()[0]["index"]
    oo = interp.get_output_details()[0]["index"]
    xs = [encode_batch([u]).astype(np.int32) for u in SAMPLE_URLS]
    for _ in range(warmup):
        interp.set_tensor(ii, xs[0]); interp.invoke(); interp.get_tensor(oo)
    times = []
    for i in range(n):
        x = xs[i % len(xs)]
        t = time.perf_counter()
        interp.set_tensor(ii, x); interp.invoke(); interp.get_tensor(oo)
        times.append((time.perf_counter() - t) * 1000)
    return float(np.median(times))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--tflite", default="artifacts/uniphish.tflite")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", default="results/latency.json")
    args = ap.parse_args()

    results = {"cpu": os.environ.get("HOSTNAME", "local"), "n": args.n, "models": {}}

    model = load_weights_into_fresh(args.weights)
    results["models"]["keras_full"] = {
        "size_mb": round(_mb(args.weights), 3),
        "latency_ms": round(bench_keras(model, args.n), 4),
    }
    print(f"keras_full : {results['models']['keras_full']['size_mb']} MB  "
          f"{results['models']['keras_full']['latency_ms']} ms/URL")

    if os.path.exists(args.tflite):
        results["models"]["tflite"] = {
            "size_mb": round(_mb(args.tflite), 3),
            "latency_ms": round(bench_tflite(args.tflite, args.n), 4),
        }
        print(f"tflite     : {results['models']['tflite']['size_mb']} MB  "
              f"{results['models']['tflite']['latency_ms']} ms/URL")

    save_json(results, args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
