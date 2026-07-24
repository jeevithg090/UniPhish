"""Inference wrapper — scores a URL and maps it to a risk tier (Section VIII).

Supports both the full Keras model and the quantized .tflite artifact.

  from uniphish.infer import UniPhishScorer
  scorer = UniPhishScorer("artifacts/uniphish_adv.keras")
  scorer.scan("http://paypa1.xyz/login")   # -> {"prob":0.97,"tier":"block", ...}
"""

from __future__ import annotations

import argparse
from typing import Dict, List

import numpy as np

from uniphish.encoding import encode_batch


class UniPhishScorer:
    def __init__(self, model_path: str, warn: float = 0.5, block: float = 0.9):
        self.warn, self.block = warn, block
        self.is_tflite = model_path.endswith(".tflite")
        if self.is_tflite:
            import tensorflow as tf
            self.interp = tf.lite.Interpreter(model_path=model_path)
            self.interp.allocate_tensors()
            self.in_idx = self.interp.get_input_details()[0]["index"]
            self.out_idx = self.interp.get_output_details()[0]["index"]
        else:
            from tensorflow import keras
            self.model = keras.models.load_model(model_path)

    def _predict(self, X: np.ndarray) -> np.ndarray:
        if self.is_tflite:
            probs = []
            for row in X:
                self.interp.set_tensor(self.in_idx, row[None, :].astype(np.int32))
                self.interp.invoke()
                probs.append(float(self.interp.get_tensor(self.out_idx).ravel()[0]))
            return np.array(probs)
        return self.model.predict(X, verbose=0).ravel()

    def tier(self, p: float) -> str:
        if p >= self.block:
            return "block"
        if p >= self.warn:
            return "warn"
        return "safe"

    def scan(self, url: str) -> Dict:
        return self.scan_batch([url])[0]

    def scan_batch(self, urls: List[str]) -> List[Dict]:
        probs = self._predict(encode_batch(list(urls)))
        return [{"url": u, "prob": round(float(p), 4), "tier": self.tier(float(p))}
                for u, p in zip(urls, probs)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="+")
    ap.add_argument("--model", default="artifacts/uniphish_adv.keras")
    args = ap.parse_args()
    scorer = UniPhishScorer(args.model)
    for r in scorer.scan_batch(args.urls):
        print(f"{r['tier']:5s}  p={r['prob']:.4f}  {r['url']}")


if __name__ == "__main__":
    main()
