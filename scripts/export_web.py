"""Export the trained model to a compact binary for zero-dependency in-browser
inference (Track C). Dumps a Float32 weights blob + a JSON manifest that
`extension/model.js` reads — so the extension can score URLs fully on-device,
with no server and no ML library.

    python -m scripts.export_web --weights artifacts/uniphish_adv.keras
"""

from __future__ import annotations

import argparse
import json
import os

import numpy as np

from uniphish.compress import load_weights_into_fresh


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--out", default="extension/model")
    args = ap.parse_args()

    m = load_weights_into_fresh(args.weights)
    os.makedirs(args.out, exist_ok=True)

    kernels = [2, 3, 4, 5, 6]
    manifest = {"maxLen": 600, "embedDim": 64, "vocab": 256, "kernels": kernels,
                "filters": 128, "fc": [256, 128], "tensors": []}
    blobs, offset = [], 0

    def add(name, arr):
        nonlocal offset
        a = np.ascontiguousarray(arr, dtype="<f4").ravel(order="C")
        manifest["tensors"].append({"name": name, "shape": list(arr.shape),
                                    "offset": offset, "size": int(a.size)})
        blobs.append(a)
        offset += a.size

    add("emb", m.get_layer("byte_embedding").get_weights()[0])   # (256, 64)
    for k in kernels:
        w, b = m.get_layer(f"conv_k{k}").get_weights()           # (k,64,128),(128,)
        add(f"conv{k}_w", w); add(f"conv{k}_b", b)
    for name in ["fc1", "fc2", "phish_prob"]:
        w, b = m.get_layer(name).get_weights()
        add(f"{name}_w", w); add(f"{name}_b", b)

    data = np.concatenate(blobs).astype("<f4")
    data.tofile(f"{args.out}/weights.bin")
    with open(f"{args.out}/manifest.json", "w") as fh:
        json.dump(manifest, fh)
    print(f"wrote {args.out}/weights.bin ({data.nbytes/1e6:.2f} MB) + manifest.json "
          f"({len(manifest['tensors'])} tensors)")


if __name__ == "__main__":
    main()
