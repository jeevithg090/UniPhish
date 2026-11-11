"""Compress a trained UniPhish model for on-device deployment (paper Section VII).

The full model is already tiny (~1.5 MB / 377,985 params), so the goal here is
portability + speed, not desperate size reduction: convert to a quantized TFLite
artifact that runs anywhere without a version-matched Keras, and is faster on
ARM CPUs via int8 weights.

    python -m uniphish.compress --weights artifacts/uniphish_adv.keras \
        --out artifacts/uniphish.tflite

Optional (needs training data + GPU, run on Kaggle): knowledge distillation to a
smaller student before quantization — see `distill_student`.
"""

from __future__ import annotations

import argparse
import os

import numpy as np

from uniphish.encoding import MAX_LEN, encode_batch
from uniphish.model import build_model


def load_weights_into_fresh(weights_path: str, **model_kw):
    """Rebuild the architecture and load weights — robust across Keras versions
    (a saved .keras from a newer Keras may not `load_model` on an older one)."""
    model = build_model(**model_kw)
    model.load_weights(weights_path)
    return model


def _representative_dataset(urls, max_len=MAX_LEN, n=300):
    X = encode_batch(list(urls)[:n], max_len).astype(np.int32)

    def gen():
        for i in range(len(X)):
            yield [X[i : i + 1]]

    return gen


def to_tflite(model, out_path: str, representative_urls=None, int8: bool = False) -> int:
    """Convert a Keras model to a (quantized) TFLite flatbuffer. Returns byte size.

    Default is dynamic-range int8 weight quantization (robust for embedding-input
    models, ~4x smaller weights, no calibration data needed). `int8=True` attempts
    full-integer quantization with a representative dataset, falling back to
    dynamic-range if the converter rejects the integer-index input.
    """
    import tensorflow as tf

    conv = tf.lite.TFLiteConverter.from_keras_model(model)
    conv.optimizations = [tf.lite.Optimize.DEFAULT]
    if int8 and representative_urls is not None:
        conv.representative_dataset = _representative_dataset(representative_urls)
    try:
        tfl = conv.convert()
    except Exception as e:  # full-int8 can reject int32 embedding indices
        print(f"[compress] int8 path failed ({e}); using dynamic-range quantization")
        conv = tf.lite.TFLiteConverter.from_keras_model(model)
        conv.optimizations = [tf.lite.Optimize.DEFAULT]
        tfl = conv.convert()

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(tfl)
    return len(tfl)


def distill_student(teacher, train_urls, y, out_path, temperature=4.0, alpha=0.3,
                    filters=64, epochs=10, batch=512):
    """Knowledge distillation into a smaller student (optional; needs data + GPU).

    Student = same byte-CNN with fewer filters. Loss = alpha*CE(hard) +
    (1-alpha)*T^2*KL(teacher_soft || student_soft). Returns the student model.
    """
    import tensorflow as tf
    from tensorflow import keras

    student = build_model(filters=filters, name="uniphish_student")
    X = encode_batch(train_urls)
    teacher_p = teacher.predict(X, verbose=0).ravel()
    opt = keras.optimizers.Adam(3e-4)
    bce = keras.losses.BinaryCrossentropy()
    ds = tf.data.Dataset.from_tensor_slices((X, y.astype("float32"), teacher_p.astype("float32")))
    ds = ds.shuffle(20000).batch(batch)

    for ep in range(epochs):
        for xb, yb, tb in ds:
            with tf.GradientTape() as tape:
                sp = tf.squeeze(student(xb, training=True), -1)
                hard = bce(yb, sp)
                # soft targets via logit temperature (approx on probabilities)
                soft = keras.losses.KLD(tf.clip_by_value(tb, 1e-6, 1 - 1e-6),
                                        tf.clip_by_value(sp, 1e-6, 1 - 1e-6))
                loss = alpha * hard + (1 - alpha) * (temperature ** 2) * soft
            grads = tape.gradient(loss, student.trainable_variables)
            opt.apply_gradients(zip(grads, student.trainable_variables))
        print(f"[distill] epoch {ep+1}/{epochs} loss={float(loss):.4f}")
    student.save(out_path)
    return student


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="artifacts/uniphish_adv.keras")
    ap.add_argument("--out", default="artifacts/uniphish.tflite")
    ap.add_argument("--int8", action="store_true", help="attempt full-integer quantization")
    args = ap.parse_args()

    model = load_weights_into_fresh(args.weights)
    rep = None
    if args.int8:
        from data.synth import SynthConfig, synthesize
        rep = [r["url"] for r in synthesize(SynthConfig(per_family=60))]
    size = to_tflite(model, args.out, representative_urls=rep, int8=args.int8)
    print(f"wrote {args.out}  ({size/1e6:.2f} MB)")


if __name__ == "__main__":
    main()
