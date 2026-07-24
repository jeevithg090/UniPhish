"""UniPhish model architecture (Section IV-C of the paper).

Byte embedding (256x64) -> SpatialDropout1D -> five parallel Conv1D branches
with kernels {2,3,4,5,6} x 128 filters -> GlobalMaxPool per branch -> concat(640)
-> Dense(256) -> Dropout -> Dense(128) -> Dropout -> Dense(1, sigmoid).

Note on parameter count: the paper's Table III reports 847,425 total trainable
parameters, but the sum of the component counts it describes (embedding 16,384 +
conv ~164,480 + FC1 164,096 + FC2 32,896 + output 129) is ~377,985. `build_model`
prints the *real* count so the discrepancy is visible and reproducible; see
`count_parameters()` and the README "Paper vs. reality" section.
"""

from __future__ import annotations

from typing import Sequence

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from uniphish.encoding import MAX_LEN, VOCAB_SIZE


def build_model(
    max_len: int = MAX_LEN,
    vocab_size: int = VOCAB_SIZE,
    embed_dim: int = 64,
    kernels: Sequence[int] = (2, 3, 4, 5, 6),
    filters: int = 128,
    spatial_dropout: float = 0.20,
    fc1_units: int = 256,
    fc2_units: int = 128,
    fc_dropout: float = 0.30,
    name: str = "uniphish",
) -> keras.Model:
    """Build the UniPhish parallel multi-kernel 1D-CNN.

    Returns an uncompiled Keras functional model producing a single sigmoid
    phishing probability in [0, 1].
    """
    inp = keras.Input(shape=(max_len,), dtype="int32", name="byte_ids")

    # Stage 1 — byte embedding (no [UNK]: every byte value has a learned vector)
    x = layers.Embedding(
        input_dim=vocab_size,
        output_dim=embed_dim,
        embeddings_initializer=keras.initializers.RandomUniform(-0.05, 0.05),
        name="byte_embedding",
    )(inp)

    # Stage 2 — SpatialDropout1D before convolution (channel-wise dropout)
    x = layers.SpatialDropout1D(spatial_dropout, name="spatial_dropout")(x)

    # Stage 3+4 — parallel multi-kernel conv branches + max-over-time pooling
    branches = []
    for k in kernels:
        b = layers.Conv1D(
            filters=filters,
            kernel_size=k,
            activation="relu",
            padding="valid",
            name=f"conv_k{k}",
        )(x)
        b = layers.GlobalMaxPooling1D(name=f"pool_k{k}")(b)
        branches.append(b)
    z = layers.Concatenate(name="concat")(branches) if len(branches) > 1 else branches[0]

    # Stage 5 — classification head
    h = layers.Dense(fc1_units, activation="relu", name="fc1")(z)
    h = layers.Dropout(fc_dropout, name="drop1")(h)
    h = layers.Dense(fc2_units, activation="relu", name="fc2")(h)
    h = layers.Dropout(fc_dropout, name="drop2")(h)
    out = layers.Dense(1, activation="sigmoid", name="phish_prob")(h)

    return keras.Model(inp, out, name=name)


def count_parameters(model: keras.Model) -> int:
    """Total trainable parameter count."""
    return int(sum(tf.size(w).numpy() for w in model.trainable_weights))


def compile_model(model: keras.Model, learning_rate: float = 3e-4,
                  beta_1: float = 0.9, beta_2: float = 0.999) -> keras.Model:
    """Compile with Adam + binary cross-entropy (used for non-adversarial training)."""
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate, beta_1=beta_1, beta_2=beta_2),
        loss="binary_crossentropy",
        metrics=[keras.metrics.BinaryAccuracy(name="acc"),
                 keras.metrics.AUC(name="auc")],
    )
    return model


if __name__ == "__main__":
    m = build_model()
    m.summary()
    print(f"\nTotal trainable parameters: {count_parameters(m):,}")
    print("Paper's Table III claims:   847,425")
