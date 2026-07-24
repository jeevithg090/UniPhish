"""Adversarial (min-max) training wrapper — Eq. (15) of the paper.

L_total = mean[ CE(f(u), y) + lambda * CE(f(u'), y) ]

where u' is the homoglyph-substituted variant of u. Substitution is a discrete,
non-differentiable augmentation, so u' is generated on the data side and both the
clean and adversarial byte tensors are fed to a custom `train_step`.
"""

from __future__ import annotations

import tensorflow as tf
from tensorflow import keras


class MinMaxTrainer(keras.Model):
    """Wraps a base UniPhish model and trains it with the clean+adversarial loss.

    Expects training data as ((x_clean, x_adv), y). For validation/inference it
    delegates to the base model on a single input.
    """

    def __init__(self, base: keras.Model, adv_lambda: float = 0.4, **kw):
        super().__init__(**kw)
        self.base = base
        self.adv_lambda = adv_lambda
        self.bce = keras.losses.BinaryCrossentropy()
        self.loss_tracker = keras.metrics.Mean(name="loss")
        self.clean_loss = keras.metrics.Mean(name="clean_loss")
        self.adv_loss = keras.metrics.Mean(name="adv_loss")
        self.acc = keras.metrics.BinaryAccuracy(name="acc")

    def call(self, inputs, training=False):
        return self.base(inputs, training=training)

    @property
    def metrics(self):
        return [self.loss_tracker, self.clean_loss, self.adv_loss, self.acc]

    def train_step(self, data):
        (x_clean, x_adv), y = data
        with tf.GradientTape() as tape:
            p_clean = self.base(x_clean, training=True)
            p_adv = self.base(x_adv, training=True)
            l_clean = self.bce(y, p_clean)
            l_adv = self.bce(y, p_adv)
            loss = l_clean + self.adv_lambda * l_adv
        grads = tape.gradient(loss, self.base.trainable_variables)
        self.optimizer.apply_gradients(zip(grads, self.base.trainable_variables))
        self.loss_tracker.update_state(loss)
        self.clean_loss.update_state(l_clean)
        self.adv_loss.update_state(l_adv)
        self.acc.update_state(y, p_clean)
        return {m.name: m.result() for m in self.metrics}

    def test_step(self, data):
        x, y = data
        p = self.base(x, training=False)
        self.acc.update_state(y, p)
        self.loss_tracker.update_state(self.bce(y, p))
        return {"loss": self.loss_tracker.result(), "acc": self.acc.result()}
