"""Train UniPhish (standard or adversarial min-max) — Sections IV & V.

Examples:
  python -m uniphish.train --data-dir data/processed --out artifacts --epochs 3
  python -m uniphish.train --no-adv                       # ablation: no adv training
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import tensorflow as tf
from sklearn.metrics import f1_score
from tensorflow import keras

from uniphish.adversarial import MinMaxTrainer
from uniphish.dataset import load_split, make_adversarial_X, Split
from uniphish.model import build_model, compile_model, count_parameters
from uniphish.utils import load_config, save_json, set_seed


class MacroF1Callback(keras.callbacks.Callback):
    """Log `val_macro_f1` = mean per-script-family F1 on the validation split."""

    def __init__(self, val: Split, base_model: keras.Model):
        super().__init__()
        self.val = val
        self.base = base_model

    def on_epoch_end(self, epoch, logs=None):
        logs = logs or {}
        p = self.base.predict(self.val.X, verbose=0).ravel()
        pred = (p >= 0.5).astype(int)
        f1s = []
        for fam in np.unique(self.val.families):
            m = self.val.families == fam
            if m.sum() and len(np.unique(self.val.y[m])) > 1:
                f1s.append(f1_score(self.val.y[m].astype(int), pred[m]))
        macro = float(np.mean(f1s)) if f1s else f1_score(self.val.y.astype(int), pred)
        logs["val_macro_f1"] = macro
        print(f"  — val_macro_f1: {macro:.4f}")


def train(cfg: dict, data_dir: str, out: str, epochs: int | None,
          adversarial: bool, seed: int) -> dict:
    set_seed(seed)
    os.makedirs(out, exist_ok=True)

    train_s = load_split(f"{data_dir}/train.csv", cfg["model"]["max_len"])
    val_s = load_split(f"{data_dir}/val.csv", cfg["model"]["max_len"])
    print(f"train={len(train_s)}  val={len(val_s)}  adversarial={adversarial}")

    m = cfg["model"]
    base = build_model(max_len=m["max_len"], vocab_size=m["vocab_size"],
                       embed_dim=m["embed_dim"], kernels=tuple(m["kernels"]),
                       filters=m["filters"], spatial_dropout=m["spatial_dropout"],
                       fc1_units=m["fc1_units"], fc2_units=m["fc2_units"],
                       fc_dropout=m["fc_dropout"])
    print(f"model parameters: {count_parameters(base):,}")

    t = cfg["train"]
    max_epochs = epochs or t["max_epochs"]
    steps = max(1, len(train_s) // t["batch_size"])
    lr = keras.optimizers.schedules.CosineDecay(
        t["learning_rate"], decay_steps=steps * max_epochs, alpha=t["lr_min"] / t["learning_rate"])
    opt = keras.optimizers.Adam(lr, beta_1=t["beta_1"], beta_2=t["beta_2"])

    cbs = [
        MacroF1Callback(val_s, base),
        keras.callbacks.EarlyStopping(monitor="val_macro_f1", mode="max",
                                       patience=t["early_stop_patience"],
                                       restore_best_weights=True),
    ]

    if adversarial:
        a = cfg["adversarial"]
        X_adv = make_adversarial_X(train_s.urls, a["sub_rate"], m["max_len"], seed)
        trainer = MinMaxTrainer(base, adv_lambda=a["lambda"])
        trainer.compile(optimizer=opt)
        ds = tf.data.Dataset.from_tensor_slices(
            ((train_s.X, X_adv), train_s.y)).shuffle(50000, seed=seed).batch(t["batch_size"]).prefetch(tf.data.AUTOTUNE)
        history = trainer.fit(ds, validation_data=(val_s.X, val_s.y),
                              epochs=max_epochs, callbacks=cbs, verbose=2)
    else:
        compile_model(base, learning_rate=t["learning_rate"])
        base.optimizer = opt
        history = base.fit(train_s.X, train_s.y, validation_data=(val_s.X, val_s.y),
                           batch_size=t["batch_size"], epochs=max_epochs,
                           callbacks=cbs, verbose=2)

    model_path = f"{out}/uniphish{'_adv' if adversarial else ''}.keras"
    base.save(model_path)
    hist = {k: [float(v) for v in vals] for k, vals in history.history.items()}
    save_json(hist, f"{out}/history{'_adv' if adversarial else ''}.json")
    print(f"\nSaved model -> {model_path}")
    return hist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--out", default="artifacts")
    ap.add_argument("--epochs", type=int, default=None)
    ap.add_argument("--no-adv", action="store_true", help="disable adversarial training")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cfg = load_config(args.config)
    train(cfg, args.data_dir, args.out, args.epochs,
          adversarial=not args.no_adv, seed=args.seed)


if __name__ == "__main__":
    main()
