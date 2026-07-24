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


class BaseCheckpoint(keras.callbacks.Callback):
    """Persist the base functional model every epoch so a session timeout (free
    GPU tiers) never loses the run. Saves `checkpoint.keras` (latest, for resume),
    `best.keras` (best `monitor`), and `train_state.json` (epoch + best score).
    """

    def __init__(self, base: keras.Model, out: str, monitor: str = "val_macro_f1"):
        super().__init__()
        self.base, self.out, self.monitor = base, out, monitor
        self.best = -np.inf
        self.state_path = os.path.join(out, "train_state.json")
        if os.path.exists(self.state_path):
            try:
                self.best = load_config_json(self.state_path).get("best", -np.inf)
            except Exception:
                pass

    def on_epoch_end(self, epoch, logs=None):
        logs = logs or {}
        self.base.save(os.path.join(self.out, "checkpoint.keras"))
        score = logs.get(self.monitor, -np.inf)
        if score > self.best:
            self.best = score
            self.base.save(os.path.join(self.out, "best.keras"))
        save_json({"epoch": int(epoch) + 1, "best": float(self.best),
                   "monitor": self.monitor}, self.state_path)


def load_config_json(path):
    from uniphish.utils import load_json
    return load_json(path)


def train(cfg: dict, data_dir: str, out: str, epochs: int | None,
          adversarial: bool, seed: int, resume: bool = False) -> dict:
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

    initial_epoch = 0
    ckpt = f"{out}/checkpoint.keras"
    if resume and os.path.exists(ckpt):
        base.set_weights(keras.models.load_model(ckpt).get_weights())
        if os.path.exists(f"{out}/train_state.json"):
            initial_epoch = load_config_json(f"{out}/train_state.json").get("epoch", 0)
        print(f"resumed from {ckpt} at epoch {initial_epoch}")

    t = cfg["train"]
    max_epochs = epochs or t["max_epochs"]
    steps = max(1, len(train_s) // t["batch_size"])
    lr = keras.optimizers.schedules.CosineDecay(
        t["learning_rate"], decay_steps=steps * max_epochs, alpha=t["lr_min"] / t["learning_rate"])
    opt = keras.optimizers.Adam(lr, beta_1=t["beta_1"], beta_2=t["beta_2"])

    cbs = [
        MacroF1Callback(val_s, base),
        BaseCheckpoint(base, out, monitor="val_macro_f1"),
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
                              epochs=max_epochs, initial_epoch=initial_epoch,
                              callbacks=cbs, verbose=2)
    else:
        compile_model(base, learning_rate=t["learning_rate"])
        base.optimizer = opt
        history = base.fit(train_s.X, train_s.y, validation_data=(val_s.X, val_s.y),
                           batch_size=t["batch_size"], epochs=max_epochs,
                           initial_epoch=initial_epoch, callbacks=cbs, verbose=2)

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
    ap.add_argument("--resume", action="store_true", help="resume from checkpoint.keras if present")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cfg = load_config(args.config)
    train(cfg, args.data_dir, args.out, args.epochs,
          adversarial=not args.no_adv, seed=args.seed, resume=args.resume)


if __name__ == "__main__":
    main()
