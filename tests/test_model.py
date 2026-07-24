"""Tests for the UniPhish Keras model (requires TensorFlow)."""

import numpy as np
import pytest

tf = pytest.importorskip("tensorflow")

from uniphish.encoding import MAX_LEN
from uniphish.model import build_model, count_parameters


def test_output_shape_and_range():
    m = build_model()
    x = np.zeros((4, MAX_LEN), dtype=np.int32)
    y = m(x, training=False).numpy()
    assert y.shape == (4, 1)
    assert (y >= 0).all() and (y <= 1).all()


def test_parameter_count_is_stable():
    # The architecture as *described* yields ~378K params (not the paper's 847,425
    # headline). We lock in the real number so regressions are caught.
    m = build_model()
    n = count_parameters(m)
    assert 370_000 < n < 385_000, f"unexpected param count {n:,}"


def test_five_branches_present():
    m = build_model()
    conv_layers = [l for l in m.layers if l.name.startswith("conv_k")]
    assert len(conv_layers) == 5
