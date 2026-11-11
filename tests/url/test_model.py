"""Unit tests for the TF-free byte-level CNN runtime and occlusion saliency.

Offline and fast: the model is pure NumPy over a packaged weight blob; no network, no
TensorFlow. Cross-runtime numerical parity against the JS reference lives in
``test_model_parity.py``.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from uniphish.url import model as model_mod
from uniphish.url.model import (
    MAX_LEN,
    PARAM_COUNT,
    ModelUnavailable,
    UrlModel,
    get_model,
)
from uniphish.url.saliency import (
    CharSaliency,
    SalientSpan,
    occlusion_saliency,
    top_spans,
)

# A blatant-looking phishing URL and a plainly benign one. These verdicts come straight
# from the trained weights (see the parity oracle), so they are stable, not aspirational.
PHISH = "http://paypal.com.secure-login.example/verify"
BENIGN = "https://example.com/"


@pytest.fixture(scope="module")
def m() -> UrlModel:
    return get_model()


# --------------------------------------------------------------------------- #
# Loading / metadata
# --------------------------------------------------------------------------- #
def test_param_count_matches_paper_reproduction(m: UrlModel) -> None:
    assert m.param_count == PARAM_COUNT == 377_985


def test_info_reports_provenance_and_caveats(m: UrlModel) -> None:
    info = m.info()
    assert info["param_count"] == 377_985
    assert info["runtime"]["param_count"] == 377_985
    assert info["runtime"]["max_len"] == MAX_LEN
    assert info["runtime"]["kernels"] == [2, 3, 4, 5, 6]
    # provenance file is shipped and merged in
    assert info["metrics"]["in_distribution_macro_f1"] == pytest.approx(0.9991)
    assert any("fused" in c.lower() for c in info["caveats"]), "honest fusion caveat expected"


def test_get_model_is_a_thread_safe_singleton() -> None:
    assert get_model() is get_model()


# --------------------------------------------------------------------------- #
# Prediction contract
# --------------------------------------------------------------------------- #
def test_predict_shapes_dtype_and_range(m: UrlModel) -> None:
    urls = [BENIGN, PHISH, "a.co", "http://192.168.0.1/login"]
    probs = m.predict(urls)
    assert probs.shape == (4,)
    assert probs.dtype == np.float32
    assert np.all((probs >= 0.0) & (probs <= 1.0))


def test_predict_one_returns_python_float(m: UrlModel) -> None:
    p = m.predict_one(BENIGN)
    assert isinstance(p, float)
    assert 0.0 <= p <= 1.0


def test_empty_input_returns_empty_array(m: UrlModel) -> None:
    out = m.predict([])
    assert out.shape == (0,)
    assert out.dtype == np.float32
    assert m.logits([]).shape == (0,)


def test_phishing_scores_above_benign(m: UrlModel) -> None:
    assert m.predict_one(PHISH) > 0.5
    assert m.predict_one(BENIGN) < 0.5
    assert m.predict_one(PHISH) > m.predict_one(BENIGN)


def test_determinism(m: UrlModel) -> None:
    a = m.predict([PHISH, BENIGN])
    b = m.predict([PHISH, BENIGN])
    np.testing.assert_array_equal(a, b)


def test_batching_matches_single(m: UrlModel) -> None:
    urls = [BENIGN, PHISH, "https://пример.example/вход", "a.co", "http://0xC0A80001/"]
    batched = m.predict(urls)
    singles = np.array([m.predict_one(u) for u in urls], dtype=np.float32)
    np.testing.assert_allclose(batched, singles, atol=1e-6)


def test_batching_spans_internal_chunk_boundary(m: UrlModel) -> None:
    # More URLs than the internal chunk size, to exercise concatenation across chunks.
    urls = [f"http://host{i}.example/login?id={i}" for i in range(model_mod._CHUNK + 17)]
    batched = m.predict(urls)
    assert batched.shape == (len(urls),)
    # chunk-split must equal a single whole-batch pass
    first = m.predict(urls[:10])
    np.testing.assert_allclose(batched[:10], first, atol=0)


def test_logits_and_probs_are_consistent(m: UrlModel) -> None:
    urls = [BENIGN, PHISH, "a.co"]
    logits = m.logits(urls)
    probs = m.predict(urls)
    assert logits.dtype == np.float32
    expected = 1.0 / (1.0 + np.exp(-logits.astype(np.float64)))  # T=1
    np.testing.assert_allclose(probs.astype(np.float64), expected, atol=1e-6)


# --------------------------------------------------------------------------- #
# Encoding (truncation / padding)
# --------------------------------------------------------------------------- #
def test_encode_pads_short_and_truncates_long(m: UrlModel) -> None:
    seq = m.encode(["ab", "x" * 5000])
    assert seq.shape == (2, MAX_LEN)
    assert seq.dtype == np.uint8
    assert list(seq[0, :2]) == [ord("a"), ord("b")]
    assert np.all(seq[0, 2:] == 0)                 # zero-padded
    assert np.all(seq[1] == ord("x"))              # truncated to 600, no padding


def test_multibyte_encoding_matches_utf8(m: UrlModel) -> None:
    url = "https://пример.example/"              # Cyrillic (2 bytes/char)
    seq = m.encode([url])[0]
    raw = url.encode("utf-8")[:MAX_LEN]
    assert list(seq[: len(raw)]) == list(raw)


def test_predict_seq_matches_predict(m: UrlModel) -> None:
    urls = [PHISH, BENIGN]
    seq = m.encode(urls)
    np.testing.assert_array_equal(m.predict_seq(seq), m.predict(urls))


def test_predict_seq_rejects_wrong_width(m: UrlModel) -> None:
    with pytest.raises(ValueError):
        m.predict_seq(np.zeros((1, MAX_LEN - 1), dtype=np.uint8))


# --------------------------------------------------------------------------- #
# Temperature calibration
# --------------------------------------------------------------------------- #
def test_temperature_softens_but_preserves_ranking() -> None:
    hot = UrlModel()                                 # T = 1
    cool = UrlModel(temperature=4.0)
    urls = [BENIGN, PHISH, "a.co", "http://login.example.test/verify"]
    # logits are temperature-independent
    np.testing.assert_allclose(hot.logits(urls), cool.logits(urls), atol=0)
    hp, cp = hot.predict(urls), cool.predict(urls)
    # a high temperature pulls every probability toward 0.5
    assert np.all(np.abs(cp - 0.5) <= np.abs(hp - 0.5) + 1e-6)
    # ...without reordering
    assert list(np.argsort(hp)) == list(np.argsort(cp))


def test_invalid_temperature_rejected() -> None:
    with pytest.raises(ValueError):
        UrlModel(temperature=0.0)


# --------------------------------------------------------------------------- #
# Asset validation / graceful failure
# --------------------------------------------------------------------------- #
def test_missing_weights_raise_model_unavailable(tmp_path, m: UrlModel) -> None:
    good_manifest = tmp_path / "manifest.json"
    good_manifest.write_text(json.dumps(m.manifest))
    with pytest.raises(ModelUnavailable):
        UrlModel(manifest_path=good_manifest, weights_path=tmp_path / "nope.bin")


def test_missing_manifest_raises_model_unavailable(tmp_path) -> None:
    with pytest.raises(ModelUnavailable):
        UrlModel(manifest_path=tmp_path / "nope.json")


def test_truncated_weights_detected(tmp_path, m: UrlModel) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(m.manifest))
    weights = tmp_path / "weights.bin"
    weights.write_bytes(np.zeros(PARAM_COUNT - 1, dtype="<f4").tobytes())  # one short
    with pytest.raises(ModelUnavailable, match="size mismatch"):
        UrlModel(manifest_path=manifest, weights_path=weights)


def test_nonfinite_weights_detected(tmp_path, m: UrlModel) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(m.manifest))
    bad = np.zeros(PARAM_COUNT, dtype="<f4")
    bad[0] = np.inf
    weights = tmp_path / "weights.bin"
    weights.write_bytes(bad.tobytes())
    with pytest.raises(ModelUnavailable):
        UrlModel(manifest_path=manifest, weights_path=weights)


# --------------------------------------------------------------------------- #
# Occlusion saliency
# --------------------------------------------------------------------------- #
def test_saliency_one_entry_per_char(m: UrlModel) -> None:
    url = "http://paypal.example/login"
    sal = occlusion_saliency(url, m)
    assert [s.char for s in sal] == list(url)
    assert all(isinstance(s, CharSaliency) for s in sal)
    assert all(np.isfinite(s.delta) for s in sal)


def test_saliency_empty_url(m: UrlModel) -> None:
    assert occlusion_saliency("", m) == []
    assert top_spans("", 5, m) == []


def test_saliency_byte_offsets_are_multibyte_aware(m: UrlModel) -> None:
    url = "http://пример.example/"              # Cyrillic chars are 2 bytes each
    sal = occlusion_saliency(url, m)
    # offsets are contiguous and match cumulative UTF-8 lengths
    pos = 0
    for s in sal:
        assert s.start_byte == pos
        assert s.end_byte == pos + len(s.char.encode("utf-8"))
        pos = s.end_byte
    # a Cyrillic char really does span two bytes
    assert any(s.end_byte - s.start_byte == 2 for s in sal)


def test_occlusion_saliency_default_space_is_probability(m: UrlModel) -> None:
    sal = occlusion_saliency("http://login.example.test/verify", m)
    assert all(s.space == "prob" for s in sal)


def test_occlusion_saliency_rejects_bad_space(m: UrlModel) -> None:
    with pytest.raises(ValueError):
        occlusion_saliency(PHISH, m, on="probability")  # type: ignore[arg-type]


def test_saliency_logit_delta_matches_reconstruction(m: UrlModel) -> None:
    # The reported delta must equal base_logit - occluded_logit for that character.
    url = PHISH
    base = float(m.logits([url])[0])
    sal = occlusion_saliency(url, m, on="logit")
    top = max(sal, key=lambda s: s.delta)
    assert top.delta > 0.5, "a confidently-phishing URL must have a strongly salient char"
    seq = m.encode([url])
    seq[0, top.start_byte : min(top.end_byte, MAX_LEN)] = 0
    occluded = float(m.logits_seq(seq)[0])
    assert top.delta == pytest.approx(base - occluded, abs=1e-5)


def test_logits_seq_matches_logits(m: UrlModel) -> None:
    urls = [PHISH, BENIGN, "a.co"]
    np.testing.assert_array_equal(m.logits_seq(m.encode(urls)), m.logits(urls))


def test_top_spans_highlights_phish_in_logit_space(m: UrlModel) -> None:
    # Probability space saturates (nothing to show); logit space (the default) must find
    # the incriminating region of a confidently-flagged URL.
    assert top_spans(PHISH, on="prob", model=m) == []
    spans = top_spans(PHISH, k=3, model=m)                 # on="logit" by default
    assert spans, "logit-space highlighting should surface the phishing tokens"
    assert all(isinstance(sp, SalientSpan) and sp.space == "logit" for sp in spans)
    assert len(spans) <= 3
    for sp in spans:
        assert sp.end > sp.start
        assert sp.text == PHISH[sp.start : sp.end]
        assert sp.delta > 0
    # ranked strongest-first
    assert [sp.delta for sp in spans] == sorted((sp.delta for sp in spans), reverse=True)
    # the merged spans should fall within the suspicious part of the URL, not the scheme
    assert any(tok in sp.text for sp in spans for tok in ("secure", "gin", "ify", "p"))


def test_top_spans_quiet_on_weak_signal(m: UrlModel) -> None:
    # With a stricter floor, a benign URL yields no manufactured "incriminating" spans.
    spans = top_spans(BENIGN, k=5, model=m, min_delta=5.0)
    assert spans == []
