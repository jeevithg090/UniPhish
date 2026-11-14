"""Tests for the text/message analyzer (smishing, chat, social engineering)."""

from __future__ import annotations

import asyncio

import pytest

from uniphish.analyzers.text import TextAnalyzer, pressure_weight
from uniphish.core.analyzer import AnalysisContext, AnalysisOptions, Analyzer, AnalyzerResult
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactKind, IndicatorType, Level, Signal

PARCEL = "Your parcel is on hold. Pay a $1.99 fee within 24 hours: http://post-track.example/x"


class StubURL(Analyzer):
    """Stand-in URL analyzer: flags hosts containing 'track' or 'evil'."""

    name = "stub_url"
    kinds = frozenset({ArtifactKind.URL})
    signals = {"url.stub": "stub"}

    def analyze_sync(self, artifact, ctx):
        bad = any(w in (artifact.url or "") for w in ("track", "evil", "paypa1"))
        if not bad:
            return AnalyzerResult()
        return AnalyzerResult(
            signals=[Signal(id="url.stub", title="Stub bad URL", weight=6.0, category="url")]
        )


def run(text: str, **meta) -> AnalyzerResult:
    art = Artifact.from_text(text, **meta)
    ctx = AnalysisContext(options=AnalysisOptions())
    return TextAnalyzer().analyze_sync(art, ctx)


def ids(res: AnalyzerResult) -> set[str]:
    return {s.id for s in res.signals}


def sig(res: AnalyzerResult, sid: str) -> Signal:
    return next(s for s in res.signals if s.id == sid)


def engine() -> Engine:
    return Engine(analyzers=[TextAnalyzer(), StubURL()])


def verdict(text: str):
    return engine().analyze_sync(Artifact.from_text(text), AnalysisOptions(persist=False))


# ------------------------------------------------------------------ smishing
def test_parcel_smishing_extracts_child_and_propagates_risk():
    res = run(PARCEL)
    assert [c.url for c in res.children] == ["http://post-track.example/x"]
    assert res.children[0].origin == "text.link"
    assert {"social.pressure", "social.link_in_pressure_message"} <= ids(res)
    v = verdict(PARCEL)
    assert v.level is Level.MALICIOUS
    assert v.children and v.children[0].origin == "text.link"
    assert any(s.id.startswith("engine.child") for s in v.signals)


def test_parcel_text_alone_is_not_benign_floor_but_below_malicious():
    v = engine().analyze_sync(
        Artifact.from_text(PARCEL), AnalysisOptions(persist=False, max_depth=0)
    )
    assert v.level is not Level.MALICIOUS
    assert v.score > 12  # moved off the prior by the language alone


def test_bank_credential_urgency_with_brand_mismatch():
    text = (
        "PayPal: your account is limited. Verify your login immediately or it will be "
        "closed: http://paypa1-secure.example/v"
    )
    res = run(text)
    assert "social.brand_link_mismatch" in ids(res)
    m = sig(res, "social.brand_link_mismatch")
    assert m.category == "brand" and m.weight == 2.0
    assert res.brand and res.brand.brand == "paypal" and not res.brand.official
    assert verdict(text).level is Level.MALICIOUS


def test_brand_with_official_link_has_no_mismatch():
    res = run("PayPal: your account needs attention, verify now at https://www.paypal.com/signin")
    assert "social.brand_link_mismatch" not in ids(res)
    assert res.brand is None


def test_brand_mismatch_without_pressure_is_weaker():
    res = run("Your Netflix subscription expired, update at http://other.example")
    m = sig(res, "social.brand_link_mismatch")
    assert m.weight == 1.2


# ----------------------------------------------------------------- asks
def test_otp_request():
    res = run("Please share your OTP to unblock your account")
    s = sig(res, "social.otp_request")
    assert s.weight == 3.0 and {"T1621", "T1111"} <= set(s.mitre)
    assert s.span is not None


def test_delivered_code_and_warning_is_not_otp_request():
    res = run("Your code is 123456. Never share it with anyone.")
    assert "social.otp_request" not in ids(res)
    assert not res.signals


def test_gift_card_bec_text():
    text = (
        "Buy 5 Apple gift cards $100 each and send me the codes, I'm in a meeting, "
        "urgent. Keep it confidential"
    )
    res = run(text)
    pay = sig(res, "social.payment_request")
    assert pay.weight == 2.5 and "T1657" in pay.mitre and pay.evidence["secrecy"] is True
    assert verdict(text).level is not Level.BENIGN


def test_tech_support_callback_number_indicator():
    res = run(
        "Microsoft security alert: your PC is infected. Call Microsoft support at "
        "+1 (888) 555-0100 now"
    )
    s = sig(res, "social.callback_number")
    assert s.weight == 2.0
    phones = [i for i in res.indicators if i.type is IndicatorType.PHONE]
    assert [p.value for p in phones] == ["+18885550100"]
    assert res.meta["text.phone_numbers"] == ["+18885550100"]


def test_plain_phone_number_in_friendly_chat_is_ignored():
    res = run("Please call me back on +44 20 7946 0000 about the invoice")
    assert "social.callback_number" not in ids(res)
    assert not res.indicators
    assert res.meta["text.phone_numbers"] == ["+442079460000"]


def test_crypto_seed_phrase_request():
    res = run("Enter your 12-word recovery seed phrase to claim your airdrop")
    s = sig(res, "social.crypto_seed_request")
    assert s.weight == 4.0 and s.span is not None


@pytest.mark.parametrize(
    "text",
    [
        "Never share your seed phrase with anyone, not even support.",
        "Our blog explains what a seed phrase is.",
        "Do not give your private key to anyone",
    ],
)
def test_seed_phrase_warnings_and_mentions_do_not_fire(text):
    assert "social.crypto_seed_request" not in ids(run(text))


def test_spanish_seed_phrase_request():
    res = run("Ingresa tu frase semilla para validar tu billetera")
    assert "social.crypto_seed_request" in ids(res)


# ------------------------------------------------------------------ benign
@pytest.mark.parametrize(
    "text",
    [
        "Hey, lunch at 1? I'll bring the notes.",
        "Running 10 minutes late, see you at the station",
        "Happy birthday! Dinner at 8 at mine",
        "Your code is 123456. Never share it.",
    ],
)
def test_benign_chat_stays_low(text):
    v = verdict(text)
    assert v.level is Level.BENIGN
    assert v.score <= 12
    assert not [s for s in v.signals if s.weight > 0.5]


def test_benign_message_with_link_has_child_but_no_signals():
    res = run("Notes from today are here: https://docs.example/notes")
    assert len(res.children) == 1
    assert not res.signals


# ------------------------------------------------------------- multilingual
@pytest.mark.parametrize(
    "text,lang",
    [
        ("Su paquete está retenido. Verifique su cuenta urgentemente", "es"),
        ("आपका खाता बंद हो जाएगा, तुरंत सत्यापित करें", "hi"),
        ("Sua conta foi bloqueada. Confirme seus dados imediatamente", "pt"),
    ],
)
def test_multilingual_pressure(text, lang):
    res = run(text)
    assert lang in res.meta["languages"]
    assert "social.pressure" in ids(res)


def test_spanish_credential_ask_fires_pressure_with_link():
    res = run(
        "Su paquete está retenido, verifique su cuenta urgentemente: http://correos-envio.example/p"
    )
    assert res.children and "social.pressure" in ids(res)


def test_otp_request_hindi():
    res = run("आपके खाते में समस्या है। ओटीपी साझा करें")
    assert "social.otp_request" in ids(res)


# --------------------------------------------------------------- structure
def test_meta_and_catalog_declared():
    res = run(PARCEL)
    assert "en" in res.meta["languages"] and "urgency" in res.meta["tactics"]
    emitted = {s.id for s in res.signals}
    assert emitted <= set(TextAnalyzer.signals)
    for s in res.signals:
        assert len(s.title) <= 70


def test_all_catalog_signals_are_emitted_somewhere():
    texts = [
        PARCEL,
        "Please share your OTP",
        "send gift cards, keep it confidential, urgent",
        "Your PC is infected. Call Microsoft support at +1 888 555 0100",
        "Enter your seed phrase",
        "PayPal: verify your login now, urgent, http://paypa1.example/x",
        "Your Netflix subscription expired, update at http://other.example",
    ]
    seen: set[str] = set()
    for t in texts:
        seen |= ids(run(t))
    assert set(TextAnalyzer.signals) - seen == {"social.urgent_credential_ask"}


def test_urgent_credential_ask_combination():
    res = run("Urgent: verify your account within 24 hours, enter your password")
    assert sig(res, "social.urgent_credential_ask").weight == 1.5  # no authority/brand
    res = run("PayPal: urgent, verify your account within 24 hours, enter your password")
    assert sig(res, "social.urgent_credential_ask").weight == 2.5


def test_pressure_weight_monotonic_and_capped():
    xs = [pressure_weight(v) for v in (0, 0.5, 1, 2, 3, 5, 12, 100)]
    assert xs == sorted(xs)
    assert xs[0] == 0 and xs[-1] == pressure_weight(5) <= 3.7


def test_links_capped_and_bad_input_safe():
    text = " ".join(f"http://h{i}.example/p" for i in range(100))
    res = run(text)
    assert len(res.children) <= 25
    assert not TextAnalyzer().applies(
        Artifact.from_text("   "), AnalysisContext(options=AnalysisOptions())
    )


def test_huge_text_is_bounded():
    text = ("urgent verify your account " * 80_000)[:900_000]
    res = run(text)
    assert res.meta["text.truncated"] is True


def test_defanged_link_extracted():
    res = run("urgent: verify at hxxp://evil[.]example/login")
    assert res.children and res.children[0].url.startswith("http://evil.example")


def test_engine_registration():
    from uniphish.core.analyzer import REGISTRY

    assert REGISTRY["text"] is TextAnalyzer
    assert (
        asyncio.run(Engine(analyzers=[TextAnalyzer()]).analyze_text("hi there")).level
        is Level.BENIGN
    )
