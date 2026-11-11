"""Tests for the email analyzer (headers, auth, sender spoofing, BEC, child fan-out).

All messages are synthetic and inert: reserved domains only (.test/.example/example.com),
documentation IP ranges, no working payloads. ``gmail.com`` / ``paypal.com`` appear only as
*names* the knowledge base knows about; no mail is ever sent or fetched.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from uniphish.analyzers.email import EmailAnalyzer
from uniphish.core.analyzer import (
    REGISTRY,
    AnalysisContext,
    AnalysisOptions,
    Analyzer,
    AnalyzerResult,
)
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactKind, IndicatorType, Level, Signal

FIX = Path(__file__).resolve().parents[1] / "mail" / "fixtures"


def run(raw: bytes | str) -> AnalyzerResult:
    art = Artifact.from_email(raw)
    return EmailAnalyzer().analyze_sync(art, AnalysisContext(options=AnalysisOptions()))


def run_fixture(name: str) -> AnalyzerResult:
    return run((FIX / name).read_bytes())


def ids(res: AnalyzerResult) -> set[str]:
    return {s.id for s in res.signals}


def sig(res: AnalyzerResult, sid: str) -> Signal:
    return next(s for s in res.signals if s.id == sid)


def mail(headers: str, body: str = "hello", *, ctype: str = "text/plain; charset=utf-8") -> bytes:
    return (f"{headers.strip()}\nMIME-Version: 1.0\nContent-Type: {ctype}\n\n{body}\n"
            ).encode()


# A test URL analyzer / file analyzer so child risk can propagate without the real ones.
class _UrlStub(Analyzer):
    name = "url_stub"
    kinds = frozenset({ArtifactKind.URL})
    signals = {"url.stub.phish": "stub"}

    def analyze_sync(self, artifact, ctx):
        if "phish" in (artifact.url or ""):
            return AnalyzerResult(signals=[Signal(id="url.stub.phish", title="stub phish",
                                                  weight=7.0, category="url")])
        return AnalyzerResult()


class _FileStub(Analyzer):
    name = "file_stub"
    kinds = frozenset({ArtifactKind.FILE})
    signals = {"file.stub.bad": "stub"}

    def analyze_sync(self, artifact, ctx):
        if b"MALICIOUS-MARKER" in (artifact.content or b""):
            return AnalyzerResult(signals=[Signal(id="file.stub.bad", title="bad file",
                                                  weight=7.0, category="file")])
        return AnalyzerResult()


def engine() -> Engine:
    return Engine(analyzers=[EmailAnalyzer(), _UrlStub(), _FileStub()])


# ----------------------------------------------------------------------- contract
def test_registered_and_contract():
    assert REGISTRY["email"] is EmailAnalyzer
    a = EmailAnalyzer()
    assert a.kinds == frozenset({ArtifactKind.EMAIL}) and a.stage == 0 and a.blocking
    assert not a.requires_online


def test_every_emitted_signal_is_declared_and_well_formed():
    emitted: set[str] = set()
    for f in sorted(FIX.glob("*.eml")):
        r = run(f.read_bytes())
        for s in r.signals:
            emitted.add(s.id)
            assert s.id in EmailAnalyzer.signals, s.id
            assert len(s.title) <= 70, s.title
            assert s.detail and s.category in {"email", "auth", "social", "brand"}
    assert len(emitted) >= 8


def test_declared_signal_ids_are_namespaced():
    for sid in EmailAnalyzer.signals:
        assert sid.split(".")[0] in {"email", "auth", "social", "brand"}


# --------------------------------------------------------------------- spoofing
def test_display_name_brand_with_freemail_sender():
    raw = mail('From: "PayPal Support" <paypal.support.9921@gmail.com>\n'
               'To: v@recipient.test\nSubject: Account limited\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <a1@gmail.com>')
    r = run(raw)
    s = sig(r, "brand.sender.display_name")
    assert s.weight == 3.5 and "T1656" in s.mitre and s.evidence["freemail"] is True
    assert r.brand and r.brand.technique == "sender" and r.brand.brand == "paypal"
    assert not r.brand.official and "paypal.com" in r.brand.legit_domains
    assert "display_name_spoof" in r.techniques


def test_display_name_spoof_fixture_with_embedded_address_and_reply_to():
    r = run_fixture("display_name_spoof.eml")
    s = sig(r, "brand.sender.display_name")
    assert s.evidence["claimed_via"] == "domain" and s.evidence["brand"] == "paypal"
    rt = sig(r, "email.reply_to.mismatch")
    assert rt.weight == 2.0 and rt.evidence["reply_to_domain"] == "collector.test"
    kinds = {i.type for i in r.indicators}
    assert IndicatorType.EMAIL in kinds and IndicatorType.DOMAIN in kinds


def test_official_sender_with_its_own_brand_name_is_not_flagged():
    raw = mail('From: "PayPal" <service@paypal.com>\nTo: v@recipient.test\nSubject: Receipt\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <z@paypal.com>')
    assert "brand.sender.display_name" not in ids(run(raw))


def test_display_name_domain_unrelated_to_a_brand():
    raw = mail('From: "billing@acme-corp.example" <x@mailer.test>\nTo: v@r.test\n'
               'Subject: Invoice\nDate: Wed, 05 Nov 2025 10:00:00 +0000\n'
               'Message-ID: <q@mailer.test>')
    r = run(raw)
    s = sig(r, "email.sender.display_name_domain")
    assert s.weight == 2.0 and "acme-corp.example" in s.evidence["mentioned"]


def test_lookalike_sender_domain():
    raw = mail('From: Support <help@paypa1.com>\nTo: v@recipient.test\nSubject: Hi\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <x@paypa1.com>')
    r = run(raw)
    s = sig(r, "brand.sender.lookalike_domain")
    assert s.weight == 3.0 and s.evidence["brand"] == "paypal" and "T1656" in s.mitre
    assert r.brand and r.brand.brand == "paypal" and not r.brand.official
    bad = [i for i in r.indicators if i.malicious]
    assert bad and bad[0].value == "paypa1.com"


def test_reply_to_same_domain_is_fine_and_bulk_is_discounted():
    base = ('From: a@corp.example\nTo: v@r.test\nSubject: s\n'
            'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <m@corp.example>\n')
    assert "email.reply_to.mismatch" not in ids(
        run(mail(base + "Reply-To: support@corp.example")))
    assert sig(run(mail(base + "Reply-To: x@other.test")),
               "email.reply_to.mismatch").weight == 2.0


# --------------------------------------------------------------------- auth
def test_dmarc_fail_fixture():
    r = run_fixture("dmarc_fail.eml")
    d = sig(r, "auth.dmarc.fail")
    assert d.weight == 2.5 and d.category == "auth" and "T1566" in d.mitre
    assert sig(r, "auth.spf.fail").weight == 1.5
    assert sig(r, "email.return_path.mismatch").weight == 1.0
    assert "auth.aligned_pass.known" not in ids(r)
    assert r.meta["auth"]["dmarc"] == "fail"


def test_forged_authentication_results_is_flagged_not_trusted():
    r = run_fixture("forged_auth_results.eml")
    assert "auth.forged_results" in ids(r) and "auth.dmarc.fail" in ids(r)
    assert not any(s.weight < 0 for s in r.signals)


def test_aligned_known_sender_is_negative_and_verdict_benign():
    raw = mail(
        "Authentication-Results: mx.recipient.test; spf=pass smtp.mailfrom=service@paypal.com;"
        " dkim=pass header.d=paypal.com header.s=s1; dmarc=pass (p=REJECT) header.from=paypal.com\n"
        'From: PayPal <service@paypal.com>\nTo: jane@recipient.test\nSubject: Your receipt\n'
        "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <r1@paypal.com>",
        "Thanks for your payment. Details: https://www.paypal.com/activity")
    r = run(raw)
    s = sig(r, "auth.aligned_pass.known")
    assert s.weight == -1.5 and s.category == "auth"
    v = engine().analyze_sync(Artifact.from_email(raw))
    assert v.level is Level.BENIGN and v.score < 15


def test_aligned_unknown_domain_gets_only_token_credit():
    r = run_fixture("legit_aligned.eml")
    assert sig(r, "auth.aligned_pass").weight == -0.3
    assert "auth.aligned_pass.known" not in ids(r)


def test_aligned_pass_on_freemail_gets_no_credit():
    raw = mail("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=bob@gmail.com;"
               " dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com\n"
               "From: Bob <bob@gmail.com>\nTo: v@r.test\nSubject: s\n"
               "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@gmail.com>")
    assert not any(i.startswith("auth.aligned_pass") for i in ids(run(raw)))


def test_unaligned_pass_is_flagged():
    raw = mail("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=a@relay.test;"
               " dkim=none; dmarc=none header.from=corp.example\n"
               "From: Boss <boss@corp.example>\nTo: v@r.test\nSubject: s\n"
               "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>")
    assert sig(run(raw), "auth.dmarc.unaligned").weight == 1.5


def test_no_auth_headers_emits_no_auth_signals():
    r = run(mail("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
                 "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>"))
    assert not any(i.startswith("auth.") for i in ids(r))
    assert r.meta["auth"]["has_results"] is False


# --------------------------------------------------------------------- BEC
BEC_HEADERS = ('From: "Pat Director" <pat.director.77@gmail.com>\n'
               'Reply-To: <pat.d@collector.test>\n'
               'To: finance@recipient.test\nSubject: Urgent request\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <bec@gmail.com>')


def test_bec_gift_card_request():
    body = ("Urgent: I need you to buy 5 gift cards today and send me the codes. "
            "Keep this confidential, I'm in a meeting and can't take calls. Sent from my iPhone")
    r = run(mail(BEC_HEADERS, body))
    s = sig(r, "email.bec.payment_pressure")
    assert s.weight == 3.0 and "T1656" in s.mitre
    assert "email.bec.mobile_excuse" in ids(r) and "bec" in r.techniques
    assert "social.email.pressure" in ids(r)
    assert sig(r, "social.email.pressure").weight <= 5.0
    v = engine().analyze_sync(Artifact.from_email(mail(BEC_HEADERS, body)))
    assert v.level is not Level.BENIGN


def test_payment_request_with_a_link_is_not_bec_pressure():
    body = "Urgent payment gift cards needed, see https://portal.example/pay"
    assert "email.bec.payment_pressure" not in ids(run(mail(BEC_HEADERS, body)))


def test_clean_sender_gift_card_mention_is_not_scored_as_bec():
    hdr = ('From: Alex <alex@corp.example>\nTo: v@r.test\nSubject: Team gift\n'
           'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <a@corp.example>')
    r = run(mail(hdr, "Urgent: please buy gift cards for the party."))
    assert "email.bec.payment_pressure" not in ids(r)


def test_mobile_excuse_needs_a_suspicious_sender():
    hdr = ('From: Alex <alex@corp.example>\nTo: v@r.test\nSubject: hi\n'
           'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <a@corp.example>')
    assert "email.bec.mobile_excuse" not in ids(run(mail(hdr, "Sent from my iPhone")))


def test_callback_number_and_otp_signals():
    hdr = ('From: Billing <billing@mailer.test>\nTo: v@r.test\nSubject: Charge\n'
           'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <a@mailer.test>')
    r = run(mail(hdr, "Urgent: your account was charged $499. Call +1 202 555 0143 immediately "
                      "to cancel this payment."))
    assert "social.email.callback_number" in ids(r)
    assert any(i.type is IndicatorType.PHONE for i in r.indicators)
    r2 = run(mail(hdr, "Reply with the code we sent you to confirm."))
    assert "social.email.otp_request" in ids(r2)


# --------------------------------------------------------- headers / transport
def test_malformed_fixture():
    r = run_fixture("malformed.eml")
    assert sig(r, "email.header.duplicate_from").weight == 2.0
    assert "email.header.malformed" in ids(r) and "email.header.missing_fields" in ids(r)


def test_dynamic_origin_and_date_skew():
    raw = mail("Received: from dsl-203-0-113-9.dyn.isp.example (dsl-203-0-113-9.dyn.isp.example"
               " [203.0.113.9]) by mx.r.test with ESMTP id 1; Wed, 05 Nov 2025 10:00:03 +0000\n"
               "From: a@corp.example\nTo: v@r.test\nSubject: s\n"
               "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>")
    r = run(raw)
    assert sig(r, "email.received.dynamic_origin").weight == 0.8
    # documentation-range relay IPs are not globally routable: never emitted as IOCs
    assert not any(i.type is IndicatorType.IPV4 for i in r.indicators)
    pub = run(raw.replace(b"203.0.113.9", b"8.8.8.8"))  # a global address, string only
    assert any(i.type is IndicatorType.IPV4 and i.value == "8.8.8.8" for i in pub.indicators)
    skew = raw.replace(b"Date: Wed, 05 Nov 2025", b"Date: Mon, 01 Dec 2025")
    assert "email.header.date_skew" in ids(run(skew))


def test_bidi_attachment_filename():
    raw = _with_attachment(b"harmless", "invoice‮gpj.exe", "application/octet-stream")
    assert sig(run(raw), "email.attachment.bidi_filename").weight == 2.5


# --------------------------------------------------------------------- links
def test_anchor_mismatch_and_brand_variant():
    html = ('<html><body><a href="https://login.mailer.test/x">https://www.paypal.com/signin</a>'
            ' <a href="https://tracker.test/y">Click here</a></body></html>')
    r = run(mail("From: a@mailer.test\nTo: v@r.test\nSubject: s\n"
                 "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@mailer.test>", html,
                 ctype="text/html; charset=utf-8"))
    s = sig(r, "email.link.anchor_mismatch")
    assert s.weight == 2.5 and s.evidence["shown"] == "www.paypal.com"
    assert "T1566.002" in s.mitre


def test_matching_anchor_text_is_not_flagged():
    html = '<a href="https://www.corp.example/a">www.corp.example</a>'
    r = run(mail("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
                 "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>", html,
                 ctype="text/html; charset=utf-8"))
    assert "email.link.anchor_mismatch" not in ids(r)


def test_javascript_link_signal_and_not_a_child():
    html = '<a href="javascript:void(0)">x</a><a href="https://ok.example/">y</a>'
    r = run(mail("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
                 "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>", html,
                 ctype="text/html; charset=utf-8"))
    assert "email.link.dangerous_scheme" in ids(r)
    assert [c.url for c in r.children] == ["https://ok.example/"]


# --------------------------------------------------------------------- children
def test_link_children_carry_origin_and_anchor_text():
    r = run_fixture("forwarded_phish.eml")
    assert [c.origin for c in r.children] == ["email.attached"]
    html = '<a href="https://landing.example/go?a=1">Verify now</a>'
    r2 = run(mail("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
                  "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>", html,
                  ctype="text/html; charset=utf-8"))
    c = r2.children[0]
    assert c.kind is ArtifactKind.URL and c.origin == "email.link"
    assert c.meta["anchor_text"] == "Verify now" and c.meta["link_source"] == "html_href"
    assert any(i.type is IndicatorType.URL and i.value == c.url for i in r2.indicators)
    assert any(i.type is IndicatorType.DOMAIN and i.value == "landing.example"
               for i in r2.indicators)


def test_duplicate_links_are_deduplicated_and_mismatched_ones_come_first():
    html = ('<a href="https://a.example/1">one</a><a href="https://a.example/1">two</a>'
            '<a href="https://evil.test/z">https://www.paypal.com/</a>')
    r = run(mail("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
                 "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>", html,
                 ctype="text/html; charset=utf-8"))
    urls = [c.url for c in r.children]
    assert urls == ["https://evil.test/z", "https://a.example/1"]


def test_phishing_link_child_raises_parent_risk():
    hdr = ("From: a@corp.example\nTo: v@r.test\nSubject: s\n"
           "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <b@corp.example>")
    benign = engine().analyze_sync(Artifact.from_email(
        mail(hdr, "see https://ok.example/page")))
    bad = engine().analyze_sync(Artifact.from_email(
        mail(hdr, "see https://phish.example/login")))
    assert bad.score > benign.score + 40 and bad.level is not Level.BENIGN
    assert any(c.kind is ArtifactKind.URL and c.level is not Level.BENIGN for c in bad.children)
    assert any(s.id == "engine.child.url" for s in bad.signals)


def _with_attachment(data: bytes, filename: str, ctype: str) -> bytes:
    b64 = base64.b64encode(data).decode()
    return (
        "From: a@corp.example\nTo: v@r.test\nSubject: file\n"
        "Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <f@corp.example>\n"
        'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nSee attached.\n\n"
        f'--B\nContent-Type: {ctype}\nContent-Transfer-Encoding: base64\n'
        f'Content-Disposition: attachment; filename="{filename}"\n\n{b64}\n--B--\n'
    ).encode()


def test_attachment_hash_indicators_and_file_child():
    import hashlib

    data = b"inert test payload MALICIOUS-MARKER"
    r = run(_with_attachment(data, "report.bin", "application/octet-stream"))
    sha = hashlib.sha256(data).hexdigest()
    vals = {(i.type, i.value) for i in r.indicators}
    assert (IndicatorType.SHA256, sha) in vals
    assert (IndicatorType.MD5, hashlib.md5(data).hexdigest()) in vals
    assert (IndicatorType.SHA1, hashlib.sha1(data).hexdigest()) in vals
    assert (IndicatorType.FILENAME, "report.bin") in vals
    f = [c for c in r.children if c.kind is ArtifactKind.FILE]
    assert len(f) == 1 and f[0].origin == "email.attachment" and f[0].content == data
    assert f[0].filename == "report.bin"
    v = engine().analyze_sync(Artifact.from_email(
        _with_attachment(data, "report.bin", "application/octet-stream")))
    assert v.level is not Level.BENIGN and any(s.id == "engine.child.file" for s in v.signals)
    assert sha in {i.value for i in v.all_indicators()}


def test_inline_image_becomes_file_child_for_qr_scanning():
    r = run_fixture("data_uri_inline_image.eml")
    imgs = [c for c in r.children if c.origin == "email.image"]
    assert len(imgs) == 1 and imgs[0].kind is ArtifactKind.FILE


def test_forwarded_phish_attachment_raises_parent_via_attached_message_child():
    inner = ("From: PayPal Security <alerts@paypa1.com>\nTo: c@recipient.test\n"
             "Subject: locked\nDate: Fri, 07 Nov 2025 11:00:00 +0000\nMessage-ID: <i@paypa1.com>\n"
             "MIME-Version: 1.0\nContent-Type: text/plain\n\nverify https://phish.example/u\n")
    outer = ("From: Colleague <c@recipient.test>\nTo: sec@recipient.test\nSubject: FW\n"
             "Date: Fri, 07 Nov 2025 12:00:00 +0000\nMessage-ID: <o@recipient.test>\n"
             'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="O"\n\n'
             "--O\nContent-Type: text/plain\n\nIs this real?\n\n"
             '--O\nContent-Type: message/rfc822\nContent-Disposition: attachment; '
             f'filename="s.eml"\n\n{inner}\n--O--\n').encode()
    r = run(outer)
    att = [c for c in r.children if c.origin == "email.attached"]
    assert len(att) == 1 and att[0].kind is ArtifactKind.EMAIL
    assert not any(c.kind is ArtifactKind.FILE for c in r.children)
    v = engine().analyze_sync(Artifact.from_email(outer))
    assert v.level is not Level.BENIGN
    child = next(c for c in v.children if c.kind is ArtifactKind.EMAIL)
    assert "brand.sender.lookalike_domain" in {s.id for s in child.signals}
    assert v.brand and v.brand.brand == "paypal"


def test_forwarded_phish_fixture_children_and_nested_indicators():
    v = engine().analyze_sync(Artifact.from_email((FIX / "forwarded_phish.eml").read_bytes()))
    inner = next(c for c in v.children if c.kind is ArtifactKind.EMAIL)
    assert "email.link.anchor_mismatch" in {s.id for s in inner.signals}
    assert "email.reply_to.mismatch" in {s.id for s in inner.signals}


# --------------------------------------------------------------------- meta
def test_meta_is_json_safe_and_summarises():
    import json

    r = run_fixture("display_name_spoof.eml")
    json.dumps(r.meta)
    assert r.meta["from"] == "account.help9921@freemail.example"
    assert r.meta["subject"].startswith("Action required")
    assert r.meta["counts"]["links"] == 2
    assert r.meta["auth"]["dmarc"] == "pass"
    assert r.meta["sender_seen_before"] is None  # no store file in an isolated data dir


def test_sender_seen_before_reads_existing_store(tmp_path):
    from uniphish.core.config import get_settings
    from uniphish.core.types import Indicator
    from uniphish.store import Store

    s = get_settings()
    st_ = Store(s.db_path)
    v = engine().analyze_sync(Artifact.from_email((FIX / "display_name_spoof.eml").read_bytes()))
    v.indicators.append(Indicator(type=IndicatorType.EMAIL,
                                  value="account.help9921@freemail.example"))
    st_.save_verdict(v)
    st_.close()
    assert run_fixture("display_name_spoof.eml").meta["sender_seen_before"] is True
    assert run_fixture("dmarc_fail.eml").meta["sender_seen_before"] is False


# --------------------------------------------------------------------- hostile input
@pytest.mark.parametrize("raw", [b"", b"\x00\xff" * 50, b"From: \n\n", b"Subject: x",
                                 b"From: " + b"a" * 100_000 + b"@x.test\n\nhi",
                                 b"\n".join(b"Received: " + b"x" * 500 for _ in range(300))])
def test_garbage_never_raises(raw):
    res = run(raw) if raw else EmailAnalyzer().analyze_sync(
        Artifact.from_email(b""), AnalysisContext(options=AnalysisOptions()))
    assert isinstance(res, AnalyzerResult)


def test_applies_only_to_email():
    a = EmailAnalyzer()
    ctx = AnalysisContext(options=AnalysisOptions())
    assert a.applies(Artifact.from_email(b"x"), ctx)
    assert not a.applies(Artifact.from_text("x"), ctx)


def test_homoglyph_display_name_still_detected():
    raw = mail('From: "PayPaІ Support" <x9@gmail.com>\nTo: v@r.test\nSubject: s\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <m@gmail.com>')
    assert "brand.sender.display_name" in ids(run(raw))


def test_detail_text_never_contains_control_or_bidi_characters():
    raw = mail('From: "PayPal ‮support\x07" <x@gmail.com>\nTo: v@r.test\nSubject: s\n'
               'Date: Wed, 05 Nov 2025 10:00:00 +0000\nMessage-ID: <m@gmail.com>')
    for s in run(raw).signals:
        assert "‮" not in s.detail and "\x07" not in s.detail


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(st.binary(max_size=4000))
def test_fuzz_never_raises(raw):
    run(raw)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(name=st.text(max_size=60), body=st.text(max_size=300))
def test_fuzz_text_headers(name, body):
    safe = name.replace("\n", " ").replace("\r", " ").replace('"', "'")
    run(f'From: "{safe}" <u@mailer.test>\nSubject: t\n\n{body}'.encode("utf-8", "replace"))
