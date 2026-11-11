"""Tests for uniphish.mail.auth: header-only SPF/DKIM/DMARC/ARC analysis + spoof helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from uniphish.mail import (
    analyze_auth,
    from_display_name_contains_other_domain,
    parse_email,
    reply_to_differs_from_from,
)
from uniphish.mail.auth import domains_aligned, org_domain

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return parse_email((FIX / name).read_bytes())


def mk(headers: str, frm: str = "From: Bank <alerts@bank.example>") -> bytes:
    return f"{frm}\n{headers}\nSubject: s\n\nbody\n".encode()


# ------------------------------------------------------------------ fixtures
def test_legit_aligned_pass():
    a = analyze_auth(load("legit_aligned.eml"))
    assert (a.spf.status, a.dkim.status, a.dmarc.status) == ("pass", "pass", "pass")
    assert a.spf.domain == "bank.example" and a.spf.helo == "mx.bank.example"
    assert a.spf.client_ip == "" or a.spf.client_ip  # not asserted from A-R
    assert a.spf.aligned and a.dkim.aligned and a.dmarc_aligned
    assert a.dmarc.policy == "reject" and a.dmarc.header_from == "bank.example"
    assert a.dkim.signatures[0].selector == "sel1"
    assert a.authenticated_domain == "bank.example"
    assert a.authserv_id == "mail.recipient.test" and a.has_auth_results
    assert a.from_domain == "bank.example" and a.notes == []
    assert a.dkim.unverified_domains == ["bank.example"]
    assert not a.fully_failed


def test_dmarc_fail_fixture():
    a = analyze_auth(load("dmarc_fail.eml"))
    assert a.spf.status == "fail" and a.spf.domain == "badhost.invalid"
    assert a.dkim.status == "none" and a.dmarc.status == "fail"
    assert a.dmarc.policy == "reject"
    assert not a.spf_aligned and not a.dkim_aligned and not a.dmarc_aligned
    assert a.authenticated_domain == "" and a.fully_failed


def test_forged_authentication_results_ignored():
    a = analyze_auth(load("forged_auth_results.eml"))
    assert a.authserv_id == "mx.recipient.test"
    assert (a.spf.status, a.dkim.status, a.dmarc.status) == ("fail", "none", "fail")
    assert not a.dmarc_aligned
    assert "ignored_untrusted_authentication_results:1" in a.notes


def test_no_auth_headers():
    a = analyze_auth(load("encoded_bodies.eml"))
    assert not a.has_auth_results and "no_authentication_results" in a.notes
    assert (a.spf.status, a.dkim.status, a.dmarc.status) == ("none",) * 3
    assert not a.dmarc_aligned


# ------------------------------------------------------------------ alignment
def test_spf_pass_but_unaligned_with_from():
    raw = mk("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=bounce@esp.example;"
             " dkim=none; dmarc=fail (p=QUARANTINE) header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status == "pass" and not a.spf.aligned and not a.dmarc_aligned
    assert a.dmarc.policy == "quarantine"


def test_relaxed_alignment_subdomain_and_registrable_level():
    raw = mk("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=b@mail.bank.example;"
             " dkim=pass header.d=news.bank.example; dmarc=pass header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.spf.aligned and a.dkim.aligned and a.dmarc_aligned


def test_dkim_pass_unrelated_domain_not_aligned():
    raw = mk("Authentication-Results: mx.r.test; dkim=pass header.d=attacker.example;"
             " dkim=fail header.d=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.dkim.status == "pass" and not a.dkim.aligned and not a.dmarc_aligned
    assert len(a.dkim.signatures) == 2


def test_second_dkim_signature_aligned():
    raw = mk("Authentication-Results: mx.r.test; dkim=pass header.d=esp.example;"
             " dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.dkim_aligned and a.authenticated_domain == "bank.example"


def test_private_suffix_not_aligned_across_tenants():
    # evil.pages.dev and good.pages.dev are different registrable units (private PSL)
    assert not domains_aligned("evil.pages.dev", "good.pages.dev")
    assert domains_aligned("a.good.pages.dev", "good.pages.dev")
    assert org_domain("mail.example.co.uk") == "example.co.uk"
    assert not domains_aligned("", "")


def test_dmarc_pass_claim_without_alignment_is_noted():
    raw = mk("Authentication-Results: mx.r.test; spf=fail smtp.mailfrom=x@evil.example;"
             " dmarc=pass header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert "dmarc_pass_but_unaligned_in_headers" in a.notes


def test_dmarc_header_from_mismatch_noted():
    raw = mk("Authentication-Results: mx.r.test; dmarc=pass header.from=other.example")
    assert "dmarc_header_from_mismatch" in analyze_auth(parse_email(raw)).notes


# ------------------------------------------------------------------ Received-SPF / fallbacks
def test_received_spf_fallback():
    raw = mk("Received-SPF: softfail (g.test: domain of transitioning x@bank.example does not"
             " designate 203.0.113.5) client-ip=203.0.113.5; envelope-from=x@bank.example;"
             " helo=h.test;")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status == "softfail" and a.spf.source == "received-spf"
    assert a.spf.domain == "bank.example" and a.spf.client_ip == "203.0.113.5"
    assert not a.spf.aligned  # softfail never aligns


def test_spf_header_disagreement_noted():
    raw = mk("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=a@bank.example\n"
             "Received-SPF: fail client-ip=203.0.113.1; envelope-from=a@bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status == "pass" and "spf_header_disagreement" in a.notes


def test_spf_domain_falls_back_to_return_path():
    raw = mk("Return-Path: <b@bank.example>\nAuthentication-Results: mx.r.test; spf=pass")
    a = analyze_auth(parse_email(raw))
    assert a.spf.domain == "bank.example" and a.spf.aligned


def test_status_aliases_and_unknown_values():
    raw = mk("Authentication-Results: mx.r.test; spf=hardfail smtp.mailfrom=a@b.example;"
             " dkim=banana header.d=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status == "fail" and a.dkim.status == "none"
    assert "garbled_authentication_results" in a.notes


# ------------------------------------------------------------------ robustness
def test_comments_nested_and_semicolons_in_comments():
    raw = mk("Authentication-Results: mx.r.test (nested (comment; with semi));\n"
             " spf=pass (a; b) smtp.mailfrom=u@bank.example;\n"
             " dmarc=pass (p=REJECT; sp=NONE) header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status == "pass" and a.dmarc.status == "pass" and a.dmarc.policy == "reject"
    assert a.authserv_id == "mx.r.test"


def test_duplicate_and_garbled_headers_do_not_raise():
    raw = mk("Authentication-Results: ;;;;\nAuthentication-Results: =====\n"
             "Authentication-Results: x; spf\nReceived-SPF:\nARC-Seal: junk\n"
             "DKIM-Signature: nothing=here")
    a = analyze_auth(parse_email(raw))
    assert isinstance(a.notes, list)


def test_no_from_domain():
    a = analyze_auth(parse_email(b"Subject: x\n\nhi"))
    assert "no_from_domain" in a.notes and not a.dmarc_aligned


def test_long_values_bounded():
    raw = mk("Authentication-Results: mx.r.test; spf=pass smtp.mailfrom=" + "a" * 50_000)
    analyze_auth(parse_email(raw))  # must return promptly without raising


def test_unverified_dkim_signature_only():
    raw = mk("DKIM-Signature: v=1; a=rsa-sha256; d=bank.example; s=x; b=AAA")
    a = analyze_auth(parse_email(raw))
    assert a.dkim.status == "none" and a.dkim.unverified_domains == ["bank.example"]
    assert "dkim_signature_present_but_unverified" in a.notes


# ------------------------------------------------------------------ ARC
def test_arc_chain():
    raw = mk("ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=relay2.example; s=a; b=X\n"
             "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=relay1.example; s=a; b=Y\n"
             "ARC-Message-Signature: i=1; d=relay1.example\n"
             "Authentication-Results: mx.r.test; arc=pass; spf=fail smtp.mailfrom=a@x.example;"
             " dmarc=fail header.from=bank.example")
    a = analyze_auth(parse_email(raw))
    assert a.arc.present and a.arc.instances == 2 and a.arc.chain_validation == "pass"
    assert a.arc.sealers == ["relay2.example", "relay1.example"]
    assert "arc_pass_but_direct_auth_failed" in a.notes


def test_no_arc():
    assert not analyze_auth(load("legit_aligned.eml")).arc.present


# ------------------------------------------------------------------ display-name spoofing
@pytest.mark.parametrize("frm,expected", [
    ('"support@paypal.com" <x@freemail.example>', True),
    ('"PayPal paypal.com" <x@freemail.example>', True),
    ('"www.paypal.com Support" <x@freemail.example>', True),
    ('"PayPal Support" <x@freemail.example>', False),          # brand name, no domain
    ('"John.Smith" <john@corp.example>', False),               # dotted name, not a domain
    ('"bank.example Alerts" <a@bank.example>', False),         # own domain is fine
    ('"alerts@mail.bank.example" <a@bank.example>', False),    # same org domain
    ('"Amazon amazon.co.uk" <x@evil.example>', True),          # multi-label suffix
    ('<x@freemail.example>', False),
])
def test_display_name_contains_other_domain(frm, expected):
    pe = parse_email(f"From: {frm}\n\nx".encode())
    assert from_display_name_contains_other_domain(pe) is expected


def test_display_name_spoof_fixture():
    pe = load("display_name_spoof.eml")
    assert from_display_name_contains_other_domain(pe)
    assert reply_to_differs_from_from(pe)


def test_legit_fixture_has_no_spoof_flags():
    pe = load("legit_aligned.eml")
    assert not from_display_name_contains_other_domain(pe)
    assert not reply_to_differs_from_from(pe)


def test_reply_to_variants():
    base = "From: A <a@bank.example>\nReply-To: {}\n\nx"
    same_org = parse_email(base.format("help@mail.bank.example").encode())
    assert not reply_to_differs_from_from(same_org)
    assert reply_to_differs_from_from(same_org, same_domain_ok=False)
    other = parse_email(base.format("help@evil.example").encode())
    assert reply_to_differs_from_from(other)
    multi = parse_email(base.format("a@bank.example, b@evil.example").encode())
    assert reply_to_differs_from_from(multi)
    none = parse_email(b"From: A <a@bank.example>\n\nx")
    assert not reply_to_differs_from_from(none)
    nofrom = parse_email(b"Reply-To: a@evil.example\n\nx")
    assert not reply_to_differs_from_from(nofrom)


# ------------------------------------------------------------------ property tests
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=400), st.text(max_size=200))
def test_property_auth_never_raises(ar, rspf):
    raw = (f"From: a@bank.example\nAuthentication-Results: {ar}\nReceived-SPF: {rspf}\n\nx"
           ).encode("utf-8", "surrogatepass")
    a = analyze_auth(parse_email(raw))
    assert a.spf.status in {"pass", "fail", "none", "softfail", "neutral", "temperror",
                            "permperror"}
    assert a.dmarc_aligned == (a.spf_aligned or a.dkim_aligned)
