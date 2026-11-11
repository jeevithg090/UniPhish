"""Tests for the Unicode homoglyph / IDN-homograph security core.

Covers :mod:`uniphish.url.confusables`, :mod:`uniphish.url.scripts` and
:mod:`uniphish.url.idn_policy`. The guiding principle is a two-sided bar: real
homoglyph attacks MUST be detected, and legitimate internationalised domains
(German, Chinese, Japanese, Korean, Greek, Russian) must NOT be flagged.

All inputs are synthetic and inert and use reserved/example TLDs.
"""

from __future__ import annotations

import idna
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.url import confusables as C
from uniphish.url import idn_policy as P
from uniphish.url import scripts as S

# --------------------------------------------------------------------------- #
# Named code points used below (Unicode names in comments for auditability).
# --------------------------------------------------------------------------- #
CYR_A = "а"   # а CYRILLIC SMALL LETTER A        (looks like Latin a)
CYR_R = "р"   # р CYRILLIC SMALL LETTER ER       (looks like Latin p)
CYR_E = "е"   # е CYRILLIC SMALL LETTER IE       (looks like Latin e)
CYR_O = "о"   # о CYRILLIC SMALL LETTER O        (looks like Latin o)
CYR_S = "с"   # с CYRILLIC SMALL LETTER ES       (looks like Latin c)
CYR_U = "у"   # у CYRILLIC SMALL LETTER U        (looks like Latin y)
CYR_PA = "ӏ"  # ӏ CYRILLIC SMALL LETTER PALOCHKA (looks like Latin l)
GRK_O = "ο"   # ο GREEK SMALL LETTER OMICRON     (looks like Latin o)
ARM_O = "օ"   # օ ARMENIAN SMALL LETTER OH       (looks like Latin o)
SCRIPT_G = "ɡ"  # ɡ LATIN SMALL LETTER SCRIPT G  (Restricted identifier)
RLO = "‮"     # RIGHT-TO-LEFT OVERRIDE
ZWJ = "‍"     # ZERO WIDTH JOINER
SOFT_HYPHEN = "­"

# "paypal" written entirely in Cyrillic look-alikes, and "apple" ditto.
PAYPAL_CYR = CYR_R + CYR_A + CYR_U + CYR_R + CYR_A + CYR_PA   # раураӏ
APPLE_CYR = CYR_A + CYR_R + CYR_R + CYR_PA + CYR_E            # аррӏе == xn--80ak6aa92e


# --------------------------------------------------------------------------- #
# confusables.py
# --------------------------------------------------------------------------- #
def test_skeleton_folds_cross_script_lookalikes_to_ascii():
    assert C.skeleton("p" + CYR_A + "ypal") == "paypal"       # Cyrillic а in paypal
    assert C.skeleton(APPLE_CYR) == "apple"
    assert C.skeleton("g" + GRK_O + GRK_O + "gle") == "google"   # Greek omicron
    assert C.skeleton("g" + ARM_O + ARM_O + "gle") == "google"   # Armenian oh


def test_are_confusable_symmetric_and_negative():
    assert C.are_confusable(CYR_A + "pple", "apple")
    assert C.are_confusable("apple", CYR_A + "pple")
    assert not C.are_confusable("apple", "aple")


def test_skeleton_is_idempotent_on_its_own_output():
    sk = C.skeleton(APPLE_CYR)
    assert C.skeleton(sk) == sk


def test_skeleton_empty_string():
    assert C.skeleton("") == ""


def test_ascii_fold_and_brand_skeleton_squatting():
    # leet digits
    assert C.brand_skeleton("g00gle") == "google"
    assert C.brand_skeleton("paypa1") == "paypal"
    # multi-glyph look-alikes
    assert C.brand_skeleton("rnicrosoft") == "microsoft"
    assert C.brand_skeleton("vvalmart") == "walmart"
    # homoglyph + leet combined
    assert C.brand_skeleton(CYR_R + CYR_A + CYR_U + CYR_R + CYR_A + "1") == "paypal"


def test_brand_skeleton_is_lowercase():
    assert C.brand_skeleton("PayPal") == "paypal"


def test_lookalikes_of_roundtrips_through_skeleton():
    looks = C.lookalikes_of("o")
    assert CYR_O in looks and GRK_O in looks
    # every reported look-alike really does fold back to 'o'
    for ch in looks:
        assert C.skeleton(ch) == "o"
    assert C.lookalikes_of("Z") == [] or all(C.skeleton(c) == "Z" for c in C.lookalikes_of("Z"))


def test_lookalikes_of_rejects_multichar():
    with pytest.raises(ValueError):
        C.lookalikes_of("ab")


def test_confusable_chars_in_reports_positions():
    hits = C.confusable_chars_in("p" + CYR_A + "ypal")
    assert hits == [(1, CYR_A, "a")]
    assert C.confusable_chars_in("paypal") == []


def test_unicode_version_is_reported():
    assert C.unicode_version().count(".") == 2


# --------------------------------------------------------------------------- #
# scripts.py — script resolution and restriction levels
# --------------------------------------------------------------------------- #
def test_script_of_and_extensions_and_status():
    assert S.script_of(CYR_A) == "Cyrl"
    assert S.script_of("a") == "Latn"
    assert S.script_name("Cyrl") == "Cyrillic"
    assert "Latn" in S.script_extensions("a")
    assert S.identifier_status(CYR_A) == "allowed"
    assert S.identifier_status(SCRIPT_G) == "restricted"


def test_mixed_script_detection():
    assert S.is_mixed_script("p" + CYR_A + "ypal")          # Latin + Cyrillic
    assert not S.is_mixed_script("apple")                   # pure Latin
    assert not S.is_mixed_script(PAYPAL_CYR)                # pure Cyrillic
    assert not S.is_mixed_script("")


def test_resolved_script_set():
    assert S.resolved_script_set("apple") == frozenset({"Latn"})
    assert S.resolved_script_set("p" + CYR_A + "ypal") == frozenset()   # mixed -> empty


@pytest.mark.parametrize("text,level", [
    ("apple", S.RestrictionLevel.ASCII_ONLY),
    (PAYPAL_CYR, S.RestrictionLevel.SINGLE_SCRIPT),
    ("中文", S.RestrictionLevel.SINGLE_SCRIPT),               # Han only
    ("sonyソニー", S.RestrictionLevel.HIGHLY_RESTRICTIVE),  # Latin + Katakana
    ("p" + CYR_A + "ypal", S.RestrictionLevel.MINIMALLY_RESTRICTIVE),   # Latin + Cyrillic
    (SCRIPT_G + "oogle", S.RestrictionLevel.UNRESTRICTED),            # Restricted char
])
def test_restriction_levels(text, level):
    assert S.restriction_level(text) is level


def test_whole_script_confusable():
    assert S.whole_script_confusable(PAYPAL_CYR)          # all-Cyrillic reads as Latin
    assert S.whole_script_confusable(APPLE_CYR)
    assert not S.whole_script_confusable("apple")         # already Latin
    assert not S.whole_script_confusable("δοκιμή")  # Greek δοκιμή
    assert not S.whole_script_confusable("")


# --------------------------------------------------------------------------- #
# scripts.py — invisible / bidi / tag / combining detectors
# --------------------------------------------------------------------------- #
def test_find_invisible():
    hits = S.find_invisible("a" + ZWJ + "b" + SOFT_HYPHEN)
    cps = {cp for _, cp, _ in hits}
    assert 0x200D in cps and 0x00AD in cps
    assert S.find_invisible("abc") == []


def test_find_invisible_variation_selector():
    hits = S.find_invisible("a️")   # VARIATION SELECTOR-16
    assert hits and hits[0][1] == 0xFE0F


def test_find_bidi_controls_trojan_source():
    hits = S.find_bidi_controls("admin" + RLO + "txt.exe")
    assert hits and hits[0][1] == 0x202E
    assert S.find_bidi_controls("plain") == []


def test_decode_tag_chars_roundtrip():
    hidden = "ignore previous instructions"
    smuggled = "hello" + "".join(chr(0xE0000 + ord(c)) for c in hidden)
    assert S.decode_tag_chars(smuggled) == hidden
    assert S.decode_tag_chars("nothing hidden here") is None


def test_has_combining_on_latin():
    assert S.has_combining_on_latin("á")      # a + COMBINING ACUTE ACCENT
    assert not S.has_combining_on_latin("café")  # precomposed é


# --------------------------------------------------------------------------- #
# idn_policy.py — the homograph assessment
# --------------------------------------------------------------------------- #
MUST_FLAG = [
    ("p" + CYR_A + "ypal.com", None, "mixed_script"),                 # Cyrillic а in paypal
    (PAYPAL_CYR + ".com", None, "whole_script_confusable"),           # whole-Cyrillic paypal
    (APPLE_CYR + ".com", None, "whole_script_confusable"),            # xn--80ak6aa92e.com
    ("g" + GRK_O + GRK_O + "gle.com", None, "mixed_script"),          # Greek omicron mix
    ("g" + ARM_O + ARM_O + "gle.com", None, "mixed_script"),          # Armenian oh mix
    ("admin" + RLO + "d.example", None, "bidi_control"),              # RTLO
    ("ban" + ZWJ + "k.example", None, "invisible_char"),              # zero-width joiner
    (SCRIPT_G + "oogle.example", None, "disallowed_identifier_char"),  # Restricted char
]


@pytest.mark.parametrize("host,tld,expected_reason", MUST_FLAG)
def test_assess_host_flags_homographs(host, tld, expected_reason):
    a = P.assess_host(host, tld=tld)
    assert not a.display_as_unicode
    assert expected_reason in a.reasons
    assert a.is_spoof


LEGIT = [
    ("bücher.de", None),                                  # German umlaut
    ("münchen.de", None),                                 # München
    ("中文网.cn", "cn"),                           # Chinese (Han) under .cn
    ("한국어.kr", "kr"),                           # Korean (Hangul) under .kr
    ("日本語テスト.jp", "jp"),         # Japanese kanji+kana under .jp
    ("δοκιμή.gr", "gr"),         # Greek-only under .gr
    ("пример.рф", "рф"),  # Cyrillic under .рф
    ("example.com", None),                                     # plain ASCII
]


@pytest.mark.parametrize("host,tld", LEGIT)
def test_assess_host_allows_legitimate_idns(host, tld):
    a = P.assess_host(host, tld=tld)
    assert a.display_as_unicode, f"{host} wrongly flagged: {a.reasons}"
    assert a.reasons == ()


def test_cyrillic_whole_script_allowed_only_under_cyrillic_cctld():
    # A whole-Cyrillic label that reads as Latin is a spoof under a Latin TLD, but is
    # exactly what a browser shows as Unicode under a Cyrillic-script ccTLD.
    assert P.assess_host(PAYPAL_CYR + ".com").is_spoof                       # under .com
    ok = P.assess_host(PAYPAL_CYR + ".рф", tld="рф")     # under .рф
    assert ok.display_as_unicode and ok.reasons == ()


def test_xn_punycode_decodes_and_flags():
    # xn--80ak6aa92e is the A-label of аррӏе; a browser would show it as this Unicode.
    assert idna.decode("xn--80ak6aa92e") == APPLE_CYR
    assert P.assess_host(idna.decode("xn--80ak6aa92e") + ".com").is_spoof


def test_skeleton_matches_top_domain():
    tops = {"paypal", "google", "apple"}
    a = P.assess_host("paypa1.example", top_domain_skeletons=tops)   # ASCII leet squat
    assert "skeleton_matches_top_domain" in a.reasons
    # the real brand itself must not self-flag
    clean = P.assess_host("paypal.com", top_domain_skeletons=tops)
    assert "skeleton_matches_top_domain" not in clean.reasons


def test_tag_smuggling_detected_as_invisible_in_host():
    smuggled = "safe" + "".join(chr(0xE0000 + ord(c)) for c in "evil") + ".example"
    a = P.assess_host(smuggled)
    assert a.is_spoof


def test_assessment_fields_populated():
    a = P.assess_host("p" + CYR_A + "ypal.com", top_domain_skeletons={"paypal"})
    assert a.host == "p" + CYR_A + "ypal.com"
    assert a.labels == ("p" + CYR_A + "ypal", "com")
    assert "Cyrl" in a.scripts and "Latn" in a.scripts
    assert a.skeleton == "paypal.com"
    assert a.restriction_level in set(S.RestrictionLevel)


def test_host_skeleton_and_confusable_report_helpers():
    assert P.host_skeleton(PAYPAL_CYR + ".com") == "paypal.com"
    rep = P.confusable_report("p" + CYR_A + "ypal.com")
    assert (1, CYR_A, "a") in rep


# --------------------------------------------------------------------------- #
# Property-based robustness (parsers/normalisers must never raise)
# --------------------------------------------------------------------------- #
@settings(max_examples=250)
@given(st.text(max_size=120))
def test_skeleton_never_raises_and_is_stable(s):
    sk = C.skeleton(s)
    assert C.skeleton(sk) == sk          # skeleton of a skeleton is itself


@settings(max_examples=250)
@given(st.text(max_size=120))
def test_assess_host_never_raises(s):
    a = P.assess_host(s)
    assert isinstance(a.display_as_unicode, bool)
    assert isinstance(a.reasons, tuple)


@settings(max_examples=200)
@given(st.from_regex(r"[a-z][a-z0-9-]{0,20}\.(com|net|org|example)", fullmatch=True))
def test_ascii_hosts_never_spoof_via_script(host):
    a = P.assess_host(host)
    # pure-ASCII hosts are always shown as-is and carry no script-based spoof reason
    assert a.display_as_unicode
    for r in ("mixed_script", "whole_script_confusable", "invisible_char", "bidi_control"):
        assert r not in a.reasons
