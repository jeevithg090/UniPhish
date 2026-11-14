"""Tests for the look-alike domain permutation engine (offline, deterministic)."""

from __future__ import annotations

import idna
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.hunt.permutations import (
    DEFAULT_MAX,
    KINDS,
    Permutation,
    generate_permutations,
    normalize_kinds,
    split_domain,
)
from uniphish.url.confusables import skeleton


@pytest.fixture(scope="module")
def paypal() -> list[Permutation]:
    return generate_permutations("paypal.com")


def by_domain(perms: list[Permutation]) -> dict[str, Permutation]:
    return {p.domain: p for p in perms}


def test_known_forms_present(paypal):
    d = by_domain(paypal)
    assert d["paypa1.com"].kind == "homoglyph"  # ASCII look-alike digit
    assert d["xn--pypal-4ve.com"].kind == "homoglyph"  # Cyrillic a, A-label
    assert d["pay-pal.com"].kind == "hyphenation"
    assert d["pay.pal.com"].kind == "subdomain"
    assert d["paypal-secure.com"].kind == "combosquat"
    assert d["securepaypal.com"].kind == "combosquat"
    assert d["paypal.tk"].kind == "tld_swap"
    assert d["paypal.co.uk"].kind == "tld_swap"
    assert d["paypall.com"].kind in {"addition", "double_char"}
    assert d["pyapal.com"].kind == "typo"  # transposition
    assert d["paypul.com"].kind == "vowel_swap"  # a->u differs by two bits
    assert d["paypl.com"].kind == "omission"


def test_excludes_exact_domain_and_has_no_duplicates(paypal):
    domains = [p.domain for p in paypal]
    assert "paypal.com" not in domains
    assert len(domains) == len(set(domains))


def test_every_kind_is_represented(paypal):
    assert {p.kind for p in paypal} == set(KINDS)


def test_bitsquats_differ_by_one_bit(paypal):
    flips = [p for p in paypal if p.kind == "bitsquat"]
    assert flips
    for p in flips:
        label = p.domain[:-4]
        assert len(label) == 6
        diff = [(a, b) for a, b in zip("paypal", label, strict=True) if a != b]
        assert len(diff) == 1
        assert bin(ord(diff[0][0]) ^ ord(diff[0][1])).count("1") == 1


def test_output_is_valid_ascii_hostnames(paypal):
    for p in paypal:
        assert p.domain.isascii() and p.domain == p.domain.lower()
        assert len(p.domain) <= 253
        for label in p.domain.split("."):
            assert 1 <= len(label) <= 63
            assert not label.startswith("-") and not label.endswith("-")
            if label.startswith("xn--"):
                idna.decode(label)  # valid A-label


def test_homoglyphs_fold_back_to_the_brand(paypal):
    uni = [p for p in paypal if p.kind in {"homoglyph", "idn_homograph"} and "xn--" in p.domain]
    assert len(uni) > 10
    folded = 0
    for p in uni:
        label = p.display.split(".")[0]
        assert not label.isascii()
        if skeleton(label) == "paypal":
            folded += 1
    assert folded >= len(uni) // 2


def test_idn_homograph_whole_script(paypal):
    idn = [p for p in paypal if p.kind == "idn_homograph"]
    assert idn
    assert any("whole-script" in p.note for p in idn)


def test_display_roundtrip():
    p = Permutation("xn--pypal-4ve.com", "homoglyph")
    assert p.display == "pаypal.com"
    assert Permutation("bad..name", "typo").display == "bad..name"
    assert p.to_dict()["display"] == p.display


def test_bounded_and_round_robin():
    out = generate_permutations("paypal.com", max=40)
    assert len(out) == 40
    assert len({p.kind for p in out}) == len(KINDS)  # nothing starved
    assert generate_permutations("paypal.com", max=0) == []
    assert len(generate_permutations("paypal.com")) <= DEFAULT_MAX


def test_kind_filter_and_aliases():
    out = generate_permutations("paypal.com", kinds=["tld-swap"])
    assert out and {p.kind for p in out} == {"tld_swap"}
    assert normalize_kinds("all") == KINDS
    assert normalize_kinds(["typo", "homoglyph"]) == ("homoglyph", "typo")
    with pytest.raises(ValueError):
        generate_permutations("paypal.com", kinds=["nonsense"])


def test_priority_applies_among_requested_kinds():
    full = by_domain(generate_permutations("paypal.com"))
    assert full["paypall.com"].kind == "addition"  # higher priority than double_char
    only = by_domain(generate_permutations("paypal.com", kinds=["double_char"]))
    assert only["paypall.com"].kind == "double_char"  # nothing outranks it here
    assert "ppaypal.com" in only


def test_multi_label_suffix_and_subdomain_input():
    out = by_domain(generate_permutations("login.amazon.co.uk"))
    assert "amaz0n.co.uk" in out
    assert "amazon.com" in out and out["amazon.com"].kind == "tld_swap"
    assert "amazon.co.uk" not in out


def test_idn_input():
    perms = generate_permutations("пример.рф")
    assert perms
    assert all(p.domain.isascii() for p in perms)


def test_deterministic():
    assert generate_permutations("paypal.com") == generate_permutations("paypal.com")


@pytest.mark.parametrize(
    "bad", ["", "   ", "localhost", "192.0.2.1", "a" * 300 + ".com", "http://"]
)
def test_invalid_input_rejected(bad):
    with pytest.raises(ValueError):
        generate_permutations(bad)


def test_split_domain():
    assert split_domain("https://www.paypal.com/login") == ("paypal", "com")
    assert split_domain("example.test") == ("example", "test")


def test_overlong_label_is_bounded():
    out = generate_permutations("a" * 60 + ".com")
    assert len(out) <= DEFAULT_MAX
    assert all(len(lab) <= 63 for p in out for lab in p.domain.split("."))


@settings(max_examples=40, deadline=None)
@given(st.from_regex(r"[a-z][a-z0-9-]{0,18}[a-z0-9]", fullmatch=True))
def test_property_valid_and_excludes_original(label):
    domain = f"{label}.com"
    perms = generate_permutations(domain, max=300)
    assert len(perms) <= 300
    seen = set()
    for p in perms:
        assert p.domain != domain and p.domain not in seen
        seen.add(p.domain)
        assert p.kind in KINDS
        assert p.domain.isascii() and len(p.domain) <= 253
        for lab in p.domain.split("."):
            assert 1 <= len(lab) <= 63 and not lab.startswith("-") and not lab.endswith("-")
