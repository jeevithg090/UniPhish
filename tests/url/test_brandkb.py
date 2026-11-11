"""Tests for the brand knowledge base (schema, consistency, lookups, mentions)."""

from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from uniphish.url.brandkb import BrandKB, BrandKBError, get_kb, normalize_host

kb = get_kb()


def _mk(**kw):
    base = {"id": "acme", "name": "Acme", "category": "tech", "official_domains": ["acme.example"]}
    base.update(kw)
    return base


# ----------------------------------------------------------------- whole-file checks
def test_size_and_cache() -> None:
    assert len(kb) >= 250
    assert get_kb() is kb


def test_ids_unique_snake_case() -> None:
    ids = [b.id for b in kb.all()]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"[a-z][a-z0-9_]*", i) for i in ids)


def test_every_official_domain_resolves_to_its_own_brand() -> None:
    """Catches an official domain shadowed by another brand's user-content domain."""
    for b in kb.all():
        for d in b.official_domains:
            assert kb.official_brand_for_host(d) is b, (b.id, d)
            assert kb.official_brand_for_host("www." + d) is b, (b.id, d)


def test_domains_are_lowercase_bare_and_unique() -> None:
    seen: dict[str, str] = {}
    for b in kb.all():
        for d in (*b.official_domains, *b.login_hosts, *b.cdn_hosts, *b.user_content_domains):
            assert d == d.lower() and "/" not in d and ":" not in d and "." in d, (b.id, d)
        for d in b.official_domains:
            assert d not in seen, (d, seen.get(d), b.id)
            seen[d] = b.id
        assert not set(b.official_domains) & set(b.user_content_domains), b.id


def test_login_hosts_are_official() -> None:
    for b in kb.all():
        for h in b.login_hosts:
            assert kb.official_brand_for_host(h) is b, (b.id, h)
            assert kb.login_brand_for_host(h) is b


def test_keywords_ascii_lowercase_and_native_names_non_ascii() -> None:
    for b in kb.all():
        assert b.keywords, b.id
        for k in b.keywords:
            assert re.fullmatch(r"[a-z0-9]+( [a-z0-9]+)*", k), (b.id, k)
        for n in b.native_names:
            assert not n.isascii(), (b.id, n)


def test_required_coverage() -> None:
    must = [
        "microsoft", "google", "apple", "amazon", "aws", "facebook", "instagram", "linkedin",
        "netflix", "adobe", "docusign", "dropbox", "zoom", "slack", "okta", "salesforce",
        "github", "openai", "paypal", "coinbase", "binance", "metamask", "dhl", "fedex", "ups",
        "usps", "royal_mail", "irs", "hmrc", "cra", "ato", "income_tax_india", "uidai", "epfo",
        "sbi", "sberbank", "alipay", "rakuten", "naver", "kakao", "yahoo", "line_app",
    ]
    for m in must:
        assert kb.get(m) is not None, m
    regions = {r for b in kb.all() for r in b.regions}
    wanted = {"us", "uk", "in", "cn", "jp", "kr", "ru", "br", "mx", "za", "ng", "ae", "sa", "tr"}
    assert wanted <= regions


# ----------------------------------------------------------------- host lookups
@pytest.mark.parametrize(
    ("host", "brand"),
    [
        ("login.microsoftonline.com", "microsoft"),
        ("LOGIN.MicrosoftOnline.com.", "microsoft"),
        ("accounts.google.com", "google"),
        ("www.paypal.com", "paypal"),
        ("paypal.com", "paypal"),
        ("a.b.c.paypal.com", "paypal"),
        ("www.paypal.com:443", "paypal"),
        ("aws.amazon.com", "aws"),
        ("www.amazon.de", "amazon"),
        ("appleid.apple.com", "apple"),
        ("www.irs.gov", "irs"),
    ],
)
def test_official_hosts(host: str, brand: str) -> None:
    b = kb.official_brand_for_host(host)
    assert b is not None and b.id == brand


@pytest.mark.parametrize(
    "host",
    [
        "notpaypal.com", "paypal.com.evil.test", "paypal-secure.test", "paypal.co",
        "evilpaypal.com",
        "evil.sharepoint.com", "tenant.sharepoint.com", "x.sites.google.com", "foo.github.io",
        "foo.web.app", "foo.pages.dev", "foo.blogspot.com", "bucket.s3.amazonaws.com",
        "docs.google.com", "", "   ", "a/b", "http://paypal.com", "[::1]", "paypal.com:abc", "com",
    ],
)
def test_not_official(host: str) -> None:
    assert kb.official_brand_for_host(host) is None


def test_user_content_hosts() -> None:
    cases = {
        "evil.sharepoint.com": "microsoft",
        "sharepoint.com": "microsoft",
        "x.y.sites.google.com": "google",
        "someone.github.io": "github",
        "kit.web.app": "google",
        "kit.pages.dev": "cloudflare",
        "kit.vercel.app": "vercel",
    }
    for host, brand in cases.items():
        b = kb.is_user_content_host(host)
        assert b is not None and b.id == brand, host
    assert kb.is_user_content_host("www.microsoft.com") is None
    assert kb.is_user_content_host("notsharepoint.com") is None
    assert kb.is_user_content_host("") is None


def test_cdn_hosts() -> None:
    b = kb.cdn_brand_for_host("aadcdn.msftauth.net")
    assert b is not None and b.id == "microsoft"
    assert kb.cdn_brand_for_host("static.aadcdn.msftauth.net") is b
    assert kb.cdn_brand_for_host("evilaadcdn.msftauth.net") is None
    assert kb.cdn_brand_for_host("example.com") is None


def test_get() -> None:
    assert kb.get("paypal").name == "PayPal"  # type: ignore[union-attr]
    assert kb.get("nope") is None


# ----------------------------------------------------------------- indexes
def test_keyword_index_longest_first() -> None:
    idx = kb.keyword_index()
    lengths = [len(k) for k, _ in idx]
    assert lengths == sorted(lengths, reverse=True)
    assert dict(idx)["paypal"][0].id == "paypal"
    assert len({k for k, _ in idx}) == len(idx)


def test_native_name_index() -> None:
    idx = kb.native_name_index()
    lengths = [len(k) for k, _ in idx]
    assert lengths == sorted(lengths, reverse=True)
    assert dict(idx)["支付宝"].id == "alipay"


# ----------------------------------------------------------------- text mentions
def ids(text: str, **kw) -> list[str]:
    return [b.id for b in kb.brands_mentioned_in(text, **kw)]


def test_mentions_latin_token_aware() -> None:
    assert ids("Your PayPal account is limited") == ["paypal"]
    assert ids("paypal-secure login") == ["paypal"]
    assert ids("Sign in to Microsoft 365 or Netflix") == ["microsoft", "netflix"]
    assert ids("notpaypal paypalsecure papypal") == []
    assert ids("") == []


def test_mentions_ordered_by_first_appearance() -> None:
    assert ids("netflix then paypal then netflix") == ["netflix", "paypal"]


def test_mentions_multilingual() -> None:
    assert "alipay" in ids("您的支付宝账户已被冻结")
    assert "sberbank" in ids("Ваш Сбербанк заблокирован")
    assert "rakuten" in ids("楽天カードからの重要なお知らせ")
    assert "naver" in ids("네이버 계정 보호 조치")
    assert "sbi" in ids("आपका एसबीआई खाता बंद", include_ambiguous=True)
    assert "sbi" in ids("आपका एसबीआई account बंद")
    assert "al_rajhi" in ids("حسابك في الراجحي معلق")
    assert "uidai" in ids("आपका आधार कार्ड अपडेट करें")


def test_mentions_ambiguous_need_context() -> None:
    assert "ups" not in ids("ups and downs of the week")
    assert "ups" in ids("UPS parcel delivery failed, confirm address")
    assert "ups" in ids("ups", include_ambiguous=True)
    assert "ups" not in ids("UPS parcel delivery failed", include_ambiguous=False)
    assert "line_app" not in ids("stand in line")
    assert "orange" not in ids("an orange fruit")


def test_mentions_input_is_bounded() -> None:
    assert ids("a " * 500_000 + "paypal") == []  # beyond the scan cap: ignored, no hang


# ----------------------------------------------------------------- validation
def test_valid_minimal_brand() -> None:
    k = BrandKB([_mk()])
    assert k.get("acme").keywords == ("acme",)  # type: ignore[union-attr]
    assert k.official_brand_for_host("x.acme.example").id == "acme"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "bad",
    [
        _mk(id="Bad-Id"),
        _mk(name=""),
        _mk(category=None),
        _mk(official_domains=["HTTP://acme.example"]),
        _mk(official_domains=["https://acme.example/path"]),
        _mk(official_domains=["Acme.Example"]),
        _mk(official_domains=["localhost"]),
        _mk(official_domains=["acme.example/login"]),
        _mk(login_hosts=["login.other.example"]),
        _mk(user_content_domains=["acme.example"]),
        _mk(keywords=["Upper"]),
        _mk(keywords=["has-dash"]),
        _mk(native_names=["ascii only"]),
        _mk(ambiguous="yes"),
        _mk(official_domains="acme.example"),
        _mk(surprise=1),
    ],
)
def test_validation_rejects(bad) -> None:
    with pytest.raises(BrandKBError):
        BrandKB([bad])


def test_duplicate_id_and_domain_rejected() -> None:
    with pytest.raises(BrandKBError):
        BrandKB([_mk(), _mk()])
    with pytest.raises(BrandKBError):
        BrandKB([_mk(), _mk(id="other")])
    with pytest.raises(BrandKBError):
        BrandKB(["not a mapping"])


def test_more_specific_official_beats_user_content() -> None:
    k = BrandKB(
        [
            _mk(
                id="host",
                official_domains=["host.example"],
                user_content_domains=["pages.host.example"],
            ),
            _mk(id="other", official_domains=["docs.pages.host.example"]),
        ]
    )
    assert k.official_brand_for_host("docs.pages.host.example").id == "other"  # type: ignore[union-attr]
    assert k.official_brand_for_host("evil.pages.host.example") is None
    assert k.is_user_content_host("evil.pages.host.example").id == "host"  # type: ignore[union-attr]


# ----------------------------------------------------------------- properties
@given(st.text(max_size=300))
def test_normalize_host_never_raises(s: str) -> None:
    out = normalize_host(s)
    assert isinstance(out, str)
    assert kb.official_brand_for_host(s) is None or out


@given(st.text(max_size=2000))
def test_mentions_never_raises(s: str) -> None:
    for b in kb.brands_mentioned_in(s):
        assert b.id
