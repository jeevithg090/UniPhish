"""Tests for uniphish.assets.lists: accessors, boundary safety, data integrity, perf."""

from __future__ import annotations

import base64
import gzip
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.assets import asset_path, load_lines, load_yaml
from uniphish.assets import lists as L


# --------------------------------------------------------------------------- tld
def test_tld_risk_known_and_forms():
    assert L.tld_risk("top") == pytest.approx(1.2)
    assert L.tld_risk(".TOP") == pytest.approx(1.2)
    assert L.tld_risk("evil.top") == pytest.approx(1.2)
    assert L.tld_risk("zip") is not None and L.tld_risk("mov") is not None
    for t in ("tk", "ml", "ga", "cf", "gq", "pw", "xyz", "shop", "icu", "cfd", "sbs"):
        assert L.tld_risk(t) is not None, t


def test_tld_risk_unknown_and_garbage():
    assert L.tld_risk("com") is None
    assert L.tld_risk("") is None
    assert L.tld_risk(None) is None
    assert L.tld_risk("exa mple") is None


def test_tld_data_integrity():
    table = load_yaml("tlds.yaml")["tlds"]
    assert len(table) >= 60
    for tld, spec in table.items():
        assert 0.3 <= spec["risk"] <= 1.5, tld
        assert spec["note"], tld
        assert spec["tier"] in {"free", "cheap", "gtld", "confusing"}


# --------------------------------------------------------------------------- lots
@pytest.mark.parametrize(
    "host,kind",
    [
        ("evil.pages.dev", "serverless"),
        ("a.b.workers.dev", "serverless"),
        ("pages.dev", "serverless"),
        ("x.web.app", "hosting"),
        ("sites.google.com", "site_builder"),
        ("bucket.blob.core.windows.net", "storage"),
        ("x.ngrok-free.app", "tunnel"),
        ("ipfs.io", "ipfs"),
        ("x.trycloudflare.com", "tunnel"),
        ("telegra.ph", "blog"),
        ("pub-123.r2.dev", "storage"),
        ("forms.gle", "forms"),
        ("tenant.sharepoint.com", "file_share"),
    ],
)
def test_lots_match_hits(host, kind):
    e = L.lots_match(host)
    assert e is not None and e.kind == kind


@pytest.mark.parametrize(
    "host",
    [
        "evilpages.dev",
        "pages.dev.evil.test",
        "notpages.dev",
        "xworkers.dev",
        "github.io.evil.test",
        "",
        None,
        "paypal.com",
        "1.2.3.4",
        "a..b.pages.dev",
    ],
)
def test_lots_match_boundary_safe(host):
    assert L.lots_match(host) is None


def test_lots_case_port_trailing_dot_idna():
    assert L.lots_match("EVIL.Pages.DEV.") is not None
    assert L.lots_match("evil.pages.dev:8443") is not None
    assert L.lots_match("evil.pages.dev:abc") is None
    assert L.lots_match("x" * 300 + ".pages.dev") is None


def test_lots_path_restricted_entries():
    assert L.lots_match("www.dropbox.com", "/scl/fi/abc/file.pdf").path == "/scl"
    assert L.lots_match("www.dropbox.com", "/sclerosis") is None
    assert L.lots_match("www.dropbox.com", "/") is None
    assert L.lots_match("docs.google.com", "/forms/d/e/x").kind == "forms"
    assert L.lots_match("docs.google.com", "/document/d/x").kind == "docs"
    assert L.lots_match("docs.google.com", "/formsabc").kind == "docs"
    assert L.lots_match("docs.google.com", "/FORMS/d/e").kind == "forms"
    assert L.lots_match("docs.google.com", "/forms?x=1#y").kind == "forms"


def test_lots_most_specific_suffix_wins():
    assert L.lots_match("x.s3.amazonaws.com").match == "s3.amazonaws.com"
    assert L.lots_match("x.firebasestorage.googleapis.com").kind == "storage"
    fb = L.lots_match("x.firebasestorage.googleapis.com")
    assert fb is not None and fb.match == "firebasestorage.googleapis.com"


def test_lots_data_integrity():
    data = load_yaml("lots.yaml")["entries"]
    assert len(data) >= 120
    seen = set()
    required = [
        "pages.dev",
        "workers.dev",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "netlify.app",
        "vercel.app",
        "github.io",
        "gitlab.io",
        "glitch.me",
        "repl.co",
        "herokuapp.com",
        "onrender.com",
        "fly.dev",
        "azurewebsites.net",
        "blob.core.windows.net",
        "storage.googleapis.com",
        "firebasestorage.googleapis.com",
        "sites.google.com",
        "forms.gle",
        "1drv.ms",
        "forms.office.com",
        "sharepoint.com",
        "weebly.com",
        "wixsite.com",
        "webflow.io",
        "notion.site",
        "canva.site",
        "ipfs.io",
        "dweb.link",
        "w3s.link",
        "ngrok-free.app",
        "trycloudflare.com",
        "loca.lt",
        "serveo.net",
        "telegra.ph",
        "r2.dev",
    ]
    for e in data:
        assert e["kind"] in L.LOTS_KINDS
        key = (e["match"], e.get("path", ""))
        assert key not in seen, f"duplicate {key}"
        seen.add(key)
    for r in required:
        assert L.lots_match(r) is not None, r
    assert L.lots_match("dropbox.com", "/scl/x") is not None
    kinds = {e["kind"] for e in data}
    assert kinds == L.LOTS_KINDS


# --------------------------------------------------------------------------- shorteners etc.
def test_shorteners():
    assert L.is_shortener("bit.ly") and L.is_shortener("BIT.LY.")
    assert L.is_shortener("www.tinyurl.com")
    assert not L.is_shortener("notbit.ly")
    assert not L.is_shortener("bit.ly.evil.test")
    assert not L.is_shortener("") and not L.is_shortener(None)
    assert len(load_yaml("shorteners.yaml")["domains"]) >= 150


def test_dyndns():
    assert L.is_dyndns("evil.duckdns.org")
    assert L.is_dyndns("x.ddns.net") and L.is_dyndns("a.b.hopto.org")
    assert L.is_dyndns("x.afraid.org") and L.is_dyndns("x.dynu.net")
    assert not L.is_dyndns("notduckdns.org")
    assert not L.is_dyndns("duckdns.org.evil.test")
    assert not L.is_dyndns("example.com")


def test_freemail():
    for d in (
        "gmail.com",
        "QQ.com",
        "163.com",
        "naver.com",
        "mail.ru",
        "yandex.com",
        "gmx.de",
        "web.de",
        "proton.me",
        "rediffmail.com",
        "outlook.com",
        "user@gmail.com",
    ):
        assert L.is_freemail(d), d
    assert not L.is_freemail("gmail.com.evil.test")
    assert not L.is_freemail("mygmail.com")
    assert not L.is_freemail("x.gmail.com")
    assert not L.is_freemail("example.com")
    assert not L.is_freemail("")


def test_disposable():
    lines = load_lines("disposable_domains.txt.gz")
    assert len(lines) > 5000
    assert L.is_disposable("mailinator.com")
    assert L.is_disposable("someone@mailinator.com")
    assert L.is_disposable("x.mailinator.com")
    assert not L.is_disposable("zzzmailinator.com")
    assert not L.is_disposable("mailinator.com.evil.test")
    assert not L.is_disposable("gmail.com")
    assert not L.is_disposable(None)


# --------------------------------------------------------------------------- open redirects
def test_open_redirect_google_url():
    r = L.open_redirect_match("www.google.com", "/url", "sa=t&q=https%3A%2F%2Fevil.test%2Fx&usg=1")
    assert r is not None and r.destination == "https://evil.test/x"
    assert r.params == ("q", "url")


def test_open_redirect_google_search_term_not_a_destination():
    r = L.open_redirect_match("google.com", "/url", "q=paypal+login")
    assert r is not None and r.destination is None


def test_open_redirect_leading_question_mark_and_url_fallback_param():
    r = L.open_redirect_match("google.com", "/url", "?url=http%3A%2F%2Fevil.test%2F")
    assert r.destination == "http://evil.test/"


def test_open_redirect_boundaries():
    assert L.open_redirect_match("evilgoogle.com", "/url", "q=https://x.test") is None
    assert L.open_redirect_match("google.com", "/urlx", "q=https://x.test") is None
    assert L.open_redirect_match("google.com", "/search", "q=https://x.test") is None
    assert L.open_redirect_match("google.com.evil.test", "/url", "q=https://x.test") is None
    assert L.open_redirect_match("", "/url", "") is None


def test_open_redirect_bing_base64():
    dest = "https://evil.test/login?a=1"
    token = "a1" + base64.urlsafe_b64encode(dest.encode()).decode().rstrip("=")
    r = L.open_redirect_match("www.bing.com", "/ck/a", f"!&&p=abc&u={token}&ntb=1")
    assert r is not None and r.destination == dest
    bad = L.open_redirect_match("bing.com", "/ck/a", "u=a1!!!notbase64")
    assert bad is not None and bad.destination is None


def test_open_redirect_youtube_facebook_safelinks():
    yt = L.open_redirect_match("youtube.com", "/redirect", "q=https%3A%2F%2Fevil.test")
    assert yt is not None and yt.destination == "https://evil.test"
    assert (
        L.open_redirect_match(
            "l.facebook.com", "/l.php", "u=http%3A%2F%2Fevil.test%2F&h=1"
        ).destination
        == "http://evil.test/"
    )
    r = L.open_redirect_match(
        "eur01.safelinks.protection.outlook.com", "/", "url=https%3A%2F%2Fevil.test%2Fa&data=x"
    )
    assert r is not None and r.destination == "https://evil.test/a"


def test_open_redirect_t_co_is_opaque():
    r = L.open_redirect_match("t.co", "/AbCd123", "")
    assert r is not None and r.destination is None and r.encoding == "opaque"


def test_open_redirect_proofpoint_v2_v3():
    r = L.open_redirect_match(
        "urldefense.proofpoint.com", "/v2/url", "u=https-3A__evil.test_a-3Fb-3D1&d=x&c=y"
    )
    assert r is not None and r.destination == "https://evil.test/a?b=1"
    r3 = L.open_redirect_match("urldefense.com", "/v3/__https://evil.test/a__;!!abc$")
    assert r3 is not None and r3.destination == "https://evil.test/a"


def test_open_redirect_pathtail_awstrack():
    r = L.open_redirect_match("abc.awstrack.me", "/L0/https:%2F%2Fevil.test%2Fx/1/000/abc-0")
    assert r is not None and r.destination == "https://evil.test/x"


def test_open_redirect_rejects_non_http_destinations():
    for q in (
        "q=javascript%3Aalert(1)",
        "q=data%3Atext%2Fhtml%2Cx",
        "q=%2F%2Fevil.test",
        "q=https%3A%2F%2Fevil.test%2F%0Ax",
    ):
        r = L.open_redirect_match("google.com", "/url", q)
        assert r is not None and r.destination is None, q


def test_open_redirect_hostile_query_bounded():
    q = "&".join(f"a{i}=1" for i in range(500)) + "&q=https%3A%2F%2Fevil.test"
    r = L.open_redirect_match("google.com", "/url", q)
    assert r is not None  # does not raise; too many fields -> no destination
    assert r.destination is None
    big = "q=https%3A%2F%2F" + "a" * 100_000
    assert L.open_redirect_match("google.com", "/url", big).destination is None


def test_open_redirect_data_integrity():
    data = load_yaml("open_redirects.yaml")["entries"]
    assert len(data) >= 25
    for e in data:
        assert e["name"] and e["match"] == e["match"].lower()
        assert e.get("encoding", "url") in {
            "url",
            "base64url",
            "pathtail",
            "proofpoint_v2",
            "proofpoint_v3",
            "opaque",
        }
    probes = [
        ("google.com", "/url"),
        ("bing.com", "/ck/a"),
        ("youtube.com", "/redirect"),
        ("t.co", "/x"),
        ("l.facebook.com", "/l.php"),
        ("x.safelinks.protection.outlook.com", "/"),
        ("urldefense.com", "/v3/__x__;"),
    ]
    for host, path in probes:
        assert L.open_redirect_match(host, path) is not None, host


# --------------------------------------------------------------------------- lures
def terms(text, **kw):
    return [(h.term, h.lang) for h in L.find_lures(text, **kw)]


def test_lures_english_tokens_in_url():
    hits = L.find_lures("secure-login.paypal-verify.example.test/account/update")
    got = {h.term for h in hits}
    assert {"secure", "login", "verify", "account"} <= got
    for h in hits:
        assert h.weight > 0


def test_lures_spans_index_original_text():
    text = "https://evil.test/Verify-Account"
    hits = L.find_lures(text)
    assert [text[h.start : h.end] for h in hits] == ["Verify", "Account"]


def test_lures_token_aware_latin():
    assert not L.find_lures("syntax taxonomy bankrupt")
    assert [h.term for h in L.find_lures("tax-refund")] == ["tax", "refund"]
    assert not any(h.term == "pay" for h in L.find_lures("repayment spayed"))


def test_lures_phrase_and_separators():
    for t in ("log-in", "log_in", "log in", "LOG.IN"):
        assert any(h.term in ("log in", "log-in") for h in L.find_lures(t)), t


def test_lures_compound_discounted():
    plain = {h.term: h for h in L.find_lures("login")}["login"]
    comp = [h for h in L.find_lures("securelogin-paypal") if h.term == "login"]
    assert comp and comp[0].partial and comp[0].weight < plain.weight
    assert comp[0].start == 6 and comp[0].end == 11


@pytest.mark.parametrize(
    "text,term,lang",
    [
        ("https://example.test/iniciar-sesion/verificar-cuenta", "cuenta", "es"),
        ("mensagem: sua conta foi suspensa, atualize", "suspensa", "pt"),
        ("votre colis est en attente de livraison", "livraison", "fr"),
        ("Ihr Konto wurde gesperrt", "gesperrt", "de"),
        ("il tuo pacco è in giacenza", "pacco", "it"),
        ("Twoje konto zostało zablokowane", "konto", "pl"),
        ("ваш аккаунт заблокирован, подтвердите", "заблокирован", "ru"),
        ("ваш акаунт заблоковано", "заблоковано", "uk"),
        ("hesabınız doğrulanmalı", "hesab", "tr"),
        ("تم تعليق حسابك", "تم تعليق", "ar"),
        ("حساب شما مسدود شد", "مسدود", "fa"),
        ("आपका खाता निलंबित है", "निलंबित", "hi"),
        ("aapka account band ho jayega turant kyc karein", "turant", "hi-Latn"),
        ("আপনার অ্যাকাউন্ট স্থগিত", "স্থগিত", "bn"),
        ("உங்கள் கணக்கு இடைநிறுத்தம்", "இடைநிறுத்தம்", "ta"),
        ("您的账户已冻结请立即验证", "冻结", "zh-Hans"),
        ("您的帳戶已凍結", "凍結", "zh-Hant"),
        ("お客様のアカウントは利用制限されました", "アカウント", "ja"),
        ("계정이 정지되었습니다", "정지", "ko"),
        ("tài khoản của bạn bị khóa", "bị khóa", "vi"),
        ("akun anda diblokir segera verifikasi", "diblokir", "id"),
        ("บัญชีของคุณถูกระงับ", "ถูกระงับ", "th"),
        ("akaunti yako imezuiwa", "imezuiwa", "sw"),
        ("na-block ang iyong account, mag-login", "na-block", "tl"),
    ],
)
def test_lures_multilingual(text, term, lang):
    hits = [h for h in L.find_lures(text) if h.term == term]
    assert hits, f"{term!r} not found in {text!r}: {terms(text)}"
    data = load_yaml("lures.yaml")["languages"][lang]
    listed = {(i["t"] if isinstance(i, dict) else i) for items in data.values() for i in items}
    assert term in listed  # the term really belongs to the language under test


def test_lures_cover_required_languages():
    required = {
        "es",
        "pt",
        "fr",
        "de",
        "it",
        "nl",
        "pl",
        "ru",
        "uk",
        "tr",
        "ar",
        "fa",
        "hi",
        "hi-Latn",
        "bn",
        "ta",
        "zh-Hans",
        "zh-Hant",
        "ja",
        "ko",
        "vi",
        "id",
        "th",
        "sw",
        "tl",
        "en",
        "und",
    }
    assert required <= L.lure_languages()
    assert len(L.lure_languages()) >= 26


def test_lures_required_english_concepts_present():
    must = [
        "login",
        "signin",
        "verify",
        "account",
        "update",
        "secure",
        "unlock",
        "suspended",
        "invoice",
        "payment",
        "password",
        "auth",
        "sso",
        "mfa",
        "2fa",
        "recovery",
        "wallet",
        "billing",
        "refund",
        "delivery",
        "parcel",
        "tax",
        "kyc",
    ]
    for w in must:
        assert any(h.term == w for h in L.find_lures(w)), w


def test_lures_accent_stripped_variants():
    assert any(h.term == "vérifier" for h in L.find_lures("verifier-compte"))
    assert any(h.term == "contraseña" for h in L.find_lures("contrasena-olvidada"))
    assert any(h.term == "contraseña" for h in L.find_lures("tu contraseña"))


def test_lures_no_double_count_overlap():
    hits = L.find_lures("verification code")
    assert [h.term for h in hits] == ["verification code"]


def test_lures_length_changing_lowercase_keeps_offsets():
    text = "İİİ login"  # 'İ'.lower() is two code points
    hits = [h for h in L.find_lures(text) if h.term == "login"]
    assert hits and text[hits[0].start : hits[0].end] == "login"


def test_lures_max_chars_and_max_hits():
    text = "login " * 1000
    assert len(L.find_lures(text, max_hits=10)) == 10
    assert L.find_lures("x" * 100 + " login", max_chars=50) == []
    assert L.find_lures("") == [] and L.find_lures(None) == []


def test_lures_data_integrity():
    data = load_yaml("lures.yaml")
    cw = data["category_weights"]
    langs = data["languages"]
    assert len(langs) >= 28
    total = 0
    for lang, cats in langs.items():
        for cat, items in cats.items():
            assert cat in cw
            for it in items:
                t = it["t"] if isinstance(it, dict) else it
                assert t == t.strip().lower() and t
                total += 1
    assert total > 800
    # Each of the 25 spec'd languages has credential and account coverage.
    for lang in (
        "es",
        "pt",
        "fr",
        "de",
        "it",
        "nl",
        "pl",
        "ru",
        "uk",
        "tr",
        "ar",
        "fa",
        "hi",
        "bn",
        "ta",
        "zh-Hans",
        "zh-Hant",
        "ja",
        "ko",
        "vi",
        "id",
        "th",
        "sw",
        "tl",
    ):
        assert langs[lang].get("credential") and langs[lang].get("account"), lang


def _cpu(fn, *args, **kw) -> float:
    start = time.process_time()
    fn(*args, **kw)
    return time.process_time() - start


def _machine_slowdown() -> float:
    """CPU-time slowdown vs. an idle ~3 GHz core (shared CI boxes can be heavily loaded)."""

    def spin() -> int:
        s = 0
        for i in range(500_000):
            s += i
        return s

    return max(1.0, min(_cpu(spin) for _ in range(3)) / 0.025)


def test_find_lures_performance_100kb():
    slow = _machine_slowdown()
    unit = (
        "Quarterly report for the engineering team. Shipping milestones moved, the roadmap "
        "review is on Thursday. See docs at example.test/wiki/page-name?id=4 for details. "
        "Please login to verify your account. "
    )
    typical = (unit * (100_000 // len(unit) + 1))[:100_000]
    dense = (
        (
            "Dear customer please login to verify your account password at "
            "secure-update.example.test/billing?x=tax_refund and the parcel delivery. "
        )
        * 1000
    )[:100_000]
    cjk = ("您的账户已冻结请立即验证登录 お客様のアカウント 계정이 정지 ввод пароль " * 4000)[
        :100_000
    ]
    L.find_lures("warm up login")  # build the index outside the timed region

    # Best-of-three: a single sample is at the mercy of a GC pause or scheduler
    # preemption on a shared CI box, so take the fastest run (what the code can
    # actually achieve) instead of whichever one a transient spike landed on.
    def best(*args, **kw) -> float:
        return min(_cpu(L.find_lures, *args, **kw) for _ in range(3))

    assert best(typical) < 0.05 * slow  # spec: <50ms/100KB
    for text in (dense, cjk):  # pathological density
        assert best(text, max_hits=10_000) < 0.5 * slow
    for text in ("a" * 100_000, "login" * 20_000, "-" * 100_000, "\u4f60" * 100_000):
        assert best(text) < 0.1 * slow


def test_find_lures_scales_linearly():
    L.find_lures("warm")
    unit = "verify-your-account login password refund parcel example.test/path " * 100
    small = min(_cpu(L.find_lures, unit * 5, max_hits=100_000) for _ in range(3))
    big = min(_cpu(L.find_lures, unit * 20, max_hits=100_000) for _ in range(3))
    assert big < small * 12  # 4x input; allow noise, forbid quadratic (16x)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=300))
def test_find_lures_never_raises_and_spans_valid(text):
    for h in L.find_lures(text):
        assert 0 <= h.start < h.end <= len(text)
        assert h.weight > 0


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=100), st.text(max_size=100), st.text(max_size=100))
def test_matchers_never_raise_on_arbitrary_input(host, path, query):
    L.lots_match(host, path)
    L.open_redirect_match(host, path, query)
    L.is_shortener(host)
    L.is_dyndns(host)
    L.is_freemail(host)
    L.is_disposable(host)
    L.tld_risk(host)
    L.top_rank(host)


# --------------------------------------------------------------------------- top sites
def test_top_rank():
    assert L.top_rank("google.com") == 1
    assert L.top_rank("GOOGLE.COM.") == 1
    assert L.top_rank("definitely-not-a-top-site.test") is None
    assert L.top_rank("www.google.com") is None  # caller passes the registrable domain
    assert L.top_rank("") is None and L.top_rank(None) is None
    assert L.is_top_site("google.com", 1)
    assert not L.is_top_site("google.com", 0)
    ranks = [L.top_rank(d) for d in ("microsoft.com", "paypal.com")]
    assert all(r is not None for r in ranks)
    assert L.is_top_site("paypal.com", 100_000)


def test_top_sites_data_integrity():
    lines = load_lines("top_sites.txt.gz")
    assert len(lines) == 100_000
    assert len(set(lines)) == len(lines)
    assert all(d == d.lower() and " " not in d and "," not in d for d in lines[:2000])
    raw = gzip.decompress(asset_path("top_sites.txt.gz").read_bytes()).decode()
    assert raw.startswith("# Tranco")


def test_disposable_and_top_sites_do_not_overlap():
    top = set(load_lines("top_sites.txt.gz")[:2000])
    overlap = {d for d in top if L.is_disposable(d)}
    assert not overlap, overlap


def test_freemail_not_disposable_overlap():
    for d in load_yaml("freemail.yaml")["global"]:
        assert not L.is_disposable(d), d


def test_readme_documents_sources():
    readme = asset_path("README.md").read_text(encoding="utf-8")
    for needle in (
        "Tranco",
        "disposable-email-domains",
        "Spamhaus",
        "Interisle",
        "tlds.yaml",
        "lots.yaml",
        "lures.yaml",
        "open_redirects.yaml",
    ):
        assert needle in readme, needle
