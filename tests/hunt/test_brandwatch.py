"""Tests for BrandWatch: offline ranking, mocked liveness, persistence (no network)."""

from __future__ import annotations

import asyncio
import socket

import pytest

from uniphish.hunt.brandwatch import KIND_PRIOR, BrandWatch, Candidate
from uniphish.hunt.permutations import Permutation, generate_permutations
from uniphish.store import Store


@pytest.fixture(scope="module")
def watch_paypal() -> list[Candidate]:
    return BrandWatch().watch("paypal.com", deep_limit=40)


def rank_of(cands: list[Candidate], domain: str) -> int:
    return [c.domain for c in cands].index(domain)


def by_domain(cands):
    return {c.domain: c for c in cands}


def test_obvious_lookalikes_outrank_noise(watch_paypal):
    d = by_domain(watch_paypal)
    for good in ("paypa1.com", "xn--pypal-4ve.com", "paypal-secure.com", "paypal-login.com"):
        assert d[good].score >= 60, good
    for noise in ("paypalq.com", "wwwpaypal.com", "paypal.co", "paypal.io"):
        assert d[noise].score <= 45, noise
        assert rank_of(watch_paypal, "paypa1.com") < rank_of(watch_paypal, noise)
        assert rank_of(watch_paypal, "xn--pypal-4ve.com") < rank_of(watch_paypal, noise)
    top = watch_paypal[:25]
    assert all(c.kind in {"homoglyph", "idn_homograph", "combosquat", "typo"} for c in top)


def test_sorted_best_first_and_excludes_original(watch_paypal):
    scores = [c.score for c in watch_paypal]
    assert scores == sorted(scores, reverse=True)
    assert "paypal.com" not in {c.domain for c in watch_paypal}
    assert all(0 <= c.score <= 100 for c in watch_paypal)


def test_candidate_details():
    bw = BrandWatch()
    brand, _ = bw.resolve_target("paypal.com")
    c = bw.score_permutations(
        [Permutation("xn--pypal-4ve.com", "homoglyph")], "paypal.com", brand=brand
    )[0]
    assert c.display == "pаypal.com"
    assert c.brand == "paypal" and c.target == "paypal.com"
    assert "punycode" in c.techniques and "homoglyph" in c.techniques
    assert "T1583.001" in c.mitre
    assert c.live is None and c.ips == ()
    assert c.deep and c.technique == "homoglyph" and c.confidence > 0.9
    data = c.to_dict()
    assert data["domain"] == c.domain and data["reasons"]


def test_abused_tld_raises_tld_swap_score(watch_paypal):
    d = by_domain(watch_paypal)
    assert d["paypal.tk"].score > d["paypal.io"].score
    assert "suspicious_tld" in d["paypal.tk"].techniques


def test_other_brands_official_domains_are_dropped():
    bw = BrandWatch()
    perms = [Permutation("paypal.me", "tld_swap"), Permutation("paypa1.com", "homoglyph")]
    out = bw.score_permutations(perms, "paypal.com")
    assert [c.domain for c in out] == ["paypa1.com"]  # paypal.me is PayPal's own


def test_popular_site_scores_zero():
    bw = BrandWatch()
    # google.com is a top site: a "permutation" landing on it is not a look-alike
    out = bw.score_permutations([Permutation("netflix.com", "tld_swap")], "netflux.test")
    assert out == [] or out[0].score == 0


def test_filters_limit_and_min_score():
    bw = BrandWatch()
    out = bw.watch("paypal.com", deep_limit=0, min_score=60, limit=10)
    assert len(out) == 10 and all(c.score >= 60 for c in out)


def test_resolve_brand_and_domain_targets():
    bw = BrandWatch()
    brand, domains = bw.resolve_target("paypal")
    assert brand and brand.id == "paypal" and domains[0] == "paypal.com"
    assert len(domains) <= 3
    brand, domains = bw.resolve_target("https://www.paypal.com/signin")
    assert brand and brand.id == "paypal" and domains == ["paypal.com"]
    brand, domains = bw.resolve_target("acme-widgets.example")
    assert brand is None and domains == ["acme-widgets.example"]
    for bad in ("", "no-such-brand-xyz"):
        with pytest.raises(ValueError):
            bw.resolve_target(bad)


def test_unknown_domain_still_ranks_homoglyphs_first():
    out = BrandWatch().watch("acme-widgets.example", deep_limit=10, limit=30)
    assert out and out[0].brand is None
    assert out[0].kind in {"homoglyph", "idn_homograph"}


def test_monitor_brand_uses_official_domains():
    bw = BrandWatch()
    out = bw.monitor_brand("paypal", max_domains=1, limit=50, deep_limit=5)
    assert out and len(out) <= 50 and all(c.score >= 40 for c in out)
    assert {c.target for c in out} == {"paypal.com"}
    with pytest.raises(ValueError):
        bw.monitor_brand("nope-not-a-brand")


def test_multi_domain_watch_merges_without_duplicates():
    out = BrandWatch().watch("paypal", max_domains=2, max_permutations=200, deep_limit=0)
    doms = [c.domain for c in out]
    assert len(doms) == len(set(doms))
    assert len({c.target for c in out}) == 2


# ---------------------------------------------------------------- liveness (mocked)
def make_resolver(live: dict[str, list[str]], calls: list[str] | None = None):
    async def resolver(host: str, rdtype: str, timeout: float) -> list[str]:
        if calls is not None:
            calls.append(f"{host}/{rdtype}")
        if rdtype != "A":
            return []
        return live.get(host, [])

    return resolver


@pytest.fixture(scope="module")
def base_candidates() -> list[Candidate]:
    return BrandWatch().watch("paypal.com", deep_limit=0)


def test_live_candidates_score_higher_and_dead_lower(base_candidates):
    live = {"paypal.tk": ["93.184.216.34"], "paypal-secure.com": ["93.184.216.34"]}
    before = by_domain(base_candidates)
    bw = BrandWatch(resolver=make_resolver(live))
    out = asyncio.run(bw.check_live(base_candidates, max_checks=500))
    after = by_domain(out)
    for dom in live:
        assert after[dom].live is True
        assert after[dom].ips == ("93.184.216.34",)
        assert after[dom].score >= before[dom].score
        assert after[dom].score > before[dom].score or before[dom].score == 100
    dead = after["paypa1.com"]
    assert dead.live is False and dead.score < before["paypa1.com"].score
    assert "does not resolve" in dead.reasons[-1]
    scores = [c.score for c in out]
    assert scores == sorted(scores, reverse=True)


def test_live_low_prior_can_overtake_dead_high_prior():
    bw = BrandWatch(resolver=make_resolver({"paypal.io": ["93.184.216.34"]}))
    cands = bw.watch("paypal.com", deep_limit=0, kinds=["tld_swap", "typo"])
    out = asyncio.run(bw.check_live(cands))
    d = by_domain(out)
    assert d["paypal.io"].live and d["paypal.io"].score > d["paypql.com"].score


def test_private_answers_do_not_count_as_live(base_candidates):
    bw = BrandWatch(resolver=make_resolver({"paypal.tk": ["10.0.0.5"]}))
    tk = by_domain(base_candidates)["paypal.tk"]
    out = asyncio.run(bw.check_live([*base_candidates[:5], tk]))
    assert by_domain(out)["paypal.tk"].live is False


def test_max_checks_bounds_lookups(base_candidates):
    calls: list[str] = []
    bw = BrandWatch(resolver=make_resolver({}, calls))
    out = asyncio.run(bw.check_live(base_candidates, max_checks=7))
    assert len({c.split("/")[0] for c in calls}) == 7
    assert sum(c.live is False for c in out) == 7
    assert sum(c.live is None for c in out) == len(base_candidates) - 7


def test_resolver_failure_is_tolerated(base_candidates):
    async def boom(host, rdtype, timeout):
        raise RuntimeError("resolver down")

    out = asyncio.run(BrandWatch(resolver=boom).check_live(base_candidates[:5]))
    assert len(out) == 5 and all(c.live is False or c.live is None for c in out)


def test_check_live_scores_bare_permutations_with_target():
    perms = generate_permutations("paypal.com", kinds=["tld_swap"], max=10)
    bw = BrandWatch(resolver=make_resolver({perms[0].domain: ["93.184.216.34"]}))
    out = asyncio.run(bw.check_live(perms, target="paypal.com"))
    assert len(out) == len(perms) and out[0].domain == perms[0].domain and out[0].live
    with pytest.raises(ValueError):
        asyncio.run(bw.check_live(perms))


def test_watch_live_end_to_end():
    bw = BrandWatch(resolver=make_resolver({"paypa1.com": ["93.184.216.34"]}))
    out = asyncio.run(bw.watch_live("paypal.com", max_checks=50, limit=5, deep_limit=0))
    assert len(out) == 5 and out[0].domain == "paypa1.com" and out[0].live


def test_no_real_network_used_by_default(base_candidates, monkeypatch):
    # conftest blocks DNS; with the default resolver the sweep must fail soft, not raise
    def blocked(*a, **k):
        raise AssertionError("real DNS lookup attempted")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    out = asyncio.run(BrandWatch(resolver=make_resolver({})).check_live(base_candidates[:3]))
    assert len(out) == 3


# ---------------------------------------------------------------- persistence + engine
def test_persist_records_hunt_events_and_dedupes():
    store = Store(":memory:")
    bw = BrandWatch(store=store)
    cands = bw.watch("paypal.com", deep_limit=5, limit=40)
    n = bw.persist(cands, min_score=60)
    assert n > 0
    events = store.recent_hunt_events(limit=1000, brand="paypal")
    assert len(events) == n
    ev = next(e for e in events if e["domain"] == "paypa1.com")
    assert ev["source"] == "brandwatch" and ev["score"] >= 60
    assert "homoglyph" in ev["techniques"]
    assert bw.persist(cands, min_score=60) == 0  # idempotent
    assert bw.persist(cands, min_score=60, only_live=True) == 0


def test_watch_persist_flag_and_only_live():
    store = Store(":memory:")
    bw = BrandWatch(store=store, resolver=make_resolver({"paypa1.com": ["93.184.216.34"]}))
    out = asyncio.run(bw.watch_live("paypal.com", max_checks=30, deep_limit=0, limit=30))
    assert bw.persist(out, min_score=0, only_live=True) == 1
    assert [e["domain"] for e in store.recent_hunt_events()] == ["paypa1.com"]


def test_persist_uses_shared_store_by_default():
    from uniphish.store import get_store, reset_store

    try:
        bw = BrandWatch()
        n = bw.persist(bw.watch("paypal.com", deep_limit=0, limit=5), min_score=1)
        assert n == len(get_store().recent_hunt_events(limit=100))
    finally:
        reset_store()


def test_verify_requires_engine_and_merges_verdict(base_candidates):
    with pytest.raises(RuntimeError):
        asyncio.run(BrandWatch().verify(base_candidates))

    class FakeVerdict:
        score, id = 99, "v-1"

    class FakeEngine:
        async def analyze_url(self, url, **opts):
            assert url.startswith("https://")
            return FakeVerdict()

    bw = BrandWatch(engine=FakeEngine(), resolver=make_resolver({"paypal.tk": ["93.184.216.34"]}))
    live = asyncio.run(bw.check_live(base_candidates))
    out = asyncio.run(bw.verify(live, top=3))
    d = by_domain(out)
    assert d["paypal.tk"].verdict_score == 99 and d["paypal.tk"].score == 99
    assert sum(c.verdict_id is not None for c in out) == 1  # only live ones verified


def test_kind_priors_are_sane():
    assert KIND_PRIOR["idn_homograph"] > KIND_PRIOR["combosquat"] > KIND_PRIOR["addition"]
    assert all(0 < v < 1 for v in KIND_PRIOR.values())
