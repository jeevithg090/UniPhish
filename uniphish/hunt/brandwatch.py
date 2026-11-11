"""Brand watch: rank look-alikes of a protected domain / brand and find the live ones.

:class:`BrandWatch` is the defensive counterpart of the CT firehose: instead of waiting
for an attacker's certificate to appear, it enumerates the look-alikes of *your own*
domains (:mod:`uniphish.hunt.permutations`), scores each one offline as a potential
impersonation, optionally resolves them to see which already exist, and persists the
interesting ones as ``hunt_events`` in the store.

Scoring (0-100, :attr:`Candidate.score`)
----------------------------------------
Scores are hand-set priors, not a fitted probability.  Stage 1 (cheap, every candidate)
starts from a per-kind prior (:data:`KIND_PRIOR`: homoglyph / IDN homograph 0.85-0.90,
combosquat with a credential keyword 0.60-0.70, keyboard typo 0.50, random appended
letter 0.30 ...), lifts it to 0.90 when the candidate's confusable skeleton equals the
protected label, adds up to +25% of the remaining headroom for an abused TLD (from
``tlds.yaml``) and damps typo-class kinds on very short labels (too many innocent
neighbours).  Another brand's official domain is dropped; a popular site (Tranco top 20k)
keeps score 0.  Stage 2 (``deep_limit`` best candidates, ~80 ms each) re-runs the full
:func:`uniphish.url.brands.brand_impersonation` and :func:`uniphish.url.techniques.classify`
and can only *raise* the score.  Live checking (:meth:`BrandWatch.check_live`) adds +15 to
candidates that resolve and scales ones that demonstrably do not by 0.7.

Resolution goes through :mod:`uniphish.core.net` (public addresses only).  Calling
``check_live`` is the explicit consent to touch DNS; nothing else here does network I/O.
A resolving domain proves registration, not malice: wildcard zones and parked domains
resolve too, so a live hit is a lead for review, not a verdict.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from uniphish.assets.lists import tld_risk, top_rank
from uniphish.core.net import Resolver, is_public_ip, resolve_ips
from uniphish.hunt.permutations import (
    DEFAULT_MAX,
    Permutation,
    generate_permutations,
    split_domain,
)
from uniphish.url.brandkb import Brand, BrandKB, BrandKBError, get_kb
from uniphish.url.brands import brand_candidates, split_host
from uniphish.url.confusables import brand_skeleton
from uniphish.url.parse import parse_url
from uniphish.url.techniques import classify

if TYPE_CHECKING:
    from uniphish.core.engine import Engine
    from uniphish.store import Store

log = logging.getLogger("uniphish.hunt")

__all__ = ["KIND_PRIOR", "BrandWatch", "Candidate", "SOURCE"]

SOURCE = "brandwatch"
_POPULAR_RANK = 20_000
_LIVE_BONUS = 15
_DEAD_FACTOR = 0.7
_DEFAULT_DEEP = 30
_DEFAULT_LIVE_CHECKS = 500
_CREDENTIAL_KEYWORDS = frozenset({
    "login", "signin", "secure", "security", "verify", "account", "support", "update",
    "billing", "wallet", "portal", "id", "help", "official",
})

#: Prior probability that a candidate of this kind is a deliberate impersonation.
KIND_PRIOR: dict[str, float] = {
    "idn_homograph": 0.90, "homoglyph": 0.85, "combosquat": 0.60, "bitsquat": 0.45,
    "typo": 0.50, "hyphenation": 0.55, "subdomain": 0.45, "tld_swap": 0.35,
    "omission": 0.45, "double_char": 0.40, "vowel_swap": 0.40, "addition": 0.30,
}
_KIND_TECHNIQUE = {
    "homoglyph": "homoglyph", "idn_homograph": "idn_homograph", "typo": "typosquat",
    "omission": "typosquat", "addition": "typosquat", "double_char": "typosquat",
    "vowel_swap": "typosquat", "hyphenation": "typosquat", "bitsquat": "typosquat",
    "combosquat": "combosquat", "subdomain": "subdomain_stuffing",
}
_TYPO_KINDS = frozenset({"typo", "omission", "addition", "double_char", "vowel_swap",
                         "bitsquat", "hyphenation"})


@dataclass(frozen=True, slots=True)
class Candidate:
    """A scored look-alike of a protected domain.

    ``live`` is ``None`` until :meth:`BrandWatch.check_live` has run, then ``True`` if
    the name resolved to a public address.  ``domain`` is the ASCII form; ``display`` the
    Unicode form a user would see.
    """

    domain: str
    display: str
    kind: str
    note: str
    target: str
    brand: str | None
    score: int
    technique: str | None = None
    confidence: float = 0.0
    techniques: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ("T1583.001",)
    reasons: tuple[str, ...] = ()
    live: bool | None = None
    ips: tuple[str, ...] = ()
    verdict_score: int | None = None
    verdict_id: str | None = None
    deep: bool = field(default=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation."""
        return {
            "domain": self.domain, "display": self.display, "kind": self.kind,
            "note": self.note, "target": self.target, "brand": self.brand,
            "score": self.score, "technique": self.technique,
            "confidence": round(self.confidence, 3), "techniques": list(self.techniques),
            "mitre": list(self.mitre), "reasons": list(self.reasons), "live": self.live,
            "ips": list(self.ips), "verdict_score": self.verdict_score,
            "verdict_id": self.verdict_id,
        }


def _rank_key(c: Candidate) -> tuple[Any, ...]:
    return (-c.score, 0 if c.live else 1, -c.confidence, c.domain)


def _clamp(p: float) -> float:
    return 0.0 if p < 0.0 else 1.0 if p > 1.0 else p


class BrandWatch:
    """Generate, rank, live-check and persist look-alikes of protected domains.

    ``engine`` (optional) enables :meth:`verify`, a full engine verdict for chosen
    candidates; ``store`` (optional) is where :meth:`persist` records ``hunt_events``
    (``get_store()`` is used when none was given).  Pure-compute methods never touch the
    network; ``resolver`` is a test / custom-DNS injection point for :meth:`check_live`.
    """

    def __init__(self, engine: Engine | None = None, store: Store | None = None, *,
                 resolver: Resolver | None = None) -> None:
        self.engine = engine
        self.store = store
        self.resolver = resolver
        try:
            self._kb: BrandKB = get_kb()
        except BrandKBError as exc:
            log.warning("brand KB unavailable for brand watch: %s", exc)
            self._kb = BrandKB([])

    # ------------------------------------------------------------------ targets #
    def resolve_target(self, domain_or_brand: str, *, max_domains: int = 3
                       ) -> tuple[Brand | None, list[str]]:
        """Map user input to ``(brand | None, domains to permute)``.

        A string containing a dot (or ``://``) is a domain; its owning brand is looked up
        in the KB.  Otherwise it is a brand id, name or alias and its first
        ``max_domains`` official domains are used.  Raises ``ValueError`` when nothing
        matches.
        """
        text = (domain_or_brand or "").strip()
        if not text:
            raise ValueError("watch needs a domain or a brand")
        if "." in text or "://" in text:
            sld, suffix = split_domain(text)
            domain = f"{sld}.{suffix}"
            return self._kb.official_brand_for_host(domain), [domain]
        key = text.casefold()
        brand = self._kb.get(key)
        if brand is None:
            for b in self._kb.all():
                if b.name.casefold() == key or key in {a.casefold() for a in b.aliases}:
                    brand = b
                    break
        if brand is None:
            raise ValueError(f"unknown brand {domain_or_brand!r}; pass a domain instead")
        domains: list[str] = []
        for d in brand.official_domains:
            try:
                sld, suffix = split_domain(d)
            except ValueError:
                continue
            dom = f"{sld}.{suffix}"
            if dom not in domains:
                domains.append(dom)
            if len(domains) >= max(1, int(max_domains)):
                break
        if not domains:
            raise ValueError(f"brand {brand.id!r} has no usable official domain")
        return brand, domains

    # ------------------------------------------------------------------ scoring #
    def score_permutations(self, perms: Iterable[Permutation], target: str, *,
                           brand: Brand | None = None, deep_limit: int = _DEFAULT_DEEP
                           ) -> list[Candidate]:
        """Score ``perms`` (look-alikes of ``target``) and return them ranked, best first.

        Candidates that are another brand's official domain are dropped.  ``brand`` is
        the protected brand (if any); it is used to prefer matches against that brand.
        """
        t_sld, _t_suffix = split_domain(target)
        t_skel = brand_skeleton(t_sld)
        stage1: list[Candidate] = []
        for perm in perms:
            cand = self._stage1(perm, target, t_sld, t_skel, brand)
            if cand is not None:
                stage1.append(cand)
        stage1.sort(key=_rank_key)
        n_deep = max(0, int(deep_limit))
        out: list[Candidate] = []
        for i, cand in enumerate(stage1):
            out.append(self._stage2(cand, brand) if i < n_deep and cand.score > 0 else cand)
        out.sort(key=_rank_key)
        return out

    def _stage1(self, perm: Permutation, target: str, t_sld: str, t_skel: str,
                brand: Brand | None) -> Candidate | None:
        try:
            parsed = parse_url("http://" + perm.domain)
            parts = split_host(parsed)
        except Exception as exc:  # parse_url should not raise; stay defensive
            log.debug("cannot parse permutation %r: %r", perm.domain, exc)
            return None
        owner = self._kb.official_brand_for_host(perm.domain)
        if owner is not None:
            return None                     # a legitimately owned domain, not a look-alike
        reasons = [f"{perm.kind}: {perm.note}" if perm.note else perm.kind]
        p = KIND_PRIOR.get(perm.kind, 0.3)
        if perm.kind == "combosquat":
            extra = {w for w in parts.sld.replace(t_sld, " ").replace("-", " ").split()}
            if extra & _CREDENTIAL_KEYWORDS:
                p = 0.70
                reasons.append("adds a credential / support keyword")
        if parts.sld != t_sld and brand_skeleton(parts.sld) == t_skel:
            if p < 0.90:
                reasons.append("confusable skeleton equals the protected label")
            p = max(p, 0.90)
        risk = tld_risk(parts.suffix)
        if risk is not None:
            p += (1.0 - p) * min(risk / 1.5, 1.0) * 0.25
            reasons.append(f"abused TLD .{parts.suffix.rsplit('.', 1)[-1]}")
        if perm.kind in _TYPO_KINDS and len(t_sld) <= 4:
            p *= 0.85
            reasons.append("short label: many innocent neighbours")
        rank = top_rank(parsed.registrable_domain)
        if rank is not None and rank <= _POPULAR_RANK:
            p = 0.0
            reasons.append(f"popular site (rank {rank}), unlikely to be impersonation")
        techniques = []
        if (t := _KIND_TECHNIQUE.get(perm.kind)):
            techniques.append(t)
        if risk is not None:
            techniques.append("suspicious_tld")
        if perm.domain.startswith("xn--") or ".xn--" in perm.domain:
            techniques.append("punycode")
        return Candidate(
            domain=perm.domain, display=perm.display, kind=perm.kind, note=perm.note,
            target=target, brand=brand.id if brand else None,
            score=int(round(_clamp(p) * 100)), techniques=tuple(dict.fromkeys(techniques)),
            reasons=tuple(reasons))

    def _stage2(self, cand: Candidate, brand: Brand | None) -> Candidate:
        """Refine with the full brand matcher and technique classifier (raise-only)."""
        try:
            matches = [m for m in brand_candidates("http://" + cand.domain) if not m.official]
            tech = classify("http://" + cand.domain)
        except Exception as exc:
            log.debug("deep scoring failed for %r: %r", cand.domain, exc)
            return cand
        best = None
        if matches:
            same = [m for m in matches if brand is not None and m.brand == brand.id]
            best = (same or matches)[0]
        score = cand.score / 100.0
        reasons = list(cand.reasons)
        brand_id, technique, conf = cand.brand, None, 0.0
        if best is not None:
            conf = best.confidence
            weight = 0.95 if (brand is not None and best.brand == brand.id) else 0.8
            if conf * weight > score:
                score = conf * weight
            if brand is None or best.brand != brand.id:
                brand_id = best.brand
            technique = best.technique
            reasons.append(f"brand matcher: {best.name} via {best.technique} "
                           f"({best.confidence:.2f})")
        techniques = tuple(dict.fromkeys([*cand.techniques, *tech.techniques]))
        mitre = tuple(dict.fromkeys([*cand.mitre, *tech.mitre]))
        return replace(
            cand, score=max(cand.score, int(round(_clamp(score) * 100))), brand=brand_id,
            technique=technique or tech.primary, confidence=conf, techniques=techniques,
            mitre=mitre, reasons=tuple(reasons), deep=True)

    # ------------------------------------------------------------------ watch #
    def watch(self, domain_or_brand: str, *, kinds: Iterable[str] | str | None = None,
              max_permutations: int = DEFAULT_MAX, deep_limit: int = _DEFAULT_DEEP,
              min_score: int = 0, limit: int | None = None, max_domains: int = 3,
              persist: bool = False) -> list[Candidate]:
        """Rank look-alikes of a domain or brand (offline).

        ``domain_or_brand`` is a domain (``paypal.com``) or a KB brand id / name.  Returns
        candidates sorted best-first, keeping those scoring ``>= min_score`` and at most
        ``limit``.  With ``persist=True`` the result is also stored (see
        :meth:`persist`).  Raises ``ValueError`` for unusable input.
        """
        brand, domains = self.resolve_target(domain_or_brand, max_domains=max_domains)
        merged: dict[str, Candidate] = {}
        per_domain = max(1, int(max_permutations))
        for dom in domains:
            perms = generate_permutations(dom, kinds=kinds, max=per_domain)
            for cand in self.score_permutations(perms, dom, brand=brand,
                                                deep_limit=deep_limit):
                cur = merged.get(cand.domain)
                if cur is None or cand.score > cur.score:
                    merged[cand.domain] = cand
        # a look-alike of one official domain may be an official domain of the same brand
        official = {d for d in domains}
        ranked = sorted((c for c in merged.values()
                         if c.domain not in official and c.score >= min_score), key=_rank_key)
        if limit is not None:
            ranked = ranked[:max(0, int(limit))]
        if persist:
            self.persist(ranked)
        return ranked

    def monitor_brand(self, brand_id: str, *, max_domains: int = 3, min_score: int = 40,
                      limit: int | None = 500, **kwargs: Any) -> list[Candidate]:
        """:meth:`watch` over a KB brand's official domains (``min_score`` default 40)."""
        brand = self._kb.get((brand_id or "").strip().casefold())
        if brand is None:
            raise ValueError(f"unknown brand id {brand_id!r}")
        return self.watch(brand.id, max_domains=max_domains, min_score=min_score,
                          limit=limit, **kwargs)

    # ------------------------------------------------------------------ liveness #
    async def check_live(self, candidates: Sequence[Candidate | Permutation], *,
                         max_checks: int = _DEFAULT_LIVE_CHECKS, concurrency: int = 20,
                         timeout: float | None = 3.0, resolver: Resolver | None = None,
                         target: str | None = None) -> list[Candidate]:
        """Resolve candidates (best first, at most ``max_checks``) and re-rank.

        Only :mod:`uniphish.core.net` is used, so private / reserved answers never count
        as live.  Resolving candidates gain +15 score; checked-but-dead ones are scaled by
        0.7; unchecked ones keep their offline score.  Bare ``Permutation`` inputs are
        scored first and therefore need ``target`` (the domain they imitate).
        """
        cands: list[Candidate] = []
        bare = [c for c in candidates if isinstance(c, Permutation)]
        if bare:
            if not target:
                raise ValueError("check_live needs target= to score bare Permutation inputs")
            brand, _ = self.resolve_target(target)
            cands.extend(self.score_permutations(bare, target, brand=brand))
        cands.extend(c for c in candidates if isinstance(c, Candidate))
        cands.sort(key=_rank_key)
        res = resolver or self.resolver
        sem = asyncio.Semaphore(max(1, int(concurrency)))
        todo = cands[:max(0, int(max_checks))]

        async def one(c: Candidate) -> Candidate:
            async with sem:
                try:
                    ips = await resolve_ips(c.domain, timeout=timeout, resolver=res)
                except Exception as exc:  # resolver faults must not abort the sweep
                    log.debug("live check of %s failed: %r", c.domain, exc)
                    return c
            public = tuple(ip for ip in ips if is_public_ip(ip))
            if public:
                score = min(100, c.score + _LIVE_BONUS) if c.score > 0 else 0
                return replace(c, live=True, ips=public, score=score,
                               reasons=(*c.reasons, "resolves to a public address"))
            return replace(c, live=False, score=int(round(c.score * _DEAD_FACTOR)),
                           reasons=(*c.reasons, "does not resolve"))

        checked = await asyncio.gather(*(one(c) for c in todo))
        out = [*checked, *cands[len(todo):]]
        out.sort(key=_rank_key)
        return out

    async def watch_live(self, domain_or_brand: str, *, max_checks: int = 200,
                         min_score: int = 0, limit: int | None = None,
                         persist: bool = False, **kwargs: Any) -> list[Candidate]:
        """:meth:`watch` followed by :meth:`check_live` of the best ``max_checks``."""
        cands = self.watch(domain_or_brand, **kwargs)
        checked = await self.check_live(cands, max_checks=max_checks)
        ranked = [c for c in checked if c.score >= min_score]
        if limit is not None:
            ranked = ranked[:max(0, int(limit))]
        if persist:
            self.persist(ranked)
        return ranked

    async def verify(self, candidates: Sequence[Candidate], *, top: int = 10,
                     live_only: bool = True) -> list[Candidate]:
        """Run the engine on the best candidates and merge its verdict into the score.

        Needs ``engine``.  The engine is offline unless its settings enable online
        analysis.  The candidate score becomes the max of its own and the verdict score.
        """
        if self.engine is None:
            raise RuntimeError("BrandWatch.verify needs an engine")
        chosen = [c for c in sorted(candidates, key=_rank_key)
                  if not live_only or c.live][:max(0, int(top))]
        engine = self.engine

        async def one(c: Candidate) -> Candidate:
            try:
                v = await engine.analyze_url(f"https://{c.domain}/")
            except Exception as exc:
                log.warning("engine verdict failed for %s: %r", c.domain, exc)
                return c
            return replace(c, score=max(c.score, int(v.score)), verdict_score=int(v.score),
                           verdict_id=v.id)

        done = {c.domain: c for c in await asyncio.gather(*(one(c) for c in chosen))}
        return sorted((done.get(c.domain, c) for c in candidates), key=_rank_key)

    # ------------------------------------------------------------------ persistence #
    def persist(self, candidates: Iterable[Candidate], *, min_score: int = 40,
                only_live: bool = False) -> int:
        """Record candidates as ``hunt_events`` (source ``brandwatch``); returns new rows.

        A domain already recorded with an equal or higher score is skipped, so repeated
        sweeps do not flood the table.  Uses ``self.store`` or the shared store.
        """
        store = self.store
        if store is None:
            from uniphish.store import get_store

            store = get_store()
        from uniphish.store import norm_value

        known: dict[str, int] = {}
        for ev in store.recent_hunt_events(limit=10_000):
            if ev.get("source") == SOURCE:
                known[ev["domain"]] = max(known.get(ev["domain"], 0), int(ev.get("score", 0)))
        added = 0
        for c in candidates:
            if c.score < min_score or (only_live and not c.live):
                continue
            key = norm_value("domain", c.domain)
            if known.get(key, -1) >= c.score:
                continue
            store.add_hunt_event(
                SOURCE, c.domain, score=c.score, brand=c.brand,
                techniques=[c.kind, *[t for t in c.techniques if t != c.kind]],
                stix=None)
            known[key] = c.score
            added += 1
        return added
