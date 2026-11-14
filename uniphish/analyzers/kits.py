"""Phishing-kit, AiTM and ClickFix signature analyzer.

Why this exists: many modern phishing pages have no tell-tale URL. What gives them away
is *what the page is built to do*: a proxied Microsoft sign-in portal still carries the
real portal's internal config keys, a ClickFix page writes to the clipboard and tells you
to press Win+R, a Browser-in-the-Browser page paints its own address bar. Those facts are
stable across kit deployments, so a small declarative signature set (like AV or Sigma
rules) catches them without any model.

Signatures live in ``uniphish/assets/rules/kit_signatures.yaml`` and are *descriptions of
indicators*, never functional kit code. This module compiles them once, evaluates them
against a :class:`~uniphish.page.html.PageModel` and emits one ``kit.<id>`` signal per
matched signature.

Security properties
-------------------
* The page is never executed. All matching works on the parsed model, the (bounded) raw
  markup and the (bounded) visible text.
* Every regex is *linted at load time* (:func:`check_regex_safe`): unbounded repeats,
  large bounds, back-references, nested variable repeats and alternation inside a repeat
  are rejected, so a rule file cannot introduce catastrophic backtracking. Input is
  additionally capped at :data:`MAX_HTML_SCAN` / :data:`MAX_TEXT_SCAN` characters.
* A malformed rule file fails loudly at load (:class:`KitRuleError`) rather than being
  silently skipped.

Public helpers: :func:`match_html` (reused by the fetch analyzer), :func:`evaluate`,
:func:`load_signatures`, :class:`KitAnalyzer`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from typing import Any
from urllib.parse import urlsplit

import soupsieve
from bs4 import BeautifulSoup

try:  # Python 3.11+
    from re import _constants as _sre_const
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants as _sre_const  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

from uniphish.assets import load_yaml
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.mitre import CATALOG
from uniphish.core.types import Artifact, ArtifactKind, Indicator, IndicatorType, Signal
from uniphish.page.html import PageModel, parse_html

log = logging.getLogger("uniphish.kits")

MAX_HTML_SCAN = 750_000  # characters of raw markup that regexes may scan
MAX_TEXT_SCAN = 200_000  # characters of visible text that matchers may scan
MAX_DOM_CHARS = 400_000  # characters re-parsed for dom_pattern matchers
MAX_REPEAT_BOUND = 1_000  # largest allowed regex repeat bound
MAX_DETAIL_ITEMS = 4  # matcher summaries quoted in a signal detail
RULES_FILE = ("rules", "kit_signatures.yaml")

FAMILIES: dict[str, str] = {
    "aitm_proxy": "Adversary-in-the-Middle proxy",
    "clickfix": "ClickFix / paste-and-run",
    "bitb": "Browser-in-the-Browser",
    "cred_harvester": "Credential-harvesting kit",
    "oauth_consent": "OAuth consent / device-code phishing",
    "callback_toad": "Callback (TOAD) phishing",
    "crypto_drainer": "Crypto wallet drainer",
    "captcha_lure": "Fake CAPTCHA lure",
    "generic_kit": "Phishing-kit artefact",
}

_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_META_FIELDS = frozenset(
    {
        "description",
        "refresh_target",
        "refresh_delay",
        "csp",
        "referrer",
        "generator",
        "og_site_name",
        "theme_color",
        "refresh_offsite",
    }
)


class KitRuleError(ValueError):
    """Raised when the signature file (or a rule passed to the loader) is invalid."""


# --------------------------------------------------------------------------- #
# ReDoS linting
# --------------------------------------------------------------------------- #
def _subpatterns(av: Any) -> Iterable[Any]:
    """Yield every nested parsed sub-pattern inside an sre AST argument."""
    if isinstance(av, _sre_parse.SubPattern):
        yield av
    elif isinstance(av, (list, tuple)):
        for item in av:
            yield from _subpatterns(item)


def _lint(sub: Any, in_repeat: bool) -> None:
    repeats = {_sre_const.MAX_REPEAT, _sre_const.MIN_REPEAT}
    if hasattr(_sre_const, "POSSESSIVE_REPEAT"):
        repeats.add(_sre_const.POSSESSIVE_REPEAT)
    for op, av in sub:
        if op in repeats:
            lo, hi, body = av
            if hi == _sre_const.MAXREPEAT or hi > MAX_REPEAT_BOUND:
                raise KitRuleError(f"unbounded or oversized repeat (max {MAX_REPEAT_BOUND})")
            if in_repeat and hi > lo:
                raise KitRuleError("nested variable repeat")
            _lint(body, in_repeat or hi > 1)
        elif op is _sre_const.BRANCH:
            if in_repeat:
                raise KitRuleError("alternation inside a repeat")
            for alt in av[1]:
                _lint(alt, in_repeat)
        elif op is _sre_const.GROUPREF:
            raise KitRuleError("back-references are not allowed")
        else:
            for child in _subpatterns(av):
                _lint(child, in_repeat)


def check_regex_safe(pattern: str, flags: int = 0) -> None:
    """Raise :class:`KitRuleError` unless ``pattern`` is compilable and ReDoS-safe.

    Allowed: bounded repeats (``{m,n}`` with n <= 1000, ``?``), alternation outside of
    repeats, classes, anchors, lookarounds. Rejected: ``*``, ``+``, ``{n,}``,
    back-references, a variable repeat nested in a repeat, alternation in a repeat.
    """
    try:
        parsed = _sre_parse.parse(pattern, flags)
    except (re.error, RecursionError, OverflowError) as exc:
        raise KitRuleError(f"invalid regex {pattern!r}: {exc}") from exc
    try:
        _lint(parsed, False)
    except KitRuleError as exc:
        raise KitRuleError(f"unsafe regex {pattern[:80]!r}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Evaluation context and matchers
# --------------------------------------------------------------------------- #
def _norm_text(s: str) -> str:
    return " ".join(s.lower().split())


def _host_under(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


@dataclass
class _Ctx:
    page: PageModel
    html: str
    host: str
    favicon_hashes: frozenset[int]
    text: str = field(init=False)

    def __post_init__(self) -> None:
        self.text = _norm_text(self.page.visible_text[:MAX_TEXT_SCAN])

    @cached_property
    def soup(self) -> BeautifulSoup | None:
        try:
            return BeautifulSoup(self.html[:MAX_DOM_CHARS], "lxml")
        except Exception:  # defensive: hostile markup must never crash analysis
            log.debug("kits: dom parse failed", exc_info=True)
            return None


@dataclass(frozen=True)
class Hit:
    """One matcher's positive result."""

    summary: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Matcher:
    kind: str
    negate: bool
    cost: int
    fn: Callable[[_Ctx], Hit | None]

    def run(self, ctx: _Ctx) -> Hit | None:
        """Return a Hit when this matcher holds (inversion applied), else None."""
        try:
            hit = self.fn(ctx)
        except Exception:  # a matcher bug must not take the analyzer down
            log.debug("kits: matcher %s failed", self.kind, exc_info=True)
            return None
        if self.negate:
            return None if hit is not None else Hit("")
        return hit


def _short(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _expect(spec: Mapping[str, Any], allowed: set[str], kind: str) -> None:
    extra = set(spec) - allowed - {"kind", "not", "desc"}
    if extra:
        raise KitRuleError(f"matcher {kind}: unknown keys {sorted(extra)}")


def _str_list(spec: Mapping[str, Any], key: str, kind: str) -> list[str]:
    val = spec.get(key)
    if not isinstance(val, list) or not val or not all(isinstance(v, str) and v for v in val):
        raise KitRuleError(f"matcher {kind}: '{key}' must be a non-empty list of strings")
    return list(val)


def _regex(spec: Mapping[str, Any], kind: str, key: str = "pattern") -> re.Pattern[str]:
    pat = spec.get(key)
    if not isinstance(pat, str) or not pat:
        raise KitRuleError(f"matcher {kind}: '{key}' must be a non-empty string")
    flags = re.I | re.S
    check_regex_safe(pat, flags)
    return re.compile(pat, flags)


def _build_text_contains(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"terms", "min"}, "text_contains")
    terms = [t for t in (_norm_text(x) for x in _str_list(spec, "terms", "text_contains")) if t]
    need = int(spec.get("min", 1))
    desc = str(spec.get("desc") or "text")

    def fn(ctx: _Ctx) -> Hit | None:
        found = [t for t in terms if t in ctx.text]
        if len(found) < need:
            return None
        quoted = ", ".join(f"'{_short(t, 40)}'" for t in found[:3])
        return Hit(f"{desc}: {quoted}", {"terms": found[:5]})

    return 2, fn


def _build_html_regex(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"pattern", "scope"}, "html_regex")
    scope = spec.get("scope", "html")
    if scope not in ("html", "text"):
        raise KitRuleError("html_regex: scope must be 'html' or 'text'")
    rx = _regex(spec, "html_regex")
    desc = str(spec.get("desc") or f"{scope} pattern")

    def fn(ctx: _Ctx) -> Hit | None:
        hay = ctx.html if scope == "html" else ctx.text
        return Hit(desc) if rx.search(hay) else None

    return 3 if scope == "html" else 2, fn


def _build_form(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"require_password", "action_regex"}, "form_action_cross_origin")
    need_pw = bool(spec.get("require_password", False))
    rx = (
        _regex(spec, "form_action_cross_origin", "action_regex") if "action_regex" in spec else None
    )
    desc = str(spec.get("desc") or "form posts to another site")

    def fn(ctx: _Ctx) -> Hit | None:
        for f in ctx.page.forms:
            if not f.is_cross_origin or not f.action:
                continue
            if need_pw and not f.has_password:
                continue
            if rx is not None and not rx.search(f.action[:2_000]):
                continue
            return Hit(
                f"{desc} ({f.action_host or 'unknown host'})", {"action_host": f.action_host}
            )
        return None

    return 1, fn


def _build_clipboard(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"min"}, "has_clipboard_write")
    need = int(spec.get("min", 1))
    desc = str(spec.get("desc") or "script writes to the clipboard")

    def fn(ctx: _Ctx) -> Hit | None:
        n = ctx.page.clipboard_write
        return (
            Hit(f"{desc} ({n} call site{'s' if n != 1 else ''})", {"clipboard_write": n})
            if n >= need
            else None
        )

    return 0, fn


def _build_title(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"pattern"}, "title_regex")
    rx = _regex(spec, "title_regex")
    desc = str(spec.get("desc") or "page title")

    def fn(ctx: _Ctx) -> Hit | None:
        title = ctx.page.title[:500]
        return Hit(f"{desc}: '{_short(title)}'") if rx.search(title) else None

    return 1, fn


def _build_resource(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"suffixes"}, "resource_host_suffix")
    suffixes = [s.lower().strip(".") for s in _str_list(spec, "suffixes", "resource_host_suffix")]

    def fn(ctx: _Ctx) -> Hit | None:
        if not ctx.host:  # without the page's own host we cannot say a resource is foreign
            return None
        for s in suffixes:
            if _host_under(ctx.host, s):
                return None
        for h in sorted(ctx.page.resource_hosts):
            if any(_host_under(h.lower(), s) for s in suffixes):
                return Hit(f"resources loaded from {_short(h, 50)}", {"resource_host": h})
        return None

    return 1, fn


def _build_meta(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"field", "equals", "contains", "regex", "present"}, "meta")
    fname = spec.get("field")
    if fname not in _META_FIELDS:
        raise KitRuleError(f"meta: field must be one of {sorted(_META_FIELDS)}")
    equals, contains = spec.get("equals"), spec.get("contains")
    rx = _regex(spec, "meta", "regex") if "regex" in spec else None
    present = spec.get("present")
    if equals is None and contains is None and rx is None and present is None:
        raise KitRuleError("meta: give one of equals, contains, regex, present")

    def fn(ctx: _Ctx) -> Hit | None:
        raw = (
            ctx.page.meta_refresh_offsite
            if fname == "refresh_offsite"
            else getattr(ctx.page.meta, str(fname))
        )
        val = "" if raw in (None, False) else str(raw)[:2_000]
        ok = (
            (present is None or bool(val) == bool(present))
            and (equals is None or val.lower() == str(equals).lower())
            and (contains is None or str(contains).lower() in val.lower())
            and (rx is None or rx.search(val) is not None)
        )
        return Hit(f"meta {fname}: '{_short(val)}'") if ok else None

    return 1, fn


def _build_favicon(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"hashes"}, "favicon_mmh3")
    raw = spec.get("hashes")
    if not isinstance(raw, list) or not raw or not all(isinstance(h, int) for h in raw):
        raise KitRuleError("favicon_mmh3: 'hashes' must be a non-empty list of integers")
    wanted = frozenset(raw)

    def fn(ctx: _Ctx) -> Hit | None:
        hit = sorted(wanted & ctx.favicon_hashes)
        return Hit(f"favicon hash {hit[0]}", {"favicon_mmh3": hit[0]}) if hit else None

    return 1, fn


def _build_script_src(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"pattern"}, "script_src_regex")
    rx = _regex(spec, "script_src_regex")

    def fn(ctx: _Ctx) -> Hit | None:
        for s in ctx.page.scripts:
            if s.src and rx.search(s.src[:2_000]):
                return Hit(f"script from {_short(s.host or s.src, 50)}")
        return None

    return 1, fn


def _build_dom(spec: Mapping[str, Any]) -> tuple[int, Callable[[_Ctx], Hit | None]]:
    _expect(spec, {"selector", "min"}, "dom_pattern")
    sel = spec.get("selector")
    if not isinstance(sel, str) or not sel:
        raise KitRuleError("dom_pattern: 'selector' must be a non-empty string")
    try:
        compiled = soupsieve.compile(sel)
    except Exception as exc:  # soupsieve raises SelectorSyntaxError and friends
        raise KitRuleError(f"dom_pattern: bad selector {sel!r}: {exc}") from exc
    need = int(spec.get("min", 1))
    desc = str(spec.get("desc") or "DOM pattern")

    def fn(ctx: _Ctx) -> Hit | None:
        soup = ctx.soup
        if soup is None:
            return None
        return Hit(desc) if len(compiled.select(soup, limit=need)) >= need else None

    return 4, fn


_BUILDERS: dict[str, Callable[[Mapping[str, Any]], tuple[int, Callable[[_Ctx], Hit | None]]]] = {
    "text_contains": _build_text_contains,
    "html_regex": _build_html_regex,
    "form_action_cross_origin": _build_form,
    "has_clipboard_write": _build_clipboard,
    "title_regex": _build_title,
    "resource_host_suffix": _build_resource,
    "meta": _build_meta,
    "favicon_mmh3": _build_favicon,
    "script_src_regex": _build_script_src,
    "dom_pattern": _build_dom,
}
MATCHER_KINDS: tuple[str, ...] = tuple(_BUILDERS)


def _build_matcher(spec: Any) -> Matcher:
    if not isinstance(spec, Mapping):
        raise KitRuleError("matcher must be a mapping")
    kind = spec.get("kind")
    builder = _BUILDERS.get(str(kind))
    if builder is None:
        raise KitRuleError(f"unknown matcher kind {kind!r}")
    cost, fn = builder(spec)
    return Matcher(kind=str(kind), negate=bool(spec.get("not", False)), cost=cost, fn=fn)


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Signature:
    """A compiled signature. ``signal_id`` is what the analyzer emits."""

    id: str
    name: str
    family: str
    weight: float
    mitre: tuple[str, ...]
    description: str
    all_of: tuple[Matcher, ...]
    any_of: tuple[Matcher, ...]
    min_any: int = 1
    not_suffix: tuple[str, ...] = ()
    require_url: bool = False

    @property
    def signal_id(self) -> str:
        return f"kit.{self.id}"


@dataclass(frozen=True)
class KitMatch:
    """A signature that matched, with what it matched on."""

    signature: Signature
    hits: tuple[Hit, ...]

    @property
    def evidence(self) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for h in self.hits:
            for k, v in h.evidence.items():
                merged.setdefault(k, v)
        return merged

    def to_signal(self) -> Signal:
        sig = self.signature
        what = "; ".join(h.summary for h in self.hits[:MAX_DETAIL_ITEMS] if h.summary)
        detail = f"{FAMILIES[sig.family]} pattern. {sig.description.strip()}"
        if what:
            detail += f" Matched: {what}."
        return Signal(
            id=sig.signal_id,
            title=sig.name,
            detail=detail,
            weight=sig.weight,
            category="kit",
            mitre=list(sig.mitre),
            tags=[sig.family],
            evidence={"signature": sig.id, "family": sig.family, **self.evidence},
        )


def _compile_signature(raw: Any) -> Signature:
    if not isinstance(raw, Mapping):
        raise KitRuleError("signature must be a mapping")
    sid = raw.get("id")
    if not isinstance(sid, str) or not _ID_RE.match(sid):
        raise KitRuleError(f"bad signature id {sid!r} (dotted lowercase, e.g. 'aitm.thing')")
    try:
        name = str(raw["name"])
        family = str(raw["family"])
        weight = float(raw["severity_weight"])
    except (KeyError, TypeError, ValueError) as exc:
        raise KitRuleError(f"{sid}: needs name, family, severity_weight ({exc})") from exc
    if family not in FAMILIES:
        raise KitRuleError(f"{sid}: unknown family {family!r}")
    if len(name) > 70:
        raise KitRuleError(f"{sid}: name longer than 70 chars")
    if not -4.0 <= weight <= 8.0:
        raise KitRuleError(f"{sid}: severity_weight outside -4..8")
    mitre = tuple(str(m) for m in raw.get("mitre") or ())
    for m in mitre:
        if m not in CATALOG:
            raise KitRuleError(f"{sid}: unknown MITRE id {m!r}")
    scope = raw.get("host_scope") or {}
    if not isinstance(scope, Mapping) or set(scope) - {"not_suffix", "require_url"}:
        raise KitRuleError(f"{sid}: bad host_scope")
    unknown = set(raw) - {
        "id",
        "name",
        "family",
        "severity_weight",
        "mitre",
        "description",
        "host_scope",
        "all_of",
        "any_of",
        "min_any",
    }
    if unknown:
        raise KitRuleError(f"{sid}: unknown keys {sorted(unknown)}")
    try:
        all_of = sorted((_build_matcher(m) for m in raw.get("all_of") or ()), key=lambda m: m.cost)
        any_of = sorted((_build_matcher(m) for m in raw.get("any_of") or ()), key=lambda m: m.cost)
    except KitRuleError as exc:
        raise KitRuleError(f"{sid}: {exc}") from exc
    if not all_of and not any_of:
        raise KitRuleError(f"{sid}: needs all_of and/or any_of matchers")
    min_any = int(raw.get("min_any", 1))
    if any_of and not 1 <= min_any <= len(any_of):
        raise KitRuleError(f"{sid}: min_any out of range")
    if all(m.negate for m in (*all_of, *any_of)):
        raise KitRuleError(f"{sid}: needs at least one positive matcher")
    return Signature(
        id=sid,
        name=name,
        family=family,
        weight=weight,
        mitre=mitre,
        description=" ".join(str(raw.get("description", "")).split()),
        all_of=tuple(all_of),
        any_of=tuple(any_of),
        min_any=min_any,
        not_suffix=tuple(str(s).lower().strip(".") for s in scope.get("not_suffix") or ()),
        require_url=bool(scope.get("require_url", False)),
    )


def load_signatures(raw: Sequence[Mapping[str, Any]] | None = None) -> tuple[Signature, ...]:
    """Compile signatures from ``raw`` (a list of mappings) or the packaged YAML file.

    Raises :class:`KitRuleError` on any invalid rule or duplicate id. The packaged set is
    cached by :func:`default_signatures`; this function always recompiles.
    """
    if raw is None:
        raw = load_yaml(*RULES_FILE)
    if not isinstance(raw, list):
        raise KitRuleError("signature file must contain a list")
    sigs: list[Signature] = []
    seen: set[str] = set()
    for entry in raw:
        sig = _compile_signature(entry)
        if sig.id in seen:
            raise KitRuleError(f"duplicate signature id {sig.id!r}")
        seen.add(sig.id)
        sigs.append(sig)
    return tuple(sigs)


@lru_cache(maxsize=1)
def default_signatures() -> tuple[Signature, ...]:
    """The packaged signature set, compiled once."""
    return load_signatures()


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def _host_of(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlsplit(url.strip()).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def _eval_one(sig: Signature, ctx: _Ctx) -> KitMatch | None:
    if sig.require_url and not ctx.host:
        return None
    if ctx.host and any(_host_under(ctx.host, s) for s in sig.not_suffix):
        return None
    hits: list[Hit] = []
    for m in sig.all_of:
        h = m.run(ctx)
        if h is None:
            return None
        if h.summary:
            hits.append(h)
    if sig.any_of:
        found = 0
        for m in sig.any_of:
            h = m.run(ctx)
            if h is None:
                continue
            found += 1
            if h.summary:
                hits.append(h)
            if found >= sig.min_any:
                break
        if found < sig.min_any:
            return None
    return KitMatch(sig, tuple(hits))


def evaluate(
    page: PageModel,
    html: str,
    url: str | None = None,
    *,
    signatures: Sequence[Signature] | None = None,
    favicon_hashes: Iterable[int] = (),
) -> list[KitMatch]:
    """Evaluate ``signatures`` (default: packaged set) against an already parsed page.

    ``html`` is the raw markup (truncated to :data:`MAX_HTML_SCAN` characters).
    ``favicon_hashes`` are Shodan-style mmh3 hashes of the page's favicons, if known.
    """
    sigs = default_signatures() if signatures is None else signatures
    ctx = _Ctx(
        page=page,
        html=html[:MAX_HTML_SCAN],
        host=_host_of(url),
        favicon_hashes=frozenset(int(h) for h in favicon_hashes),
    )
    out = []
    for sig in sigs:
        m = _eval_one(sig, ctx)
        if m is not None:
            out.append(m)
    return out


def match_html(
    html: str | bytes,
    url: str | None = None,
    *,
    favicon_hashes: Iterable[int] = (),
    signatures: Sequence[Signature] | None = None,
) -> list[KitMatch]:
    """Parse ``html`` and return matched signatures. Never raises on hostile input.

    Convenience entry point for callers without a :class:`PageModel` (for example the
    fetch analyzer holding the HTML of a fetched page).
    """
    if isinstance(html, (bytes, bytearray)):
        html = bytes(html).decode("utf-8", "replace")
    if not isinstance(html, str):
        return []
    try:
        html = html[:MAX_HTML_SCAN]  # bound the parse as well as the regex scans
        page = parse_html(html, url)
        return evaluate(page, html, url, signatures=signatures, favicon_hashes=favicon_hashes)
    except Exception:  # defensive
        log.warning("kits: match_html failed", exc_info=True)
        return []


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
def _favicon_hashes_from_meta(meta: Mapping[str, Any]) -> list[int]:
    raw = meta.get("favicon_mmh3")
    vals = raw if isinstance(raw, (list, tuple, set)) else [raw]
    out: list[int] = []
    for v in vals:
        try:
            if v is not None and not isinstance(v, bool):
                out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def build_result(matches: Sequence[KitMatch], evaluated: int) -> AnalyzerResult:
    """Turn matches into an :class:`AnalyzerResult` (signals, techniques, indicators)."""
    techniques: list[str] = []
    indicators: list[Indicator] = []
    seen_hosts: set[str] = set()
    for m in matches:
        if m.signature.family not in techniques:
            techniques.append(m.signature.family)
        host = str(m.evidence.get("action_host") or "").lower()
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            indicators.append(
                Indicator(
                    type=IndicatorType.DOMAIN,
                    value=host,
                    role="exfil-endpoint",
                    context=f"password form target ({m.signature.id})",
                )
            )
    return AnalyzerResult(
        signals=[m.to_signal() for m in matches],
        indicators=indicators,
        techniques=techniques,
        meta={
            "kits": {
                "matched": [m.signature.id for m in matches],
                "families": techniques,
                "signatures_evaluated": evaluated,
            }
        },
    )


@register
class KitAnalyzer(Analyzer):
    """Evaluate the declarative kit signatures against a PAGE artifact."""

    name = "kits"
    kinds = frozenset({ArtifactKind.PAGE})
    stage = 0
    requires_online = False
    blocking = True
    description = (
        "Phishing-kit fingerprints: AiTM reverse proxies, ClickFix, "
        "Browser-in-the-Browser, OAuth/device-code, callback and wallet-drainer pages"
    )
    signals = {s.signal_id: s.name for s in default_signatures()}

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        html = artifact.html()[:MAX_HTML_SCAN]
        if not html.strip():
            return AnalyzerResult()
        page = ctx.shared.get("page.model")  # reuse the page analyzer's parse if present
        if not isinstance(page, PageModel):
            page = ctx.memo("kits.page_model", lambda: parse_html(html, artifact.url))
        sigs = default_signatures()
        matches = evaluate(
            page,
            html,
            artifact.url,
            signatures=sigs,
            favicon_hashes=_favicon_hashes_from_meta(artifact.meta),
        )
        return build_result(matches, len(sigs))
