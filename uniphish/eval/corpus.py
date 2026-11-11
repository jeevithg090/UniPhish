"""Loader for the labelled sample corpus in ``examples/corpus``.

Why this module exists: demos, the README gallery, smoke tests and ad-hoc benchmarks all
need the same small, documented, *inert* set of phishing and benign artifacts across every
delivery vector (URLs, text, e-mail, pages, files). The data lives as plain files (so people
can read and diff it); this loader turns them into engine inputs without each caller
re-implementing parsing, path safety and labelling.

Layout (see ``examples/corpus/README.md``)::

    manifest.yaml     index of every item: id, kind, label, category, headline signal
    urls.jsonl        URL items          (payload text lives in the jsonl record)
    texts.jsonl       text items
    emails/*.eml      raw RFC 5322 messages
    pages/*.html      HTML documents (served-from URL recorded in the manifest)
    files/*           inert file samples (the *presented* file name is in the manifest)

Public API: :func:`load_items`, :func:`load_corpus`, :func:`counts`, :func:`validate_corpus`,
:class:`CorpusItem`. An item converts to an engine :class:`~uniphish.core.types.Artifact`
(``to_artifact``), to the eval harness's :class:`~uniphish.eval.datasets.ArtifactSpec` /
:class:`~uniphish.eval.datasets.EvalItem` (``to_spec`` / ``to_eval_item``; files are not
representable by the harness's spec and are skipped there).

Security: the corpus directory is data, not code. Manifest paths must be relative and are
resolved against (and confined to) the corpus root; ``jsonl`` sources are restricted to the
two known file names; YAML is read with ``safe_load``; every read is size-capped. Nothing is
ever executed or followed, and nothing here touches the network.

Honesty note: ``hard`` items are deliberately difficult for an offline engine and are kept so
the corpus does not flatter the detector; aggregate numbers should always state whether they
include them.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from uniphish.core.types import Artifact

log = logging.getLogger("uniphish.eval")

__all__ = [
    "CORPUS_ENV",
    "KINDS",
    "LABELS",
    "CorpusError",
    "CorpusItem",
    "corpus_dir",
    "counts",
    "load_corpus",
    "load_items",
    "load_manifest",
    "validate_corpus",
]

CORPUS_ENV = "UNIPHISH_CORPUS_DIR"
KINDS = ("url", "text", "email", "page", "file")
LABELS = ("malicious", "benign")
SCHEMA_VERSION = 1
_JSONL_SOURCES = {"url": "urls.jsonl", "text": "texts.jsonl"}
_MAX_MANIFEST_BYTES = 2_000_000
_MAX_JSONL_BYTES = 4_000_000
_MAX_ITEM_BYTES = 5_000_000
_REQUIRED = ("id", "kind", "label", "category")


class CorpusError(ValueError):
    """The corpus is missing, malformed or unsafe to read."""


def corpus_dir(root: str | os.PathLike[str] | None = None) -> Path:
    """Locate the corpus directory.

    Order: the explicit *root* argument, ``$UNIPHISH_CORPUS_DIR``, then
    ``<repo>/examples/corpus`` (works from a source checkout). Raises
    :class:`CorpusError` if the directory does not exist (e.g. a wheel install).
    """
    if root is not None:
        p = Path(root)
    elif os.environ.get(CORPUS_ENV):
        p = Path(os.environ[CORPUS_ENV])
    else:
        p = Path(__file__).resolve().parents[2] / "examples" / "corpus"
    p = p.expanduser().resolve()
    if not p.is_dir():
        raise CorpusError(
            f"sample corpus not found at {p}; use a source checkout or set {CORPUS_ENV}")
    return p


# --------------------------------------------------------------------------- #
# Item
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CorpusItem:
    """One labelled corpus item with its payload already loaded.

    ``payload`` is ``str`` for url/text/page and ``bytes`` for email/file. ``label`` is
    ``"malicious"`` or ``"benign"``. ``headline_signal`` is the signal id the engine is
    expected to emit (``None`` = no particular signal expected). ``hard`` marks items that are
    deliberately difficult offline.
    """

    id: str
    kind: str
    payload: str | bytes
    label: str
    category: str
    lang: str = "en"
    script: str = "Latn"
    note: str = ""
    headline_signal: str | None = None
    expected_techniques: tuple[str, ...] = ()
    hard: bool = False
    path: str | None = None
    url: str | None = None
    filename: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"

    @property
    def label_int(self) -> int:
        """1 for malicious, 0 for benign (the eval harness convention)."""
        return 1 if self.is_malicious else 0

    def meta(self) -> dict[str, Any]:
        """Everything except the payload, as a plain dict."""
        return {
            "id": self.id, "category": self.category, "lang": self.lang,
            "script": self.script, "note": self.note,
            "headline_signal": self.headline_signal,
            "expected_techniques": list(self.expected_techniques), "hard": self.hard,
            "path": self.path, "url": self.url, "filename": self.filename,
        }

    def to_artifact(self) -> Artifact:
        """Build the engine artifact for this item (applies the artifact size limits)."""
        p = self.payload
        if self.kind == "url":
            return Artifact.from_url(_as_str(p))
        if self.kind == "text":
            return Artifact.from_text(_as_str(p))
        if self.kind == "email":
            return Artifact.from_email(_as_bytes(p))
        if self.kind == "page":
            return Artifact.from_page(_as_str(p), self.url)
        if self.kind == "file":
            return Artifact.from_file(_as_bytes(p), self.filename)
        raise CorpusError(f"unknown kind {self.kind!r}")  # pragma: no cover

    def to_spec(self) -> Any:
        """The eval harness's :class:`ArtifactSpec` (url/text/email/page only)."""
        from uniphish.eval.datasets import ArtifactSpec

        if self.kind == "file":
            raise CorpusError("file items cannot be expressed as an ArtifactSpec")
        value = _as_str(self.payload) if self.kind != "email" \
            else _as_bytes(self.payload).decode("utf-8", "replace")
        return ArtifactSpec(self.kind, value, self.url if self.kind == "page" else None)

    def to_eval_item(self, dataset: str = "corpus") -> Any:
        """The eval harness's :class:`EvalItem` (url/text/email/page only)."""
        from uniphish.eval.datasets import EvalItem

        tags = tuple(self.tags) + (("hard",) if self.hard else ())
        return EvalItem(id=self.id, dataset=dataset, category=self.category,
                        label=self.label_int, spec=self.to_spec(), lang=self.lang,
                        script=self.script, tags=tags, note=self.note)


def _as_str(p: str | bytes) -> str:
    return p if isinstance(p, str) else p.decode("utf-8", "replace")


def _as_bytes(p: str | bytes) -> bytes:
    return p if isinstance(p, bytes) else p.encode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
def _read_capped(path: Path, cap: int) -> bytes:
    size = path.stat().st_size
    if size > cap:
        raise CorpusError(f"{path.name} is {size} bytes, over the {cap} byte cap")
    return path.read_bytes()


def _safe_path(root: Path, rel: object) -> Path:
    """Resolve a manifest-relative path, refusing anything that escapes *root*."""
    if not isinstance(rel, str) or not rel or "\x00" in rel:
        raise CorpusError(f"invalid path {rel!r}")
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise CorpusError(f"path {rel!r} must be relative to the corpus root")
    p = (root / rel).resolve()
    if not p.is_relative_to(root):
        raise CorpusError(f"path {rel!r} escapes the corpus root")
    if not p.is_file():
        raise CorpusError(f"missing corpus file {rel!r}")
    return p


def load_manifest(root: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """Parse and structurally validate ``manifest.yaml``; return its item dicts."""
    base = corpus_dir(root)
    mp = base / "manifest.yaml"
    if not mp.is_file():
        raise CorpusError(f"manifest.yaml not found in {base}")
    try:
        doc = yaml.safe_load(_read_capped(mp, _MAX_MANIFEST_BYTES))
    except yaml.YAMLError as e:
        raise CorpusError(f"manifest.yaml is not valid YAML: {e}") from e
    if not isinstance(doc, dict) or doc.get("version") != SCHEMA_VERSION:
        raise CorpusError(f"manifest.yaml: expected a mapping with version {SCHEMA_VERSION}")
    items = doc.get("items")
    if not isinstance(items, list) or not items:
        raise CorpusError("manifest.yaml: 'items' must be a non-empty list")
    seen: set[str] = set()
    for i, e in enumerate(items):
        if not isinstance(e, dict):
            raise CorpusError(f"manifest item {i} is not a mapping")
        for k in _REQUIRED:
            if not isinstance(e.get(k), str) or not e[k]:
                raise CorpusError(f"manifest item {i} lacks a string {k!r}")
        if e["kind"] not in KINDS:
            raise CorpusError(f"{e['id']}: unknown kind {e['kind']!r}")
        if e["label"] not in LABELS:
            raise CorpusError(f"{e['id']}: label must be one of {LABELS}, got {e['label']!r}")
        if e["id"] in seen:
            raise CorpusError(f"duplicate id {e['id']!r}")
        seen.add(e["id"])
    return items


def _load_jsonl(root: Path, name: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    text = _read_capped(_safe_path(root, name), _MAX_JSONL_BYTES).decode("utf-8")
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            raise CorpusError(f"{name}:{n}: invalid JSON ({e.msg})") from e
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) \
                or not isinstance(rec.get("input"), str):
            raise CorpusError(f"{name}:{n}: record needs string 'id' and 'input'")
        if rec["id"] in out:
            raise CorpusError(f"{name}:{n}: duplicate id {rec['id']!r}")
        out[rec["id"]] = rec
    return out


def _build_item(root: Path, e: dict[str, Any], jsonl: dict[str, dict[str, dict[str, Any]]],
                ) -> CorpusItem:
    kind, iid = e["kind"], e["id"]
    rec: dict[str, Any] = {}
    payload: str | bytes
    if kind in _JSONL_SOURCES:
        if e.get("source") != _JSONL_SOURCES[kind]:
            raise CorpusError(f"{iid}: source must be {_JSONL_SOURCES[kind]!r}")
        src = jsonl.setdefault(kind, _load_jsonl(root, _JSONL_SOURCES[kind]))
        if iid not in src:
            raise CorpusError(f"{iid}: not found in {_JSONL_SOURCES[kind]}")
        rec = src[iid]
        payload = rec["input"]
    else:
        raw = _read_capped(_safe_path(root, e.get("path")), _MAX_ITEM_BYTES)
        payload = raw if kind in ("email", "file") else raw.decode("utf-8", "replace")
    techs = rec.get("expected_techniques") or []
    if not isinstance(techs, list):
        raise CorpusError(f"{iid}: expected_techniques must be a list")
    return CorpusItem(
        id=iid, kind=kind, payload=payload, label=e["label"], category=e["category"],
        lang=str(e.get("lang") or "en"), script=str(e.get("script") or "Latn"),
        note=str(rec.get("note") or ""), headline_signal=e.get("headline_signal"),
        expected_techniques=tuple(str(t) for t in techs), hard=bool(e.get("hard", False)),
        path=e.get("path") or e.get("source"), url=e.get("url"), filename=e.get("filename"))


def load_items(*, kinds: Iterable[str] | None = None, labels: Iterable[str] | None = None,
               categories: Iterable[str] | None = None, include_hard: bool = True,
               root: str | os.PathLike[str] | None = None) -> list[CorpusItem]:
    """Load the corpus (manifest order), optionally filtered.

    Args:
        kinds: restrict to these kinds (``url``/``text``/``email``/``page``/``file``).
        labels: restrict to ``malicious`` and/or ``benign``.
        categories: restrict to these category names.
        include_hard: set False to drop deliberately difficult items.
        root: corpus directory override (default: see :func:`corpus_dir`).

    Raises:
        CorpusError: missing/malformed manifest, unsafe path, oversize or missing file, or an
            unknown filter value.
    """
    kset = _norm_filter(kinds, KINDS, "kind")
    lset = _norm_filter(labels, LABELS, "label")
    cset = set(categories) if categories is not None else None
    base = corpus_dir(root)
    jsonl: dict[str, dict[str, dict[str, Any]]] = {}
    items: list[CorpusItem] = []
    for e in load_manifest(base):
        if kset is not None and e["kind"] not in kset:
            continue
        if lset is not None and e["label"] not in lset:
            continue
        if cset is not None and e["category"] not in cset:
            continue
        if not include_hard and e.get("hard"):
            continue
        items.append(_build_item(base, e, jsonl))
    return items


def _norm_filter(values: Iterable[str] | None, allowed: tuple[str, ...], what: str,
                 ) -> set[str] | None:
    if values is None:
        return None
    s = {values} if isinstance(values, str) else set(values)
    bad = s - set(allowed)
    if bad:
        raise CorpusError(f"unknown {what} {sorted(bad)}; expected {allowed}")
    return s


def load_corpus(**kwargs: Any) -> Iterator[tuple[str, str | bytes, str, dict[str, Any]]]:
    """Yield ``(kind, payload, label, meta)`` for each item (same filters as
    :func:`load_items`). ``meta`` is :meth:`CorpusItem.meta`."""
    for it in load_items(**kwargs):
        yield it.kind, it.payload, it.label, it.meta()


def counts(items: Iterable[CorpusItem] | None = None) -> dict[str, Any]:
    """Item counts: total, per kind, per label, per kind x label, per category, hard."""
    its = list(items) if items is not None else load_items()
    by_kind = Counter(i.kind for i in its)
    by_label = Counter(i.label for i in its)
    return {
        "total": len(its),
        "by_kind": {k: by_kind.get(k, 0) for k in KINDS},
        "by_label": {k: by_label.get(k, 0) for k in LABELS},
        "by_kind_label": {k: {lb: sum(1 for i in its if i.kind == k and i.label == lb)
                              for lb in LABELS} for k in KINDS},
        "by_category": dict(sorted(Counter(i.category for i in its).items())),
        "hard": sum(1 for i in its if i.hard),
    }


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_corpus(root: str | os.PathLike[str] | None = None) -> list[str]:
    """Return a list of problems (empty = healthy).

    Checks that every manifest item loads, every referenced file exists, every jsonl record
    and every file under ``emails/``, ``pages/`` and ``files/`` is indexed (no orphans), and
    that each payload builds into a valid artifact.
    """
    problems: list[str] = []
    try:
        base = corpus_dir(root)
        entries = load_manifest(base)
        items = load_items(root=base)
    except CorpusError as e:
        return [str(e)]
    indexed_paths = {e["path"] for e in entries if e.get("path")}
    for sub in ("emails", "pages", "files"):
        d = base / sub
        if not d.is_dir():
            problems.append(f"missing directory {sub}/")
            continue
        for f in sorted(d.iterdir()):
            rel = f"{sub}/{f.name}"
            if f.is_file() and f.name != "README.md" and rel not in indexed_paths:
                problems.append(f"orphan file not in manifest: {rel}")
    ids = {e["id"] for e in entries}
    for name in _JSONL_SOURCES.values():
        for rid in _load_jsonl(base, name):
            if rid not in ids:
                problems.append(f"{name}: record {rid!r} is not in the manifest")
    for it in items:
        try:
            it.to_artifact()
        except Exception as e:  # report every bad item, not just the first
            problems.append(f"{it.id}: cannot build artifact ({e})")
        if it.kind == "page" and not it.url:
            problems.append(f"{it.id}: page item lacks a url")
        if it.kind == "file" and not it.filename:
            problems.append(f"{it.id}: file item lacks a filename")
    return problems


def _main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI
    import sys

    c = counts()
    out = [f"UniPhish sample corpus: {c['total']} items ({c['hard']} marked hard)"]
    for k in KINDS:
        kl = c["by_kind_label"][k]
        out.append(f"  {k:<6} {c['by_kind'][k]:>3}  malicious={kl['malicious']} "
                   f"benign={kl['benign']}")
    problems = validate_corpus()
    out.extend(f"PROBLEM: {p}" for p in problems)
    sys.stdout.write("\n".join(out) + "\n")
    return 1 if problems else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
