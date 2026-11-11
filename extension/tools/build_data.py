#!/usr/bin/env python3
"""Generate the extension's compact on-device data bundle from ``uniphish/assets``.

Why this exists: the Python platform keeps its brand list, TLD risk table, LOTS hosts,
shorteners, confusables and lure lexicon as YAML/gzipped JSON under ``uniphish/assets``.
The browser extension must score URLs with *no server*, so it needs the same knowledge in
a form that is small to ship and cheap to parse.  This script is the single, reproducible
bridge: it reads the canonical assets and writes minified JSON into ``extension/data/``.

    .venv/bin/python extension/tools/build_data.py            # (re)generate
    .venv/bin/python extension/tools/build_data.py --check    # fail if data/ is stale

Outputs (all minified, UTF-8, deterministic ordering so diffs are reviewable):

* ``brands.json``      brands: official domains, user-content domains, folded terms.
* ``lists.json``       TLD risk, LOTS hosts, shorteners, dynamic-DNS zones, multi-label
                       public suffixes, top-10k ranked domains, lure vocabulary.
* ``confusables.json`` UTS #39 prototypes for every non-ASCII char that imitates ASCII.

Only reads data; never touches the network.  Standard library + PyYAML only.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "uniphish" / "assets"
OUT = ROOT / "extension" / "data"

TOP_N = 10_000
_NONALNUM = re.compile(r"[^a-z0-9]")
# Words that make an ambiguous brand term credible (kept in sync with brandkb._CONTEXT_WORDS).
CONTEXT_WORDS = sorted({
    "account", "login", "signin", "sign", "verify", "verification", "password", "secure",
    "security", "suspended", "locked", "payment", "bank", "card", "delivery", "parcel",
    "package", "tracking", "refund", "invoice", "wallet", "support", "billing", "customer",
    "service", "official", "app", "update", "confirm", "authenticate", "credentials",
    "logon",
})


def _dump(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def _yaml(name: str) -> dict:
    with (ASSETS / name).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def build_brands() -> dict:
    raw = _yaml("brands.yaml")["brands"]
    out = []
    for b in raw:
        official = list(b.get("official_domains") or [])
        extra_hosts = []
        for h in [*(b.get("login_hosts") or []), *(b.get("cdn_hosts") or [])]:
            if not any(h == d or h.endswith("." + d) for d in official):
                extra_hosts.append(h)
        terms: list[str] = []
        for kw in [*(b.get("keywords") or []), *(b.get("aliases") or [])]:
            t = _NONALNUM.sub("", str(kw).lower())
            if t and t.isascii() and 4 <= len(t) <= 40 and t not in terms:
                terms.append(t)
        item: dict = {"i": b["id"], "n": b["name"], "d": official, "t": terms}
        if extra_hosts:
            item["h"] = extra_hosts
        if b.get("user_content_domains"):
            item["u"] = list(b["user_content_domains"])
        if b.get("ambiguous"):
            item["a"] = 1
        native = [n for n in (b.get("native_names") or []) if n]
        if native:
            item["x"] = native
        out.append(item)
    return {"v": 1, "brands": out}


def build_confusables() -> dict:
    with gzip.open(ASSETS / "unicode" / "confusables.json.gz", "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    m: dict[str, str] = {}
    for src_hex, proto_hex in sorted(data["map"].items(), key=lambda kv: int(kv[0], 16)):
        ch = chr(int(src_hex, 16))
        proto = "".join(chr(int(cp, 16)) for cp in proto_hex.split())
        if ord(ch) >= 0x80 and proto.isascii() and proto.isprintable() and proto.strip():
            m[ch] = proto
    return {"v": str(data.get("version", "")), "m": m}


def _psl_multilabel() -> dict[str, list[str]]:
    """ICANN multi-label public suffixes grouped by their final label."""
    try:
        import tldextract
        ex = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        tlds = ex._get_tld_extractor().tlds(include_psl_private_domains=False)
    except Exception as exc:  # pragma: no cover - tldextract is a platform dependency
        print(f"warning: tldextract unavailable ({exc}); using a minimal suffix set",
              file=sys.stderr)
        tlds = ["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
                "co.in", "com.br", "com.cn", "com.mx", "co.za", "co.nz", "com.tr"]
    grouped: dict[str, list[str]] = {}
    for t in sorted(tlds):
        if "." not in t or "*" in t or t.startswith("!"):
            continue
        head, _, last = t.rpartition(".")
        grouped.setdefault(last, []).append(head)
    return {k: sorted(v) for k, v in sorted(grouped.items())}


def _lure_vocab() -> dict:
    """Flatten the multilingual lure lexicon: ``tok`` (token match) and ``sub`` (substring)."""
    data = _yaml("lures.yaml")
    cat_w = data.get("category_weights", {})
    tok: dict[str, float] = {}
    sub: dict[str, float] = {}
    spaceless = re.compile(r"[฀-๿぀-ヿ㐀-鿿가-힯]")
    for _lang, cats in (data.get("languages") or {}).items():
        for cat, terms in (cats or {}).items():
            base = float(cat_w.get(cat, 0.3))
            for t in terms or []:
                term, w = (t["t"], float(t.get("w", base))) if isinstance(t, dict) else (t, base)
                term = str(term).lower()
                if not term or " " in term:
                    continue
                target = sub if spaceless.search(term) else tok
                if w > target.get(term, 0.0):
                    target[term] = round(w, 2)
    return {"tok": dict(sorted(tok.items())), "sub": dict(sorted(sub.items()))}


def build_lists() -> dict:
    tlds = {k: float(v["risk"]) for k, v in _yaml("tlds.yaml")["tlds"].items()}
    lots = []
    for e in _yaml("lots.yaml")["entries"]:
        row = [e["match"], e["kind"], e["name"]]
        if e.get("path"):
            row.append(e["path"])
        lots.append(row)
    shorteners = list(_yaml("shorteners.yaml")["domains"])
    dyn_raw = _yaml("dyndns.yaml")
    dyn = list(dyn_raw.get("domains") or dyn_raw.get("zones") or [])
    with gzip.open(ASSETS / "top_sites.txt.gz", "rt", encoding="utf-8") as fh:
        top = [ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")][:TOP_N]
    return {"v": 1, "tld": tlds, "lots": lots, "short": shorteners, "dyn": dyn,
            "psl": _psl_multilabel(), "top": top, "ctx": CONTEXT_WORDS, "lure": _lure_vocab()}


def render() -> dict[str, str]:
    return {
        "brands.json": _dump(build_brands()),
        "lists.json": _dump(build_lists()),
        "confusables.json": _dump(build_confusables()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if extension/data is stale")
    args = ap.parse_args()
    files = render()
    if args.check:
        stale = [n for n, txt in files.items()
                 if not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != txt]
        if stale:
            print("stale: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("extension/data is up to date")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, txt in files.items():
        (OUT / name).write_text(txt, encoding="utf-8")
        print(f"{name}: {len(txt.encode('utf-8')):,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
