#!/usr/bin/env python3
"""Generate UniPhish's compact Unicode security assets from the Unicode source files.

Why this exists
---------------
The homoglyph / IDN-homograph core (:mod:`uniphish.url.confusables`,
:mod:`uniphish.url.scripts`, :mod:`uniphish.url.idn_policy`) needs four Unicode tables:

* ``confusables.txt``        — UTS #39 confusable prototype mapping (the skeleton core),
* ``IdentifierStatus.txt``   — UTS #39 Allowed / Restricted identifier characters,
* ``Scripts.txt``            — UAX #24 Script property,
* ``ScriptExtensions.txt``   — UAX #24 Script_Extensions property.

Shipping the multi-megabyte upstream text files would be wasteful, so this build-time
script parses them once and emits small, range-compressed, gzip-compressed JSON assets
that :mod:`uniphish.assets` loads lazily at runtime. The exact Unicode version is written
to ``VERSION`` next to the assets so the data provenance is auditable.

Usage
-----
Download the four source files (and the property-value aliases used to shorten script
names) then run the generator::

    curl -sS -o confusables.txt      https://www.unicode.org/Public/security/latest/confusables.txt
    curl -sS -o IdentifierStatus.txt https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
    curl -sS -o Scripts.txt          https://www.unicode.org/Public/UCD/latest/ucd/Scripts.txt
    curl -sS -o ScriptExtensions.txt https://www.unicode.org/Public/UCD/latest/ucd/ScriptExtensions.txt
    curl -sS -o PropertyValueAliases.txt https://www.unicode.org/Public/UCD/latest/ucd/PropertyValueAliases.txt

    .venv/bin/python scripts/gen_unicode_data.py --src ./raw --out uniphish/assets/unicode

Or let the script fetch them itself (build machines only; never at runtime)::

    .venv/bin/python scripts/gen_unicode_data.py --download --out uniphish/assets/unicode

The generated assets are committed to the repository; runtime code never downloads.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------- #
# Source URLs (used only with --download, i.e. at build time, never at runtime)
# --------------------------------------------------------------------------- #
SOURCES = {
    "confusables.txt": "https://www.unicode.org/Public/security/latest/confusables.txt",
    "IdentifierStatus.txt": "https://www.unicode.org/Public/security/latest/IdentifierStatus.txt",
    "Scripts.txt": "https://www.unicode.org/Public/UCD/latest/ucd/Scripts.txt",
    "ScriptExtensions.txt": "https://www.unicode.org/Public/UCD/latest/ucd/ScriptExtensions.txt",
    "PropertyValueAliases.txt": "https://www.unicode.org/Public/UCD/latest/ucd/PropertyValueAliases.txt",
}

_VERSION_RE = re.compile(r"^#\s*Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", re.MULTILINE)
_RANGE_RE = re.compile(r"^([0-9A-Fa-f]{4,6})(?:\.\.([0-9A-Fa-f]{4,6}))?$")


# --------------------------------------------------------------------------- #
# Low-level parsing helpers
# --------------------------------------------------------------------------- #
def _version(text: str, fallback: str = "0.0.0") -> str:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else fallback


def _strip(line: str) -> str:
    """Drop the comment and surrounding whitespace from a UCD data line."""
    return line.split("#", 1)[0].strip()


def _parse_range(token: str) -> tuple[int, int] | None:
    m = _RANGE_RE.match(token.strip())
    if not m:
        return None
    start = int(m.group(1), 16)
    end = int(m.group(2), 16) if m.group(2) else start
    return start, end


def _merge(ranges: list[tuple[int, int, object]]) -> list[list[object]]:
    """Sort and coalesce adjacent/overlapping ranges that carry the same value."""
    ranges.sort(key=lambda r: r[0])
    out: list[list[object]] = []
    for start, end, value in ranges:
        if out and out[-1][2] == value and start <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end, value])
    return out


# --------------------------------------------------------------------------- #
# Per-file parsers
# --------------------------------------------------------------------------- #
def parse_script_aliases(text: str) -> dict[str, str]:
    """``PropertyValueAliases.txt`` ``sc`` rows -> {short code: long name}."""
    aliases: dict[str, str] = {}
    for line in text.splitlines():
        row = _strip(line)
        if not row.startswith("sc ;") and not row.startswith("sc\t"):
            continue
        parts = [p.strip() for p in row.split(";")]
        if len(parts) >= 3:
            aliases[parts[1]] = parts[2]
    return aliases


def parse_scripts(text: str, long_to_short: dict[str, str]) -> list[list[object]]:
    """``Scripts.txt`` -> range-compressed [[start, end, short_code], ...]."""
    ranges: list[tuple[int, int, object]] = []
    for line in text.splitlines():
        row = _strip(line)
        if ";" not in row:
            continue
        rng, _, name = row.partition(";")
        pr = _parse_range(rng)
        if pr is None:
            continue
        short = long_to_short.get(name.strip(), name.strip())
        ranges.append((pr[0], pr[1], short))
    return _merge(ranges)


def parse_script_extensions(text: str) -> list[list[object]]:
    """``ScriptExtensions.txt`` -> [[start, end, [short_code, ...]], ...]."""
    ranges: list[tuple[int, int, object]] = []
    for line in text.splitlines():
        row = _strip(line)
        if ";" not in row:
            continue
        rng, _, codes = row.partition(";")
        pr = _parse_range(rng)
        if pr is None:
            continue
        values = tuple(sorted(codes.split()))
        ranges.append((pr[0], pr[1], values))
    merged = _merge(ranges)
    return [[s, e, list(v)] for s, e, v in merged]


def parse_identifier_allowed(text: str) -> list[list[int]]:
    """``IdentifierStatus.txt`` -> allowed [[start, end], ...] (rest is Restricted)."""
    ranges: list[tuple[int, int, object]] = []
    for line in text.splitlines():
        row = _strip(line)
        if ";" not in row:
            continue
        rng, _, status = row.partition(";")
        if status.strip() != "Allowed":
            continue
        pr = _parse_range(rng)
        if pr is None:
            continue
        ranges.append((pr[0], pr[1], True))
    merged = _merge(ranges)
    return [[s, e] for s, e, _ in merged]


def parse_confusables(text: str) -> dict[str, str]:
    """``confusables.txt`` -> {source_hex: 'proto_hex[ proto_hex...]'}.

    The source field is always a single code point; the prototype may be several.
    The upstream table is transitively closed, so a single mapping pass is sufficient.
    """
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        row = _strip(line)
        if ";" not in row:
            continue
        fields = [f.strip() for f in row.split(";")]
        if len(fields) < 2 or not fields[0] or not fields[1]:
            continue
        src_parts = fields[0].split()
        if len(src_parts) != 1:
            continue  # defensive: UTS#39 sources are single code points
        try:
            src_cp = int(src_parts[0], 16)
            proto_cps = [int(cp, 16) for cp in fields[1].split()]
        except ValueError:
            continue
        # A code point that maps to itself carries no information.
        if len(proto_cps) == 1 and proto_cps[0] == src_cp:
            continue
        mapping[f"{src_cp:04X}"] = " ".join(f"{cp:04X}" for cp in proto_cps)
    return mapping


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def _read(src_dir: Path, name: str) -> str:
    return (src_dir / name).read_text(encoding="utf-8")


def _download(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "uniphish-build/2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            (dest / name).write_bytes(resp.read())
        print(f"downloaded {name}", file=sys.stderr)


def _write_gzip_json(path: Path, obj: object) -> int:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    blob = gzip.compress(raw, mtime=0)
    path.write_bytes(blob)
    return len(blob)


def generate(src_dir: Path, out_dir: Path) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    conf_text = _read(src_dir, "confusables.txt")
    ident_text = _read(src_dir, "IdentifierStatus.txt")
    scripts_text = _read(src_dir, "Scripts.txt")
    scx_text = _read(src_dir, "ScriptExtensions.txt")
    aliases_text = _read(src_dir, "PropertyValueAliases.txt")

    aliases = parse_script_aliases(aliases_text)
    long_to_short = {long: short for short, long in aliases.items()}

    version = _version(conf_text) or _version(ident_text)

    confusables = {"version": version, "map": parse_confusables(conf_text)}
    scripts = {
        "version": _version(scripts_text, version),
        "scripts": parse_scripts(scripts_text, long_to_short),
        "extensions": parse_script_extensions(scx_text),
        "names": aliases,
    }
    identifier = {
        "version": _version(ident_text, version),
        "allowed": parse_identifier_allowed(ident_text),
    }

    sizes = {
        "confusables.json.gz": _write_gzip_json(out_dir / "confusables.json.gz", confusables),
        "scripts.json.gz": _write_gzip_json(out_dir / "scripts.json.gz", scripts),
        "identifier_status.json.gz": _write_gzip_json(
            out_dir / "identifier_status.json.gz", identifier
        ),
    }
    (out_dir / "VERSION").write_text(version + "\n", encoding="utf-8")
    sizes["confusable_mappings"] = len(confusables["map"])
    sizes["version"] = version  # type: ignore[assignment]
    return sizes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--src", type=Path, help="directory holding the raw Unicode .txt files")
    ap.add_argument("--out", type=Path, required=True, help="output asset directory")
    ap.add_argument(
        "--download", action="store_true", help="fetch the source files first (build machines only)"
    )
    args = ap.parse_args(argv)

    if args.download:
        src = args.src or (args.out.parent / "_unicode_raw")
        _download(src)
    elif args.src:
        src = args.src
    else:
        ap.error("either --download or --src is required")
        return 2

    sizes = generate(src, args.out)
    for k, v in sizes.items():
        print(f"{k}: {v}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
