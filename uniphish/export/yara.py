"""YARA rule export: hunt phishing URLs, domains and kit fingerprints in files and memory.

Why: YARA is the lingua franca for scanning mail attachments, saved HTML/SVG pages,
sandbox dumps and proxy captures. :func:`to_yara` builds one rule from the verdict's
selected IOCs (see :func:`uniphish.export.sigma.collect_iocs`): URL and domain strings,
any AiTM / ClickFix / kit fingerprint strings found on ``kit.*`` signals, IPs, and an
exact-hash clause for SHA-256 file IOCs.

Strings are emitted ``ascii wide nocase`` (so UTF-16 documents match) and escaped for
YARA's string syntax (``\\\\``, ``\\"``, control and non-ASCII bytes as ``\\xNN``). Rule
names are sanitised to ``[A-Za-z_][A-Za-z0-9_]*`` and made unique with a content hash.
"""

from __future__ import annotations

import re

from uniphish.core.types import Verdict
from uniphish.export.sigma import (
    NoIndicatorsError,
    brand_name,
    collect_iocs,
    mitre_techniques,
)

__all__ = ["escape_string", "rule_name", "to_yara"]

_MIN_STRING_LEN = 4
_NAME_BAD = re.compile(r"[^A-Za-z0-9_]+")


def escape_string(value: str) -> str:
    """Escape ``value`` as the body of a YARA text string (without surrounding quotes)."""
    out: list[str] = []
    for b in value.encode("utf-8"):
        if b == 0x5C:
            out.append("\\\\")
        elif b == 0x22:
            out.append('\\"')
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def rule_name(brand: str, fingerprint: str) -> str:
    """Valid, deterministic YARA identifier: ``UniPhish_<Brand>_<hash8>`` (<=128 chars)."""
    base = _NAME_BAD.sub("_", brand).strip("_")[:48]
    parts = ["UniPhish"] + ([base] if base else ["Phish"]) + [fingerprint[:8]]
    name = "_".join(parts)
    return name if re.match(r"^[A-Za-z_]", name) else "_" + name


def _meta_str(value: str) -> str:
    return escape_string(value)[:500]


def to_yara(verdict: Verdict, *, allow_benign: bool = False) -> str:
    """Return a YARA rule (source text) matching the verdict's phishing indicators.

    Raises:
        NoIndicatorsError: no URL / domain / IP / hash / kit-string IOC to match.
    """
    iocs = collect_iocs(verdict, allow_benign=allow_benign)
    strings: list[str] = []
    groups: list[str] = []

    def add(prefix: str, values: list[str]) -> None:
        values = [v for v in values if len(v) >= _MIN_STRING_LEN]
        for i, v in enumerate(values):
            strings.append(f'        ${prefix}{i} = "{escape_string(v)}" ascii wide nocase')
        if values:
            groups.append(f"any of (${prefix}*)")

    add("u", [u.url for u in iocs.urls])
    add("d", iocs.domains)
    add("i", iocs.ips)
    add("k", iocs.kit_strings)

    imports = ""
    if iocs.sha256:
        imports = 'import "hash"\n\n'
        groups.extend(f'hash.sha256(0, filesize) == "{h}"' for h in iocs.sha256)
    if not groups:
        raise NoIndicatorsError("verdict yields no strings or hashes to match")

    techs = [t.id for t in mitre_techniques(verdict) if t.framework == "attack"]
    brand = brand_name(verdict)
    desc = f"UniPhish: {verdict.level.value} {brand + ' ' if brand else ''}phishing artifact"
    if verdict.summary:
        desc += f" - {verdict.summary}"
    meta = [
        '        author = "UniPhish"',
        f'        description = "{_meta_str(desc)}"',
        f'        date = "{verdict.created_at:%Y-%m-%d}"',
        f'        mitre_attack = "{_meta_str(",".join(techs))}"',
        f"        score = {verdict.score}",
        f'        verdict_level = "{verdict.level.value}"',
    ]
    if brand:
        meta.append(f'        brand = "{_meta_str(brand)}"')

    cond = "\n        or ".join(groups)
    body = [f"rule {rule_name(brand, iocs.fingerprint())}", "{", "    meta:", *meta]
    if strings:
        body += ["    strings:", *strings]
    body += ["    condition:", f"        {cond}", "}"]
    return imports + "\n".join(body) + "\n"
