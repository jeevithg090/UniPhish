"""Suricata / Snort-3 rule export for phishing infrastructure found by UniPhish.

Why: network defenders run IDS/NDR sensors, not UniPhish. This module emits ready-to-load
rules (TLS SNI, HTTP Host, DNS query, HTTP host+URI and raw-IP) for the hosts and URLs in a
verdict, built from the same conservative IOC selection as the Sigma exporter
(:func:`uniphish.export.sigma.collect_iocs`).

SID allocation
--------------
Local rule ids must not collide with registered rulesets (ET Open uses 2,000,000-2,999,999
and ET Pro 2,400,000+...). UniPhish reserves **4,100,000-4,999,999** (``SID_BASE`` ..
``SID_BASE + SID_SPAN - 1``). A sid is derived deterministically from the sha256 of the rule
kind and its indicator, so the same IOC always yields the same sid across runs and hosts;
collisions inside one call are resolved by linear probing. This range is a local convention,
not a registration with any ruleset authority.

Escaping: Suricata ``content`` strings hex-escape ``; \\ " | :`` and every non-printable or
non-ASCII byte as ``|XX|``; ``msg`` text is restricted to a safe character set.
"""

from __future__ import annotations

import hashlib
import re

from uniphish.core.types import Verdict
from uniphish.export.sigma import (
    Iocs,
    UrlIoc,
    brand_name,
    collect_iocs,
    mitre_techniques,
)

__all__ = ["SID_BASE", "SID_SPAN", "escape_content", "to_suricata_rules",
           "validate_suricata_rule"]

SID_BASE = 4_100_000
SID_SPAN = 900_000
_CLASSTYPE = "social-engineering"
_TACTIC_META = {"initial-access": "Initial_Access", "credential-access": "Credential_Access",
                "execution": "Execution", "defense-evasion": "Defense_Evasion",
                "resource-development": "Resource_Development",
                "reconnaissance": "Reconnaissance", "collection": "Collection"}

_CONTENT_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -._~/?=&%@!$'()*+,#[]<>{}^`")
_MSG_SAFE = re.compile(r"[^A-Za-z0-9 ._()/+,\-]")


def escape_content(value: str) -> str:
    """Escape ``value`` for use inside a Suricata ``content:"..."`` option."""
    out: list[str] = []
    hexrun: list[str] = []

    def flush() -> None:
        if hexrun:
            out.append("|" + " ".join(hexrun) + "|")
            hexrun.clear()

    for b in value.encode("utf-8"):
        ch = chr(b)
        if b < 0x80 and ch in _CONTENT_SAFE:
            flush()
            out.append(ch)
        else:
            hexrun.append(f"{b:02X}")
    flush()
    return "".join(out)


def _msg(verdict: Verdict, what: str, value: str) -> str:
    brand = brand_name(verdict)
    techs = [t.id for t in mitre_techniques(verdict) if t.framework == "attack"][:3]
    parts = [f"UniPhish phishing {what} {value}"]
    inner = "; ".join(x for x in (brand, ",".join(techs)) if x)
    text = parts[0] + (f" ({inner})" if inner else "")
    return _MSG_SAFE.sub("", text.replace(";", ","))[:200]


def _metadata(verdict: Verdict) -> str:
    items: list[str] = []
    for t in mitre_techniques(verdict):
        if t.framework == "attack":
            items.append(f"mitre_technique_id {t.id}")
    tactics = {_TACTIC_META.get(t.tactic) for t in mitre_techniques(verdict)
               if t.framework == "attack"}
    items.extend(f"mitre_tactic_name {n}" for n in sorted(x for x in tactics if x))
    items.append(f"created_at {verdict.created_at:%Y_%m_%d}")
    items.append(f"uniphish_score {verdict.score}")
    brand = re.sub(r"[^A-Za-z0-9]+", "_", brand_name(verdict)).strip("_")
    if brand:
        items.append(f"uniphish_brand {brand}")
    return ", ".join(items)


class _Sids:
    def __init__(self) -> None:
        self.used: set[int] = set()

    def get(self, kind: str, value: str) -> int:
        h = int.from_bytes(hashlib.sha256(f"uniphish|{kind}|{value}".encode()).digest()[:8], "big")
        sid = SID_BASE + h % SID_SPAN
        while sid in self.used:
            sid = SID_BASE + (sid - SID_BASE + 1) % SID_SPAN
        self.used.add(sid)
        return sid


def _rule(header: str, msg: str, body: str, sid: int, meta: str) -> str:
    return (f'alert {header} (msg:"{msg}"; {body} classtype:{_CLASSTYPE}; '
            f"sid:{sid}; rev:1; metadata:{meta};)")


def _host_rules(verdict: Verdict, iocs: Iocs, sids: _Sids, meta: str) -> list[str]:
    rules: list[str] = []
    for d in iocs.domains:
        c = escape_content("." + d)
        buf = f'dotprefix; content:"{c}"; nocase; endswith;'
        rules.append(_rule(
            "tls $HOME_NET any -> $EXTERNAL_NET any", _msg(verdict, "TLS SNI", d),
            f"flow:established,to_server; tls.sni; {buf}", sids.get("sni", d), meta))
        rules.append(_rule(
            "http $HOME_NET any -> $EXTERNAL_NET any", _msg(verdict, "HTTP Host", d),
            f"flow:established,to_server; http.host; {buf}", sids.get("host", d), meta))
        rules.append(_rule(
            "dns $HOME_NET any -> any any", _msg(verdict, "DNS query", d),
            f"dns.query; {buf}", sids.get("dns", d), meta))
    return rules


def _uri_rule(verdict: Verdict, u: UrlIoc, sids: _Sids, meta: str) -> str | None:
    if u.path_query == "/" and not u.shared_host:
        return None  # domain-level rules already cover it
    host = escape_content(u.host)
    uri = escape_content(u.path_query)
    body = ("flow:established,to_server; "
            f'http.host; content:"{host}"; nocase; bsize:{len(u.host)}; '
            f'http.uri; content:"{uri}"; startswith; fast_pattern;')
    if u.path_query == "/":
        body = ("flow:established,to_server; "
                f'http.host; content:"{host}"; nocase; bsize:{len(u.host)}; '
                'http.uri; content:"/"; bsize:1;')
    return _rule("http $HOME_NET any -> $EXTERNAL_NET any",
                 _msg(verdict, "URL", u.host + u.path_query.split("?", 1)[0]),
                 body, sids.get("uri", u.url), meta)


def to_suricata_rules(verdict: Verdict, *, allow_benign: bool = False) -> list[str]:
    """Suricata rules for the phishing hosts / URLs / IPs in ``verdict`` (``[]`` if none).

    Emits, per safe domain: TLS SNI, HTTP Host and DNS-query rules (``dotprefix`` +
    ``endswith`` so the domain and its subdomains match, never ``evilexample.test`` for
    ``example.test``); per URL with a path (or any URL on a shared hosting platform): an
    HTTP host+URI rule; per IP: one ``alert ip`` rule. Sids are deterministic, see module
    docstring.
    """
    iocs = collect_iocs(verdict, allow_benign=allow_benign)
    if not iocs.web:
        return []
    meta = _metadata(verdict)
    sids = _Sids()
    rules = _host_rules(verdict, iocs, sids, meta)
    for u in iocs.urls:
        r = _uri_rule(verdict, u, sids, meta)
        if r:
            rules.append(r)
    for ip in iocs.ips:
        rules.append(_rule(f"ip $HOME_NET any -> {ip} any", _msg(verdict, "C2/landing IP", ip),
                           "flow:to_server;", sids.get("ip", ip), meta))
    return rules


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
_HEADER_RE = re.compile(r"^alert (tls|http|dns|ip|tcp|udp) \S+ \S+ (->|<>) \S+ \S+ \(")


def _split_options(body: str) -> list[str]:
    """Split a rule option body on unescaped ';' outside quotes."""
    opts, cur, quoted, esc = [], [], False, False
    for ch in body:
        cur.append(ch)
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            quoted = not quoted
        elif ch == ";" and not quoted:
            opts.append("".join(cur).strip())
            cur = []
    if "".join(cur).strip():
        opts.append("<unterminated>" + "".join(cur).strip())
    return opts


def validate_suricata_rule(rule: str) -> list[str]:
    """Syntactic check of a Suricata rule string; returns problems (empty = ok).

    Verifies header shape, balanced parentheses/quotes, that every option ends with ``;``,
    required ``msg`` / ``sid`` / ``rev``, and that content hex escapes are well formed.
    """
    problems: list[str] = []
    if not _HEADER_RE.match(rule):
        return ["bad header"]
    if not rule.endswith(";)"):
        problems.append("rule must end with ';)'")
    start = rule.index("(")
    body = rule[start + 1:-1] if rule.endswith(")") else rule[start + 1:]
    depth, quoted, esc = 0, False, False
    for ch in rule[start:]:
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
    if quoted:
        problems.append("unbalanced quotes")
    if depth != 0:
        problems.append("unbalanced parentheses")
    opts = _split_options(body)
    if any(o.startswith("<unterminated>") for o in opts):
        problems.append("option missing terminating ';'")
    names = [o.split(":", 1)[0].rstrip(";").strip() for o in opts]
    for req in ("msg", "sid", "rev", "classtype"):
        if req not in names:
            problems.append(f"missing {req}")
    for o in opts:
        if o.startswith("content:"):
            m = re.match(r'^content:"((?:[^"\\]|\\.)*)";$', o)
            if not m:
                problems.append(f"malformed content option: {o[:40]}")
                continue
            raw = m.group(1)
            if re.search(r'(?<!\\)[;"\\]', raw) or raw.count("|") % 2:
                problems.append("unescaped special character in content")
            for hx in re.findall(r"\|([^|]*)\|", raw):
                if not re.fullmatch(r"[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})*", hx):
                    problems.append(f"bad hex block in content: {hx!r}")
    return problems
