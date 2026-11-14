"""Header-only email authentication analysis (SPF / DKIM / DMARC / ARC) and sender-spoof helpers.

Why this exists: whether a message genuinely came from the domain it claims is the
single strongest legitimacy (and, when it fails, phishing) signal in email. This module
reads what the *receiving* MTA already recorded in ``Authentication-Results`` (RFC 8601)
and ``Received-SPF`` (RFC 7208) and computes DMARC-style identifier alignment between
the RFC 5322 ``From`` domain and the authenticated SPF / DKIM domains. It performs **no
DNS and no cryptography**: live SPF/DKIM verification is the infra analyzer's job when
online. A ``DKIM-Signature`` header with no matching verdict is reported only as an
*unverified* signing domain.

Trust model: ``Authentication-Results`` headers can be forged by a sender. Only results
carrying the same authserv-id as the topmost header (the one the final receiver
prepends) are used; others are ignored and noted in ``notes``. If the receiver added no
such header at all, there is nothing to trust, and the notes say so.

Everything is robust to missing, duplicated and garbled headers and never raises.
Regexes are linear and applied to length-bounded strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal

from uniphish.mail.parse import ParsedEmail

Status = Literal["pass", "fail", "none", "softfail", "neutral", "temperror", "permperror"]

_STATUSES = {"pass", "fail", "none", "softfail", "neutral", "temperror", "permperror"}
_STATUS_ALIASES = {
    "hardfail": "fail",
    "unknown": "neutral",
    "policy": "neutral",
    "error": "temperror",
    "bestguesspass": "neutral",
}
MAX_AUTH_HEADER_CHARS = 8_000
MAX_AUTH_HEADERS = 20


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class SPFResult:
    status: Status = "none"
    domain: str = ""  # RFC 5321.MailFrom (or HELO) domain that was evaluated
    helo: str = ""
    client_ip: str = ""
    aligned: bool = False  # status == pass and domain aligns with From
    source: str = ""  # "authentication-results" | "received-spf" | ""


@dataclass
class DKIMSignatureResult:
    status: Status = "none"
    domain: str = ""  # d=
    selector: str = ""  # s=
    identity: str = ""  # i=
    aligned: bool = False


@dataclass
class DKIMResult:
    status: Status = "none"  # best across signatures (pass > fail > others)
    signatures: list[DKIMSignatureResult] = field(default_factory=list)
    unverified_domains: list[str] = field(default_factory=list)  # d= of DKIM-Signature headers
    aligned: bool = False  # some passing signature aligns with From


@dataclass
class DMARCResult:
    status: Status = "none"
    policy: str = ""  # p= as reported by the receiver ("none"/"quarantine"/"reject")
    header_from: str = ""
    aligned: bool = False  # *computed* alignment, see AuthResult.dmarc_aligned


@dataclass
class ARCInfo:
    present: bool = False
    instances: int = 0
    chain_validation: str = ""  # cv= of the highest-instance ARC-Seal
    sealers: list[str] = field(default_factory=list)


@dataclass
class AuthResult:
    spf: SPFResult = field(default_factory=SPFResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    arc: ARCInfo = field(default_factory=ARCInfo)
    from_domain: str = ""
    authserv_id: str = ""
    has_auth_results: bool = False
    spf_aligned: bool = False
    dkim_aligned: bool = False
    dmarc_aligned: bool = False  # (SPF pass & aligned) or (DKIM pass & aligned)
    authenticated_domain: str = ""  # aligned domain that actually passed, else ""
    notes: list[str] = field(default_factory=list)

    @property
    def fully_failed(self) -> bool:
        """Receiver evidence says the message did not authenticate as its From domain."""
        return not self.dmarc_aligned and (
            self.dmarc.status == "fail" or "fail" in (self.spf.status, self.dkim.status)
        )


# --------------------------------------------------------------------------- #
# Domain helpers
# --------------------------------------------------------------------------- #
def _norm_domain(value: str) -> str:
    """Domain part of an address-or-domain, lower-cased, no trailing dot or brackets."""
    v = value.strip().strip("<>\"' ")
    if "@" in v:
        v = v.rpartition("@")[2]
    return v.strip().rstrip(".").lower()


@lru_cache(maxsize=2048)
def org_domain(domain: str) -> str:
    """Registrable (organizational) domain for relaxed alignment, PSL-aware.

    For IPs the host itself is used; for suffixes the PSL does not know (reserved TLDs)
    the last two labels are used.
    """
    d = _norm_domain(domain)
    if not d:
        return ""
    from uniphish.url.parse import parse_url  # lazy: PSL load

    try:
        p = parse_url("http://" + d)
    except Exception:
        return d
    if p.registrable_domain and p.suffix:
        return p.registrable_domain
    host = p.host or d
    labels = host.split(".")
    if not p.is_ip and len(labels) > 2:
        # Suffix unknown to the PSL (reserved TLDs like .example/.test, internal names):
        # assume a single-label suffix so mail.corp.example aligns with corp.example.
        return ".".join(labels[-2:])
    return host


def domains_aligned(a: str, b: str) -> bool:
    """DMARC relaxed alignment: same organizational domain (and both non-empty)."""
    oa, ob = org_domain(a), org_domain(b)
    return bool(oa) and oa == ob


# --------------------------------------------------------------------------- #
# Header parsing
# --------------------------------------------------------------------------- #
_PAIR_RE = re.compile(
    r'([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s*=\s*("(?:[^"\\]{0,512}|\\.){0,8}"|[^\s;]{0,512})'
)
_POLICY_RE = re.compile(r"(?i)\bp\s*=\s*([A-Za-z]{3,12})")


def _strip_comments(s: str) -> tuple[str, list[str]]:
    """Remove (possibly nested) RFC 5322 comments; return (text, comment strings)."""
    out: list[str] = []
    comments: list[str] = []
    depth = 0
    buf: list[str] = []
    in_quote = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and (depth or in_quote):
            if depth:
                buf.append(s[i : i + 2])
            else:
                out.append(s[i : i + 2])
            i += 2
            continue
        if c == '"' and depth == 0:
            in_quote = not in_quote
            out.append(c)
        elif c == "(" and not in_quote:
            if depth == 0:
                buf = []
            depth += 1
            if depth > 1:
                buf.append(c)
        elif c == ")" and depth:
            depth -= 1
            if depth == 0:
                comments.append("".join(buf))
                out.append(" ")
            else:
                buf.append(c)
        elif depth:
            buf.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out), comments


def _split_semicolons(s: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    in_quote = False
    depth = 0
    for c in s:
        if c == '"' and depth == 0:
            in_quote = not in_quote
        elif c == "(" and not in_quote:
            depth += 1
        elif c == ")" and depth and not in_quote:
            depth -= 1
        if c == ";" and not in_quote and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


def _norm_status(v: str) -> tuple[Status, bool]:
    v = v.strip().strip('"').lower()
    v = _STATUS_ALIASES.get(v, v)
    if v in _STATUSES:
        return v, True  # type: ignore[return-value]
    return "none", False


@dataclass
class _Resinfo:
    method: str
    status: Status
    props: dict[str, str]
    comments: list[str]


def _parse_auth_results(value: str) -> tuple[str, list[_Resinfo], bool]:
    """Parse one Authentication-Results value -> (authserv_id, resinfos, had_garbage)."""
    chunks = _split_semicolons(value[:MAX_AUTH_HEADER_CHARS])
    head = _strip_comments(chunks[0])[0].split() if chunks else []
    authserv = head[0].strip().lower() if head else ""
    garbage = False
    infos: list[_Resinfo] = []
    for raw_chunk in chunks[1:]:
        chunk, comments = _strip_comments(raw_chunk)
        chunk = chunk.strip()
        if not chunk or chunk.lower() == "none":
            continue
        pairs = _PAIR_RE.findall(chunk)
        if not pairs:
            garbage = True
            continue
        method, result = pairs[0]
        status, ok = _norm_status(result)
        if not ok:
            garbage = True
        props = {k.lower(): v.strip().strip('"') for k, v in pairs[1:]}
        infos.append(_Resinfo(method.lower(), status, props, comments))
    return authserv, infos, garbage


_SPF_STATUS_RE = re.compile(r"^\s*([A-Za-z]{3,10})\b")


def _parse_received_spf(value: str) -> tuple[Status, dict[str, str]]:
    value = value[:MAX_AUTH_HEADER_CHARS]
    text, _ = _strip_comments(value)
    m = _SPF_STATUS_RE.match(text)
    status, _ok = _norm_status(m.group(1)) if m else ("none", False)
    kv = {k.lower().replace("_", "-"): v.strip('"') for k, v in _PAIR_RE.findall(text)}
    return status, kv


_RANK = {
    "pass": 5,
    "fail": 4,
    "softfail": 3,
    "permperror": 2,
    "temperror": 2,
    "neutral": 1,
    "none": 0,
}


def _best(statuses: list[Status]) -> Status:
    return max(statuses, key=lambda s: _RANK[s], default="none")


_DKIM_D_RE = re.compile(r"(?i)(?:^|[\s;])d\s*=\s*([A-Za-z0-9._-]{1,255})")
_ARC_I_RE = re.compile(r"(?i)(?:^|[\s;])i\s*=\s*(\d{1,3})")
_ARC_CV_RE = re.compile(r"(?i)(?:^|[\s;])cv\s*=\s*([A-Za-z]{3,10})")


# --------------------------------------------------------------------------- #
# Main entry
# --------------------------------------------------------------------------- #
def analyze_auth(email: ParsedEmail) -> AuthResult:
    """Derive SPF/DKIM/DMARC/ARC status and From-alignment from headers. Never raises."""
    try:
        return _analyze(email)
    except Exception as exc:  # defensive: hostile headers must not break analysis
        res = AuthResult(from_domain=_norm_domain(email.from_.domain))
        res.notes.append(f"auth_parse_error:{type(exc).__name__}")
        return res


def _analyze(email: ParsedEmail) -> AuthResult:
    res = AuthResult(from_domain=_norm_domain(email.from_.domain))
    notes = res.notes
    if not res.from_domain:
        notes.append("no_from_domain")

    # ---- Authentication-Results: trust only the topmost authserv-id ---------
    ar_values = email.header_values("Authentication-Results")[:MAX_AUTH_HEADERS]
    trusted: list[_Resinfo] = []
    ignored = 0
    for v in ar_values:
        sid, infos, garbage = _parse_auth_results(v)
        if garbage:
            notes.append("garbled_authentication_results")
        if not res.authserv_id:
            res.authserv_id = sid
            res.has_auth_results = True
        if sid == res.authserv_id:
            trusted.extend(infos)
        else:
            ignored += 1
    if ignored:
        notes.append(f"ignored_untrusted_authentication_results:{ignored}")
    if not ar_values:
        notes.append("no_authentication_results")

    # ---- SPF ------------------------------------------------------------------
    spf_infos = [i for i in trusted if i.method == "spf"]
    if spf_infos:
        i = spf_infos[0]
        res.spf.status = i.status
        res.spf.source = "authentication-results"
        mailfrom = i.props.get("smtp.mailfrom", "")
        res.spf.helo = i.props.get("smtp.helo", "").lower()
        res.spf.domain = _norm_domain(mailfrom) or res.spf.helo
        res.spf.client_ip = i.props.get("smtp.client-ip", "")
    rspf = email.header_values("Received-SPF")
    if rspf:
        status, kv = _parse_received_spf(rspf[0])
        if not spf_infos:
            res.spf.status = status
            res.spf.source = "received-spf"
            res.spf.domain = _norm_domain(kv.get("envelope-from", "")) or _norm_domain(
                kv.get("helo", "")
            )
            res.spf.helo = kv.get("helo", "").lower()
            res.spf.client_ip = kv.get("client-ip", "")
        elif status != res.spf.status and status in _STATUSES:
            notes.append("spf_header_disagreement")
    if res.spf.status != "none" and not res.spf.domain:
        # No envelope sender in the verdict: fall back to Return-Path.
        res.spf.domain = _norm_domain(email.return_path)
        if not res.spf.domain:
            notes.append("spf_domain_unknown")
    res.spf.aligned = res.spf.status == "pass" and domains_aligned(res.spf.domain, res.from_domain)

    # ---- DKIM -----------------------------------------------------------------
    for i in (x for x in trusted if x.method == "dkim"):
        d = _norm_domain(i.props.get("header.d", "")) or _norm_domain(i.props.get("header.i", ""))
        sig = DKIMSignatureResult(
            status=i.status,
            domain=d,
            selector=i.props.get("header.s", ""),
            identity=i.props.get("header.i", ""),
            aligned=i.status == "pass" and domains_aligned(d, res.from_domain),
        )
        res.dkim.signatures.append(sig)
    res.dkim.status = _best([s.status for s in res.dkim.signatures])
    res.dkim.aligned = any(s.aligned for s in res.dkim.signatures)
    for v in email.header_values("DKIM-Signature")[:MAX_AUTH_HEADERS]:
        m = _DKIM_D_RE.search(v[:MAX_AUTH_HEADER_CHARS])
        if m:
            d = _norm_domain(m.group(1))
            if d and d not in res.dkim.unverified_domains:
                res.dkim.unverified_domains.append(d)
    if res.dkim.unverified_domains and not res.dkim.signatures:
        notes.append("dkim_signature_present_but_unverified")

    # ---- DMARC ----------------------------------------------------------------
    dm = [i for i in trusted if i.method == "dmarc"]
    res.spf_aligned = res.spf.aligned
    res.dkim_aligned = res.dkim.aligned
    res.dmarc_aligned = res.spf_aligned or res.dkim_aligned
    res.dmarc.aligned = res.dmarc_aligned
    if dm:
        i = dm[0]
        res.dmarc.status = i.status
        res.dmarc.header_from = _norm_domain(i.props.get("header.from", ""))
        pol = i.props.get("policy.published-domain-policy", "")
        if not pol:
            for c in i.comments:
                m = _POLICY_RE.search(c[:500])
                if m:
                    pol = m.group(1)
                    break
        res.dmarc.policy = pol.lower()
        if (
            res.dmarc.header_from
            and res.from_domain
            and not domains_aligned(res.dmarc.header_from, res.from_domain)
        ):
            notes.append("dmarc_header_from_mismatch")
        if i.status == "pass" and not res.dmarc_aligned:
            notes.append("dmarc_pass_but_unaligned_in_headers")
        elif i.status == "fail" and res.dmarc_aligned:
            notes.append("dmarc_fail_but_aligned_in_headers")

    # ---- authenticated domain ---------------------------------------------------
    for s in res.dkim.signatures:
        if s.aligned:
            res.authenticated_domain = s.domain
            break
    if not res.authenticated_domain and res.spf.aligned:
        res.authenticated_domain = res.spf.domain

    # ---- ARC ------------------------------------------------------------------
    seals = email.header_values("ARC-Seal")[:MAX_AUTH_HEADERS]
    if seals or email.header_values("ARC-Message-Signature"):
        res.arc.present = True
        best_i, cv = -1, ""
        for v in seals:
            v = v[:MAX_AUTH_HEADER_CHARS]
            mi, mc, md = _ARC_I_RE.search(v), _ARC_CV_RE.search(v), _DKIM_D_RE.search(v)
            idx = int(mi.group(1)) if mi else 0
            if md:
                d = _norm_domain(md.group(1))
                if d and d not in res.arc.sealers:
                    res.arc.sealers.append(d)
            if idx > best_i:
                best_i, cv = idx, (mc.group(1).lower() if mc else "")
        res.arc.instances = len(seals)
        res.arc.chain_validation = cv
    for i in (x for x in trusted if x.method == "arc"):
        res.arc.present = True
        if not res.arc.chain_validation:
            res.arc.chain_validation = i.status

    if res.arc.present and res.arc.chain_validation == "pass" and res.fully_failed:
        notes.append("arc_pass_but_direct_auth_failed")
    return res


# --------------------------------------------------------------------------- #
# Spoofing helpers
# --------------------------------------------------------------------------- #
_EMAIL_IN_NAME_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5})"
)
_DOMAIN_IN_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9@._-])((?:www\.)?[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5})"
    r"(?![A-Za-z0-9-])"
)
# Bare dotted tokens in a display name ("John.Smith") are only treated as domains when the
# suffix is a well-known one, or the token is an explicit email address / www. host.
_COMMON_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "xyz",
        "info",
        "biz",
        "online",
        "site",
        "shop",
        "store",
        "us",
        "uk",
        "de",
        "fr",
        "es",
        "it",
        "nl",
        "ru",
        "cn",
        "jp",
        "in",
        "br",
        "au",
        "ca",
        "ch",
        "se",
        "no",
        "fi",
        "dk",
        "pl",
        "be",
        "at",
        "ie",
        "nz",
        "za",
        "mx",
        "kr",
        "tv",
        "me",
        "cc",
        "top",
        "club",
        "live",
        "tech",
        "cloud",
    }
)


def display_name_domains(email: ParsedEmail) -> list[str]:
    """Domains (registrable) that the From *display name* itself mentions."""
    name = email.from_.display_name[:300]
    if not name:
        return []
    found: list[str] = []
    for m in _EMAIL_IN_NAME_RE.finditer(name):
        found.append(m.group(1).lower())
    for m in _DOMAIN_IN_NAME_RE.finditer(name):
        host = m.group(1).lower()
        if host.startswith("www."):
            found.append(host)
            continue
        suffix = _icann_suffix(host)
        if suffix and ("." in suffix or suffix in _COMMON_TLDS):
            found.append(host)
    out: list[str] = []
    for h in found:
        o = org_domain(h)
        if o and o not in out:
            out.append(o)
    return out


@lru_cache(maxsize=1024)
def _icann_suffix(host: str) -> str:
    from uniphish.url.parse import parse_url

    try:
        return parse_url("http://" + host).icann_suffix
    except Exception:
        return ""


def display_name_domain_mismatches(email: ParsedEmail) -> list[str]:
    """Domains named in the display name that do not align with the real From domain."""
    real = email.from_.domain
    return [d for d in display_name_domains(email) if not domains_aligned(d, real)]


def from_display_name_contains_other_domain(email: ParsedEmail) -> bool:
    """True if the From display name embeds a domain/address of a *different* site.

    Classic spoof: ``"billing@paypal.com" <x@freemail.example>``. A display name that
    mentions the sender's own domain is fine.
    """
    try:
        return bool(display_name_domain_mismatches(email))
    except Exception:
        return False


def reply_to_differs_from_from(email: ParsedEmail, *, same_domain_ok: bool = True) -> bool:
    """True if a Reply-To address points somewhere other than the From address.

    With ``same_domain_ok`` (default) only a different *organizational domain* counts
    (support@ vs no-reply@ on one domain is normal); otherwise any address difference.
    """
    frm = email.from_
    if not frm.addr or not email.reply_to:
        return False
    for r in email.reply_to:
        if not r.addr:
            continue
        if same_domain_ok:
            if not domains_aligned(r.domain, frm.domain):
                return True
        elif r.addr.lower() != frm.addr.lower():
            return True
    return False
