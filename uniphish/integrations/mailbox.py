"""Abuse-inbox processor: turn a pile of user-reported phish into verdicts and a triage.

Security teams run an "report phishing" mailbox; people forward suspicious mail to it.
:class:`MailboxProcessor` scans each message with the UniPhish engine, persists the
verdict, fans it out to the configured sinks (:mod:`uniphish.integrations.sinks`) and
produces a :class:`TriageSummary` (counts by level, top impersonated brands and IOCs) so an
analyst can start with the worst items.

Inputs
------
* a single raw message: :meth:`MailboxProcessor.process_eml_bytes`
* a Maildir or a flat folder of ``.eml`` files: :meth:`process_maildir`
* an mbox file: :meth:`process_mbox`
* a live IMAP mailbox: :meth:`poll_imap` (network; off unless explicitly enabled)

Safety
------
Reported mail is hostile by definition. Messages are only ever parsed and analysed, never
rendered or executed, and the engine's own bounds apply. File ingestion reads regular
files only (symlinks are skipped so a planted link cannot pull in an arbitrary file),
skips anything above the engine's e-mail size limit and caps the number of messages.
Per-message failures are recorded in the summary and never abort a batch. The IMAP poller
refuses to touch the network unless ``allow_network=True`` (or ``UNIPHISH_ONLINE=1``),
requires TLS (``ssl=True`` or STARTTLS), never logs the password and scrubs it from errors.
The IMAP host is operator configuration, not attacker input, so it is not subject to the
SSRF filter that guards webhook sinks.
"""

from __future__ import annotations

import asyncio
import contextlib
import imaplib
import logging
import mailbox as _stdlib_mailbox
import ssl as _ssl
import threading
from collections import Counter
from collections.abc import Callable, Coroutine, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, TypeVar

from uniphish.ai.prompts import defang
from uniphish.core import events
from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.config import get_settings
from uniphish.core.types import MAX_EMAIL_BYTES, Artifact, Level, Verdict
from uniphish.integrations.sinks import Sink, SinkResult, fan_out

log = logging.getLogger("uniphish.integrations")

__all__ = [
    "MailboxError",
    "MailboxNetworkDisabled",
    "MailboxProcessor",
    "TriageItem",
    "TriageSummary",
]

T = TypeVar("T")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_EML_SUFFIXES = frozenset({".eml", ".msg", ".txt", ""})
DEFAULT_MAX_MESSAGES = 10_000


class MailboxError(RuntimeError):
    """A mailbox operation failed (message text is scrubbed of credentials)."""


class MailboxNetworkDisabled(MailboxError):
    """Raised when IMAP polling is attempted without network being enabled."""


# --------------------------------------------------------------------------- #
# Triage summary
# --------------------------------------------------------------------------- #
@dataclass
class TriageItem:
    """One processed message (or the reason it could not be processed)."""

    source: str
    verdict_id: str | None = None
    level: str | None = None
    score: int | None = None
    action: str | None = None
    brand: str | None = None
    subject: str | None = None
    error: str | None = None
    sinks: list[SinkResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": defang(self.source, 300), "verdict_id": self.verdict_id,
            "level": self.level, "score": self.score, "action": self.action,
            "brand": self.brand, "subject": defang(self.subject or "", 200) or None,
            "error": self.error,
            "sinks": [{"sink": r.sink, "status": r.status, "error": r.error}
                      for r in self.sinks],
        }


@dataclass
class TriageSummary:
    """Aggregate view of a batch: counts by level/action, top brands and IOCs."""

    total: int = 0
    errors: int = 0
    by_level: dict[str, int] = field(default_factory=dict)
    by_action: dict[str, int] = field(default_factory=dict)
    top_brands: list[tuple[str, int]] = field(default_factory=list)
    top_iocs: list[tuple[str, str, int]] = field(default_factory=list)  # (type, value, n)
    items: list[TriageItem] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list, repr=False)

    @property
    def processed(self) -> int:
        return self.total - self.errors

    @property
    def worst(self) -> list[TriageItem]:
        """Successfully scanned items, highest score first."""
        scored = [i for i in self.items if i.error is None]
        return sorted(scored, key=lambda i: (-(i.score or 0), i.source))

    def to_dict(self, *, include_items: bool = True) -> dict[str, Any]:
        """JSON-safe form. Free text and IOCs are defanged; verdict objects are omitted."""
        out: dict[str, Any] = {
            "total": self.total, "processed": self.processed, "errors": self.errors,
            "by_level": dict(self.by_level), "by_action": dict(self.by_action),
            "top_brands": [[b, n] for b, n in self.top_brands],
            "top_iocs": [[t, defang(v, 300) if t in _TEXTUAL_IOCS else v, n]
                         for t, v, n in self.top_iocs],
        }
        if include_items:
            out["items"] = [i.to_dict() for i in self.items]
        return out

    def render(self, *, limit: int = 10) -> str:
        """Plain-text triage report (defanged), worst first."""
        lines = [f"UniPhish triage: {self.processed}/{self.total} messages scanned"
                 + (f", {self.errors} failed" if self.errors else "")]
        order = [lv.value for lv in (Level.MALICIOUS, Level.SUSPICIOUS, Level.BENIGN)]
        lines.append("levels: " + ", ".join(f"{lv}={self.by_level.get(lv, 0)}" for lv in order))
        if self.top_brands:
            lines.append("brands: " + ", ".join(f"{b} ({n})" for b, n in self.top_brands))
        if self.top_iocs:
            lines.append("top IOCs:")
            lines += [f"  {t:<7} {defang(v, 200) if t in _TEXTUAL_IOCS else v}  x{n}"
                      for t, v, n in self.top_iocs]
        worst = self.worst[:limit]
        if worst:
            lines.append("worst first:")
            lines += [f"  {i.score:>3} {i.level:<10} {defang(i.subject or i.source, 80)}"
                      for i in worst]
        return "\n".join(lines)


_TEXTUAL_IOCS = frozenset({"url", "domain", "email", "filename"})
_IOC_TYPES_SKIPPED = frozenset({"user_agent", "asn", "cert_sha256"})


def build_summary(items: Sequence[TriageItem], verdicts: Sequence[Verdict], *,
                  top_n: int = 10) -> TriageSummary:
    """Aggregate ``verdicts`` into a :class:`TriageSummary`."""
    by_level = Counter(v.level.value for v in verdicts)
    by_action = Counter(v.action.value for v in verdicts)
    brands: Counter[str] = Counter()
    iocs: Counter[tuple[str, str]] = Counter()
    for v in verdicts:
        if v.level is Level.BENIGN:
            continue
        if v.brand is not None and not v.brand.official:
            brands[v.brand.name] += 1
        for ind in v.all_indicators():
            if ind.malicious is False or ind.type.value in _IOC_TYPES_SKIPPED:
                continue
            if ind.malicious is True or v.level is Level.MALICIOUS:
                iocs[(ind.type.value, ind.value)] += 1
    return TriageSummary(
        total=len(items), errors=sum(1 for i in items if i.error),
        by_level=dict(by_level), by_action=dict(by_action),
        top_brands=brands.most_common(top_n),
        top_iocs=[(t, val, n) for (t, val), n in
                  sorted(iocs.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]],
        items=list(items), verdicts=list(verdicts),
    )


# --------------------------------------------------------------------------- #
# Sync bridge
# --------------------------------------------------------------------------- #
def _run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run ``coro`` to completion from sync code, even inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: dict[str, Any] = {}

    def _worker() -> None:
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:  # re-raised in the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


# --------------------------------------------------------------------------- #
# Processor
# --------------------------------------------------------------------------- #
class MailboxProcessor:
    """Scan reported e-mail, persist the verdicts and fan them out to sinks.

    Args:
        engine: object with ``async analyze(artifact, options) -> Verdict`` (default: the
            shared :func:`uniphish.core.engine.default_engine`).
        store: optional :class:`uniphish.store.Store`; verdicts are saved with
            ``source="mailbox"``. Persistence errors are logged, never raised.
        sinks: sinks that receive every verdict (each honours its own ``min_level``).
        options: :class:`AnalysisOptions` (or a mapping for ``from_dict``); offline by default.
        max_concurrency: messages analysed in parallel during batch runs.
        max_messages: hard cap on messages per batch (maildir / mbox / IMAP).
    """

    def __init__(
        self,
        engine: Any = None,
        store: Any = None,
        sinks: Iterable[Sink] = (),
        *,
        options: AnalysisOptions | Mapping[str, Any] | None = None,
        max_concurrency: int = 4,
        max_messages: int = DEFAULT_MAX_MESSAGES,
    ) -> None:
        self._engine = engine
        self.store = store
        self.sinks: tuple[Sink, ...] = tuple(sinks)
        if isinstance(options, Mapping):
            options = AnalysisOptions.from_dict(dict(options))
        self.options: AnalysisOptions = options or AnalysisOptions()
        self._sem_size = max(1, int(max_concurrency))
        self.max_messages = max(1, int(max_messages))

    @property
    def engine(self) -> Any:
        if self._engine is None:
            from uniphish.core.engine import default_engine

            self._engine = default_engine()
        return self._engine

    # ---- single message ------------------------------------------------- #
    async def aprocess_eml_bytes(self, raw: bytes | str, *, source: str = "eml") -> Verdict:
        """Scan one raw message, persist it and deliver it to the sinks.

        Raises:
            uniphish.core.types.ArtifactTooLarge: message exceeds the engine's size limit.
        """
        artifact = Artifact.from_email(raw, origin="mailbox")
        verdict = await self.engine.analyze(artifact, self.options)
        await self._deliver(verdict, source)
        return verdict

    def process_eml_bytes(self, raw: bytes | str, *, source: str = "eml") -> Verdict:
        """Blocking form of :meth:`aprocess_eml_bytes`."""
        return _run_sync(self.aprocess_eml_bytes(raw, source=source))

    async def _deliver(self, verdict: Verdict, source: str) -> list[SinkResult]:
        if self.store is not None:
            try:
                await asyncio.to_thread(self.store.save_verdict, verdict, source="mailbox")
            except Exception:
                log.exception("could not persist verdict %s from %s", verdict.id,
                              defang(source, 120))
        if not self.sinks:
            return []
        return await fan_out(verdict, self.sinks)

    # ---- batches --------------------------------------------------------- #
    async def _process_many(self, messages: Iterable[tuple[str, bytes | Exception]]
                            ) -> TriageSummary:
        sem = asyncio.Semaphore(self._sem_size)

        async def one(source: str, raw: bytes | Exception) -> tuple[TriageItem, Verdict | None]:
            if isinstance(raw, Exception):
                return TriageItem(source, error=_err(raw)), None
            async with sem:
                try:
                    artifact = Artifact.from_email(raw, origin="mailbox")
                    verdict = await self.engine.analyze(artifact, self.options)
                except Exception as exc:
                    log.warning("scan of %s failed: %s", defang(source, 120), _err(exc))
                    return TriageItem(source, error=_err(exc)), None
                results = await self._deliver(verdict, source)
            return _item_for(source, verdict, results), verdict

        pairs = await asyncio.gather(*(one(s, r) for s, r in messages))
        summary = build_summary([p[0] for p in pairs],
                                [p[1] for p in pairs if p[1] is not None])
        events.publish("mailbox.triage", {"total": summary.total, "errors": summary.errors,
                                          "by_level": summary.by_level})
        return summary

    async def aprocess_maildir(self, path: str | Path) -> TriageSummary:
        """Triage a Maildir (``new/`` + ``cur/``) or a flat folder of message files."""
        messages = await asyncio.to_thread(
            lambda: list(_read_folder(Path(path), self.max_messages)))
        return await self._process_many(messages)

    def process_maildir(self, path: str | Path) -> TriageSummary:
        """Blocking form of :meth:`aprocess_maildir`."""
        return _run_sync(self.aprocess_maildir(path))

    async def aprocess_mbox(self, path: str | Path) -> TriageSummary:
        """Triage every message in an mbox file."""
        messages = await asyncio.to_thread(
            lambda: list(_read_mbox(Path(path), self.max_messages)))
        return await self._process_many(messages)

    def process_mbox(self, path: str | Path) -> TriageSummary:
        """Blocking form of :meth:`aprocess_mbox`."""
        return _run_sync(self.aprocess_mbox(path))

    # ---- IMAP ------------------------------------------------------------ #
    async def poll_imap(
        self,
        host: str,
        user: str,
        password: str,
        folder: str = "INBOX",
        *,
        move_to: str | None = None,
        since: date | datetime | None = None,
        port: int | None = None,
        ssl: bool = True,
        mark_seen: bool = True,
        max_messages: int | None = None,
        timeout: float = 30.0,
        allow_network: bool | None = None,
        imap_factory: Callable[[str, int, float], imaplib.IMAP4] | None = None,
    ) -> TriageSummary:
        """Fetch unseen messages from an IMAP folder, scan them and act on them.

        Messages are fetched with ``BODY.PEEK`` (so a crash never loses "unseen" state).
        Only messages that were scanned successfully are marked ``\\Seen`` and, when
        ``move_to`` is given, moved there; failures stay in place for a retry.

        Network access must be enabled explicitly (``allow_network=True`` or the global
        ``UNIPHISH_ONLINE=1``); otherwise :class:`MailboxNetworkDisabled` is raised.
        ``ssl=False`` is only accepted together with a successful STARTTLS upgrade.
        ``imap_factory(host, port, timeout)`` is the test injection point.
        """
        enabled = get_settings().online if allow_network is None else allow_network
        if not enabled:
            raise MailboxNetworkDisabled(
                "IMAP polling needs network access: pass allow_network=True or set "
                "UNIPHISH_ONLINE=1")
        limit = min(self.max_messages, max_messages or self.max_messages)
        session = _ImapSession(host, user, password, folder, port=port, use_ssl=ssl,
                               timeout=timeout, factory=imap_factory)
        try:
            await asyncio.to_thread(session.open)
            fetched = await asyncio.to_thread(session.fetch_unseen, since, limit)
            summary = await self._process_many(
                (f"imap:{folder}/{uid}", raw) for uid, raw in fetched)
            done = [uid for (uid, _), item in zip(fetched, summary.items, strict=True)
                    if item.error is None]
            await asyncio.to_thread(session.finalize, done, move_to, mark_seen)
            return summary
        finally:
            await asyncio.to_thread(session.close)


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {defang(str(exc), 200)}"


def _item_for(source: str, verdict: Verdict, results: list[SinkResult]) -> TriageItem:
    brand = verdict.brand.name if verdict.brand and not verdict.brand.official else None
    subject = verdict.meta.get("subject") if isinstance(verdict.meta, dict) else None
    return TriageItem(
        source=source, verdict_id=verdict.id, level=verdict.level.value, score=verdict.score,
        action=verdict.action.value, brand=brand,
        subject=str(subject) if subject else verdict.target, sinks=list(results))


# --------------------------------------------------------------------------- #
# File readers
# --------------------------------------------------------------------------- #
def _read_file(path: Path) -> bytes | Exception:
    try:
        if path.is_symlink() or not path.is_file():
            return ValueError("not a regular file")
        if path.stat().st_size > MAX_EMAIL_BYTES:
            return ValueError(f"message larger than {MAX_EMAIL_BYTES} bytes")
        return path.read_bytes()
    except OSError as exc:
        return exc


def _is_candidate(path: Path) -> bool:
    """Skip real directories silently; symlinks stay candidates so they are reported."""
    return path.is_symlink() or not path.is_dir()


def _read_folder(root: Path, limit: int) -> Iterable[tuple[str, bytes | Exception]]:
    if not root.is_dir():
        raise MailboxError(f"not a directory: {root.name!r}")
    subdirs = [root / n for n in ("new", "cur") if (root / n).is_dir()]
    files: list[Path] = []
    if subdirs:  # Maildir layout (tmp/ is in-flight delivery and ignored)
        for sub in subdirs:
            files += sorted(p for p in sub.iterdir()
                            if not p.name.startswith(".") and _is_candidate(p))
    else:
        files = sorted(p for p in root.iterdir()
                       if not p.name.startswith(".") and p.suffix.lower() in _EML_SUFFIXES
                       and _is_candidate(p))
    if len(files) > limit:
        log.warning("%s holds %d messages; processing the first %d", root.name, len(files), limit)
    for path in files[:limit]:
        yield (f"{path.parent.name}/{path.name}" if subdirs else path.name), _read_file(path)


def _read_mbox(path: Path, limit: int) -> Iterable[tuple[str, bytes | Exception]]:
    if path.is_symlink() or not path.is_file():
        raise MailboxError(f"not a regular mbox file: {path.name!r}")
    box = _stdlib_mailbox.mbox(str(path), create=False)
    try:
        for count, key in enumerate(box.iterkeys()):
            if count >= limit:
                log.warning("mbox %s has more than %d messages; stopping", path.name, limit)
                break
            try:
                raw = box.get_bytes(key)
            except Exception as exc:  # corrupt entry: record, keep going
                yield f"{path.name}#{key}", exc
                continue
            if len(raw) > MAX_EMAIL_BYTES:
                yield f"{path.name}#{key}", ValueError(
                    f"message larger than {MAX_EMAIL_BYTES} bytes")
            else:
                yield f"{path.name}#{key}", raw
    finally:
        box.close()


# --------------------------------------------------------------------------- #
# IMAP (blocking imaplib, driven from worker threads)
# --------------------------------------------------------------------------- #
def _imap_date(value: date | datetime) -> str:
    """RFC 3501 date (``01-Nov-2025``), locale-independent."""
    return f"{value.day:02d}-{_MONTHS[value.month - 1]}-{value.year:04d}"


class _ImapSession:
    """One IMAP login. Methods are blocking and run via ``asyncio.to_thread``."""

    def __init__(self, host: str, user: str, password: str, folder: str, *, port: int | None,
                 use_ssl: bool, timeout: float,
                 factory: Callable[[str, int, float], imaplib.IMAP4] | None) -> None:
        self._host, self._user, self._password, self._folder = host, user, password, folder
        self._ssl = use_ssl
        self._port = port or (993 if use_ssl else 143)
        self._timeout = timeout
        self._factory = factory
        self._conn: imaplib.IMAP4 | None = None
        self._can_move = False

    def _scrub(self, text: object) -> str:
        out = str(text)
        for secret in (self._password,):
            if secret:
                out = out.replace(secret, "***")
        return out

    def _make(self) -> imaplib.IMAP4:
        if self._factory is not None:
            return self._factory(self._host, self._port, self._timeout)
        if self._ssl:
            return imaplib.IMAP4_SSL(self._host, self._port, timeout=self._timeout,
                                     ssl_context=_ssl.create_default_context())
        return imaplib.IMAP4(self._host, self._port, timeout=self._timeout)

    def open(self) -> None:
        stage = "connect"
        try:
            conn = self._make()
            self._conn = conn
            if not self._ssl:
                stage = "starttls"
                conn.starttls(ssl_context=_ssl.create_default_context())
            stage = "login"
            conn.login(self._user, self._password)
            stage = "select"
            status, _ = conn.select(self._folder, readonly=False)
            if status != "OK":
                raise MailboxError(f"cannot select folder {defang(self._folder, 80)!r}")
            with contextlib.suppress(Exception):
                self._can_move = b"MOVE" in b" ".join(
                    x if isinstance(x, bytes) else str(x).encode() for x in conn.capabilities)
        except MailboxError:
            raise
        except (imaplib.IMAP4.error, OSError, _ssl.SSLError) as exc:
            raise MailboxError(f"IMAP {stage} failed: {type(exc).__name__}: "
                               f"{self._scrub(exc)}") from None

    def fetch_unseen(self, since: date | datetime | None, limit: int
                     ) -> list[tuple[str, bytes | Exception]]:
        conn = self._need()
        criteria = ["UNSEEN"] + (["SINCE", _imap_date(since)] if since else [])
        status, data = conn.uid("SEARCH", None, *criteria)
        if status != "OK":
            raise MailboxError("IMAP search failed")
        uids = [u.decode() for u in (data[0] or b"").split()][:limit]
        out: list[tuple[str, bytes | Exception]] = []
        for uid in uids:
            try:
                status, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")
                raw = next((p[1] for p in parts or [] if isinstance(p, tuple)), None)
                if status != "OK" or not isinstance(raw, (bytes, bytearray)):
                    out.append((uid, MailboxError("fetch failed")))
                elif len(raw) > MAX_EMAIL_BYTES:
                    out.append((uid, ValueError("message too large")))
                else:
                    out.append((uid, bytes(raw)))
            except (imaplib.IMAP4.error, OSError) as exc:
                out.append((uid, MailboxError(f"fetch failed: {type(exc).__name__}")))
        return out

    def finalize(self, uids: Sequence[str], move_to: str | None, mark_seen: bool) -> None:
        conn = self._need()
        try:
            for uid in uids:
                if mark_seen:
                    conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
                if move_to:
                    if self._can_move:
                        conn.uid("MOVE", uid, move_to)
                    else:
                        status, _ = conn.uid("COPY", uid, move_to)
                        if status == "OK":
                            conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            if move_to and not self._can_move and uids:
                conn.expunge()
        except (imaplib.IMAP4.error, OSError) as exc:
            raise MailboxError(f"IMAP post-processing failed: {type(exc).__name__}: "
                               f"{self._scrub(exc)}") from None

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        with contextlib.suppress(Exception):
            conn.close()
        with contextlib.suppress(Exception):
            conn.logout()

    def _need(self) -> imaplib.IMAP4:
        if self._conn is None:
            raise MailboxError("IMAP session is not open")
        return self._conn
