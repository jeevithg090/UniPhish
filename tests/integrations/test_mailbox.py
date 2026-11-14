"""Offline tests for the abuse-inbox processor (no real IMAP, no real network)."""

from __future__ import annotations

import asyncio
import imaplib
import json
import mailbox
import os
from datetime import date

import pytest

from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.engine import Engine
from uniphish.core.types import (
    Action,
    ArtifactKind,
    ArtifactTooLarge,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Verdict,
)
from uniphish.integrations.mailbox import (
    MailboxError,
    MailboxNetworkDisabled,
    MailboxProcessor,
    TriageSummary,
    _imap_date,
)
from uniphish.integrations.sinks import FileSink, StoreSink
from uniphish.store import Store

PHISH_EML = (
    b"Received: from mail.freemail.example (mail.freemail.example [203.0.113.55]) "
    b"by mx.recipient.test with ESMTP id z1; Wed, 05 Nov 2025 10:00:03 +0000\r\n"
    b"Authentication-Results: mx.recipient.test;\r\n"
    b" spf=pass smtp.mailfrom=sender@freemail.example;\r\n"
    b" dkim=pass header.d=freemail.example header.s=s1;\r\n"
    b" dmarc=pass (p=NONE) header.from=freemail.example\r\n"
    b'From: "support@paypal.com" <account.help9921@freemail.example>\r\n'
    b'Reply-To: "Account Help" <recover@collector.test>\r\n'
    b"To: victim@recipient.test\r\n"
    b"Subject: Action required: confirm your account\r\n"
    b"Date: Wed, 05 Nov 2025 10:00:00 +0000\r\n"
    b"Message-ID: <spoof1@freemail.example>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=us-ascii\r\n\r\n"
    b"Dear customer, verify now at hxxp://secure-login.example/verify or visit "
    b"www.account-check.test/login today.\r\n"
)


def eml(subject: str, body: str = "hello") -> bytes:
    return (
        f"From: a@sender.example\r\nTo: b@rcpt.example\r\nSubject: {subject}\r\n"
        f"Message-ID: <{abs(hash(subject))}@sender.example>\r\n"
        f"Date: Wed, 05 Nov 2025 10:00:00 +0000\r\n\r\n{body}\r\n"
    ).encode()


class FakeEngine:
    """Deterministic engine: the level is chosen from the subject line."""

    def __init__(self) -> None:
        self.seen: list[bytes] = []
        self.options: list[AnalysisOptions | None] = []

    async def analyze(self, artifact, options=None) -> Verdict:
        raw = artifact.content or b""
        self.seen.append(raw)
        self.options.append(options)
        text = raw.decode("utf-8", "replace")
        if "EXPLODE" in text:
            raise RuntimeError("analyzer exploded for victim@example.com")
        subject = next(
            (ln[9:].strip() for ln in text.splitlines() if ln.startswith("Subject:")), "(none)"
        )
        level = (
            Level.MALICIOUS
            if "phish" in subject.lower()
            else Level.SUSPICIOUS
            if "maybe" in subject.lower()
            else Level.BENIGN
        )
        score = {Level.MALICIOUS: 95, Level.SUSPICIOUS: 60, Level.BENIGN: 4}[level]
        bad = level is not Level.BENIGN
        return Verdict(
            kind=ArtifactKind.EMAIL,
            target=subject,
            artifact_id=artifact.id[:24],
            risk=score / 100,
            score=score,
            logit=2.0,
            level=level,
            action={
                Level.MALICIOUS: Action.BLOCK,
                Level.SUSPICIOUS: Action.WARN,
                Level.BENIGN: Action.ALLOW,
            }[level],
            confidence=0.9,
            summary=f"{level.value} message {subject}",
            meta={"subject": subject},
            brand=BrandMatch(brand="paypal", name="PayPal", technique="sender", confidence=0.9)
            if "paypal" in subject.lower()
            else None,
            indicators=[
                Indicator(
                    type=IndicatorType.URL, value="https://evil.example.test/x", malicious=True
                )
            ]
            if bad
            else [],
        )


@pytest.fixture
def engine() -> FakeEngine:
    return FakeEngine()


# --------------------------------------------------------------------------- #
# Single message through the real engine
# --------------------------------------------------------------------------- #
async def test_process_eml_bytes_persists_and_fans_out_with_real_engine(tmp_path):
    with Store(":memory:") as store:
        jsonl = tmp_path / "triage.jsonl"
        sink_store = Store(":memory:")
        # Generous budgets: the first analysis pays one-off asset/model load costs.
        proc = MailboxProcessor(
            Engine(),
            store,
            [FileSink(jsonl), StoreSink(sink_store)],
            options={"analyzer_timeout_s": 120.0, "timeout_s": 180.0},
        )
        verdict = await proc.aprocess_eml_bytes(PHISH_EML, source="fixture")

        assert verdict.kind is ArtifactKind.EMAIL
        assert verdict.level is not Level.BENIGN
        assert verdict.brand is not None and verdict.brand.brand == "paypal"
        assert verdict.origin == "mailbox"

        saved = store.get_verdict(verdict.id)
        assert saved is not None and saved.score == verdict.score
        assert store.get_verdict_row(verdict.id)["kind"] == "email"

        line = json.loads(jsonl.read_text().splitlines()[0])
        assert line["id"] == verdict.id
        assert "http://" not in jsonl.read_text()  # FileSink defangs by default

        assert sink_store.get_verdict(verdict.id) is not None
        sink_store.close()


def test_process_eml_bytes_sync_wrapper_and_inside_running_loop(engine):
    proc = MailboxProcessor(engine)
    v = proc.process_eml_bytes(eml("phish alert"))
    assert v.level is Level.MALICIOUS

    async def inside_loop() -> Verdict:
        return proc.process_eml_bytes(eml("plain note"))  # blocking call within a loop

    assert asyncio.run(inside_loop()).level is Level.BENIGN


async def test_oversized_single_message_is_rejected(engine):
    proc = MailboxProcessor(engine)
    with pytest.raises(ArtifactTooLarge):
        await proc.aprocess_eml_bytes(b"A" * (25_000_001))
    assert engine.seen == []


async def test_options_mapping_is_applied(engine):
    proc = MailboxProcessor(engine, options={"online": False, "max_depth": 1})
    await proc.aprocess_eml_bytes(eml("hi"))
    opts = engine.options[0]
    assert isinstance(opts, AnalysisOptions) and opts.online is False and opts.max_depth == 1


async def test_store_and_sink_failures_do_not_break_processing(engine, caplog):
    class BrokenStore:
        def save_verdict(self, *a, **k):
            raise RuntimeError("disk full")

    class BrokenSink:
        name, min_level = "broken", Level.BENIGN

        async def send(self, verdict):
            raise RuntimeError("sink down")

    proc = MailboxProcessor(engine, BrokenStore(), [BrokenSink()])
    with caplog.at_level("WARNING", logger="uniphish.integrations"):
        v = await proc.aprocess_eml_bytes(eml("phish now"))
    assert v.level is Level.MALICIOUS
    assert "could not persist" in caplog.text and "sink down" in caplog.text


# --------------------------------------------------------------------------- #
# Maildir / folder / mbox batches
# --------------------------------------------------------------------------- #
def _make_maildir(root, *, new=(), cur=()):
    for sub in ("tmp", "new", "cur"):
        (root / sub).mkdir(parents=True)
    for i, raw in enumerate(new):
        (root / "new" / f"1700000{i}.M1.host").write_bytes(raw)
    for i, raw in enumerate(cur):
        (root / "cur" / f"1700001{i}.M2.host:2,S").write_bytes(raw)
    return root


async def test_process_maildir_triage_summary(tmp_path, engine):
    root = _make_maildir(
        tmp_path / "Maildir",
        new=[eml("PayPal phish: verify now"), eml("maybe suspicious invoice")],
        cur=[eml("lunch on friday"), eml("Another PayPal phish")],
    )
    (root / "tmp" / "inflight").write_bytes(eml("phish in tmp must be ignored"))
    store = Store(":memory:")
    mem = FileSink(tmp_path / "all.jsonl")
    proc = MailboxProcessor(engine, store, [mem])
    summary = await proc.aprocess_maildir(root)

    assert isinstance(summary, TriageSummary)
    assert summary.total == 4 and summary.errors == 0 and summary.processed == 4
    assert summary.by_level == {"malicious": 2, "suspicious": 1, "benign": 1}
    assert summary.by_action == {"block": 2, "warn": 1, "allow": 1}
    assert summary.top_brands == [("PayPal", 2)]
    assert summary.top_iocs == [("url", "https://evil.example.test/x", 3)]
    assert len(summary.verdicts) == 4
    assert [i.score for i in summary.worst] == [95, 95, 60, 4]
    assert all(i.verdict_id and store.get_verdict(i.verdict_id) for i in summary.items)
    assert len((tmp_path / "all.jsonl").read_text().splitlines()) == 4
    assert not any("in tmp" in s.decode() for s in engine.seen)  # tmp/ never read
    store.close()


async def test_summary_rendering_and_dict_are_defanged(tmp_path, engine):
    root = _make_maildir(tmp_path / "md", new=[eml("PayPal phish: verify now")])
    summary = await MailboxProcessor(engine).aprocess_maildir(root)
    text = summary.render()
    assert "1/1 messages scanned" in text and "malicious=1" in text
    assert "PayPal (1)" in text and "hxxps://evil[.]example[.]test/x" in text
    assert "https://" not in text
    as_json = json.dumps(summary.to_dict())
    assert "https://" not in as_json and "hxxps://evil[.]example[.]test/x" in as_json
    assert "items" not in summary.to_dict(include_items=False)


async def test_flat_folder_filters_by_suffix_and_skips_hidden(tmp_path, engine):
    d = tmp_path / "reported"
    d.mkdir()
    (d / "a.eml").write_bytes(eml("phish one"))
    (d / "b.EML").write_bytes(eml("lunch"))
    (d / ".hidden.eml").write_bytes(eml("phish hidden"))
    (d / "notes.pdf").write_bytes(b"%PDF-1.4")
    (d / "sub").mkdir()
    summary = await MailboxProcessor(engine).aprocess_maildir(d)
    assert summary.total == 2 and summary.by_level == {"malicious": 1, "benign": 1}


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
async def test_maildir_skips_symlinks_and_records_per_file_errors(tmp_path, engine):
    secret = tmp_path / "secret.txt"
    secret.write_text("Subject: phish from a symlink target")
    root = _make_maildir(tmp_path / "md", new=[eml("phish ok"), eml("EXPLODE me")])
    (root / "new" / "link").symlink_to(secret)
    (root / "new" / "subdir").mkdir()
    summary = await MailboxProcessor(engine).aprocess_maildir(root)
    assert summary.total == 3 and summary.errors == 2  # subdir ignored silently
    assert summary.by_level == {"malicious": 1}
    errors = {i.source: i.error for i in summary.items if i.error}
    assert any("not a regular file" in e for e in errors.values())
    boom = next(e for s, e in errors.items() if "1700001" not in s and "RuntimeError" in e)
    assert "victim[@]example[.]com" in boom  # error text is defanged
    assert not any(b"symlink target" in s for s in engine.seen)
    assert "failed" in summary.render()


async def test_maildir_message_cap_and_missing_directory(tmp_path, engine):
    root = _make_maildir(tmp_path / "md", new=[eml(f"m{i}") for i in range(5)])
    proc = MailboxProcessor(engine, max_messages=3)
    assert (await proc.aprocess_maildir(root)).total == 3
    with pytest.raises(MailboxError, match="not a directory"):
        await proc.aprocess_maildir(tmp_path / "missing")


def test_blocking_maildir_and_mbox_wrappers(tmp_path, engine):
    root = _make_maildir(tmp_path / "md", new=[eml("phish a")])
    proc = MailboxProcessor(engine)
    assert proc.process_maildir(root).by_level == {"malicious": 1}

    path = tmp_path / "reports.mbox"
    box = mailbox.mbox(str(path))
    box.add(mailbox.mboxMessage(eml("PayPal phish")))
    box.add(mailbox.mboxMessage(eml("maybe later")))
    box.add(mailbox.mboxMessage(eml("hello")))
    box.flush()
    box.close()
    summary = proc.process_mbox(path)
    assert summary.total == 3
    assert summary.by_level == {"malicious": 1, "suspicious": 1, "benign": 1}
    assert [i.source for i in summary.items] == [
        "reports.mbox#0",
        "reports.mbox#1",
        "reports.mbox#2",
    ]
    capped = MailboxProcessor(engine, max_messages=2).process_mbox(path)
    assert capped.total == 2


async def test_mbox_rejects_non_files(tmp_path, engine):
    proc = MailboxProcessor(engine)
    with pytest.raises(MailboxError):
        await proc.aprocess_mbox(tmp_path)
    with pytest.raises(MailboxError):
        await proc.aprocess_mbox(tmp_path / "nope.mbox")


async def test_batch_with_real_engine_end_to_end(tmp_path):
    root = _make_maildir(tmp_path / "md", new=[PHISH_EML], cur=[eml("lunch on friday")])
    summary = await MailboxProcessor(Engine()).aprocess_maildir(root)
    assert summary.total == 2 and summary.errors == 0
    assert summary.worst[0].level != "benign"
    assert any(name == "PayPal" for name, _ in summary.top_brands)


# --------------------------------------------------------------------------- #
# IMAP (fully faked)
# --------------------------------------------------------------------------- #
class FakeIMAP:
    """Just enough of imaplib.IMAP4 for the poller; records every call."""

    def __init__(
        self,
        messages: dict[str, bytes],
        *,
        login_error: str | None = None,
        capabilities: tuple[str, ...] = ("IMAP4REV1",),
    ) -> None:
        self.messages = messages
        self.login_error = login_error
        self.capabilities = capabilities
        self.calls: list[tuple] = []
        self.logged_out = False

    def starttls(self, ssl_context=None):
        self.calls.append(("starttls",))
        return "OK", [b""]

    def login(self, user, password):
        self.calls.append(("login", user))
        if self.login_error:
            raise imaplib.IMAP4.error(self.login_error)
        return "OK", [b""]

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [b"3"]

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [" ".join(self.messages).encode()]
        if command == "FETCH":
            raw = self.messages[args[0]]
            return "OK", [(f"1 (BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        return "OK", [b""]

    def expunge(self):
        self.calls.append(("expunge",))
        return "OK", [b""]

    def close(self):
        self.calls.append(("close",))

    def logout(self):
        self.logged_out = True
        self.calls.append(("logout",))
        return "BYE", [b""]


def _factory_for(fake: FakeIMAP):
    seen: dict[str, object] = {}

    def factory(host: str, port: int, timeout: float):
        seen.update(host=host, port=port, timeout=timeout)
        return fake

    return factory, seen


async def test_imap_is_disabled_by_default_and_never_connects(engine):
    proc = MailboxProcessor(engine)
    called = []

    def factory(*a):
        called.append(a)
        raise AssertionError("must not connect")

    with pytest.raises(MailboxNetworkDisabled):
        await proc.poll_imap("imap.example.test", "u", "p", imap_factory=factory)
    assert called == []


async def test_imap_honours_global_online_setting(engine, monkeypatch):
    monkeypatch.setenv("UNIPHISH_ONLINE", "1")
    from uniphish.core.config import reset_settings

    reset_settings()
    fake = FakeIMAP({"7": eml("lunch")})
    factory, _ = _factory_for(fake)
    summary = await MailboxProcessor(engine).poll_imap(
        "imap.example.test", "u", "p", imap_factory=factory
    )
    assert summary.total == 1


async def test_imap_poll_scans_marks_seen_and_moves_only_successes(engine):
    fake = FakeIMAP({"11": eml("PayPal phish"), "12": eml("EXPLODE"), "13": eml("hello")})
    factory, seen = _factory_for(fake)
    store = Store(":memory:")
    proc = MailboxProcessor(engine, store)
    summary = await proc.poll_imap(
        "imap.example.test",
        "reports@corp.example",
        "hunter2-password",
        "Reports",
        move_to="Processed",
        since=date(2025, 11, 1),
        allow_network=True,
        imap_factory=factory,
    )

    assert seen["host"] == "imap.example.test" and seen["port"] == 993
    assert summary.total == 3 and summary.errors == 1
    assert summary.by_level == {"malicious": 1, "benign": 1}
    assert len(summary.verdicts) == 2
    assert all(store.get_verdict(v.id) for v in summary.verdicts)

    calls = fake.calls
    assert ("select", "Reports", False) in calls
    assert ("uid", "SEARCH", None, "UNSEEN", "SINCE", "01-Nov-2025") in calls
    assert ("uid", "FETCH", "11", "(BODY.PEEK[])") in calls  # PEEK: no implicit \Seen
    # copy+delete fallback (no MOVE capability) for the two successes only
    for uid in ("11", "13"):
        assert ("uid", "STORE", uid, "+FLAGS", "(\\Seen)") in calls
        assert ("uid", "COPY", uid, "Processed") in calls
        assert ("uid", "STORE", uid, "+FLAGS", "(\\Deleted)") in calls
    assert not any(c[:3] == ("uid", "STORE", "12") or c[:3] == ("uid", "COPY", "12") for c in calls)
    assert ("expunge",) in calls
    assert fake.logged_out
    assert [i.source for i in summary.items][:1] == ["imap:Reports/11"]
    store.close()


async def test_imap_uses_move_when_server_supports_it(engine):
    fake = FakeIMAP({"5": eml("hello")}, capabilities=("IMAP4REV1", "MOVE"))
    factory, _ = _factory_for(fake)
    await MailboxProcessor(engine).poll_imap(
        "imap.example.test",
        "u",
        "p",
        move_to="Done",
        allow_network=True,
        imap_factory=factory,
        mark_seen=False,
    )
    assert ("uid", "MOVE", "5", "Done") in fake.calls
    assert not any(c[:2] == ("uid", "COPY") for c in fake.calls)
    assert not any(c[:4] == ("uid", "STORE", "5", "+FLAGS") for c in fake.calls)
    assert ("expunge",) not in fake.calls


async def test_imap_without_ssl_requires_starttls_and_respects_limits(engine):
    fake = FakeIMAP({str(i): eml(f"m{i}") for i in range(1, 6)})
    factory, seen = _factory_for(fake)
    summary = await MailboxProcessor(engine).poll_imap(
        "imap.example.test",
        "u",
        "p",
        ssl=False,
        max_messages=2,
        allow_network=True,
        imap_factory=factory,
    )
    assert seen["port"] == 143
    assert fake.calls.index(("starttls",)) < fake.calls.index(("login", "u"))
    assert summary.total == 2
    assert sum(1 for c in fake.calls if c[:2] == ("uid", "FETCH")) == 2


async def test_imap_login_error_is_scrubbed_and_session_closed(engine):
    fake = FakeIMAP({}, login_error="LOGIN failed for hunter2-password")
    factory, _ = _factory_for(fake)
    with pytest.raises(MailboxError) as exc:
        await MailboxProcessor(engine).poll_imap(
            "imap.example.test", "u", "hunter2-password", allow_network=True, imap_factory=factory
        )
    assert "hunter2-password" not in str(exc.value) and "login failed" in str(exc.value)
    assert fake.logged_out


async def test_imap_select_failure(engine):
    fake = FakeIMAP({})
    fake.select = lambda folder, readonly=False: ("NO", [b"no such folder"])  # type: ignore[method-assign]
    factory, _ = _factory_for(fake)
    with pytest.raises(MailboxError, match="cannot select"):
        await MailboxProcessor(engine).poll_imap(
            "imap.example.test", "u", "p", "Nope", allow_network=True, imap_factory=factory
        )


def test_imap_date_is_locale_independent():
    assert _imap_date(date(2025, 3, 7)) == "07-Mar-2025"
    assert _imap_date(date(2026, 12, 31)) == "31-Dec-2026"
