"""Offline tests for the Telegram bot: pure reply builder, limits and handler wiring.

No network and no real bot token: the engine runs offline and Telegram objects are fakes.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import bot
from bot import reply as R
from bot.limits import BotConfig, RateLimiter

SMISH = ("Your PayPal account is suspended! Verify now: "
         "https://paypal-secure-login.example.test/verify?session=abcdef0123456789abcdef0123456789 "
         "or lose access within 24 hours. Reply with the code we sent.")
HOMOGLYPH = "check this https://pаypal.com/signin"   # Cyrillic a


# ------------------------------- defanging ---------------------------------- #
def test_defang_url_strips_query_userinfo_and_brackets_dots():
    out = R.defang_url("https://user:pw@Evil.Example.test:8443/a/b?token=SECRET#frag")
    assert out == "hxxps://Evil[.]Example[.]test:8443/a/b?…"
    assert "SECRET" not in out and "pw@" not in out and "user" not in out
    assert "." not in out.replace("[.]", "")


def test_defang_url_ftp_and_schemeless_and_long():
    assert R.defang_url("ftp://a.example.test/x").startswith("fxp://")
    assert R.defang_url("a.example.test/x") == "a[.]example[.]test/x"
    assert len(R.defang_url("https://a.test/" + "x" * 5000)) <= 120


def test_defang_text_idempotent_and_redacts():
    s = R.defang_text("see http://a.example.test and mail me@x.test password=hunter2")
    assert "hxxp://a[.]example[.]test" in s and "me[@]x[.]test" in s
    assert "hunter2" not in s and "password=[redacted]" in s
    assert R.defang_text(s) == s


def test_redact_card_numbers_and_opaque_tokens():
    assert "4111" not in R.redact("card 4111 1111 1111 1111 ok")
    assert "[redacted]" in R.redact("key " + "A" * 40)


def test_clean_removes_bidi_and_zero_width():
    assert R.clean("a‮b​c\x00d") == "abcd"


# ------------------------------- build_reply -------------------------------- #
def test_smishing_text_card_is_threat_with_brand_and_defanged_link():
    card = R.build_reply(SMISH)
    assert card.level in {"suspicious", "malicious"} and card.score >= 50
    assert card.brand == "PayPal"
    assert card.reasons and len(card.reasons) <= R.MAX_REASONS
    assert card.links and card.links[0].text.startswith("hxxps://paypal-secure-login[.]example[.]test")
    html = card.to_html()
    assert "http://" not in html and "https://" not in html
    assert "abcdef0123456789" not in html and "session" not in html   # query never echoed
    assert "T1566" in html and "PayPal" in html
    assert card.advice in html


def test_benign_greeting_is_safe():
    card = R.build_reply("Hi, are we still on for lunch tomorrow?")
    assert card.level == "benign" and card.emoji == R.LEVEL_EMOJI["benign"]
    assert card.brand is None and not card.reasons and not card.links
    assert "Risk" in card.to_html()


def test_homoglyph_url_is_flagged():
    card = R.build_reply(HOMOGLYPH)
    assert card.level == "malicious"
    assert card.brand == "PayPal"
    assert any("xn--" in ln.text for ln in card.links)
    assert "https://" not in card.to_html()


def test_empty_and_whitespace_give_none_card():
    for t in ("", "   \n", None):
        c = R.build_reply(t)
        assert c.level == "none" and c.score == 0
        assert "Risk" not in c.to_html()


def test_hidden_text_link_url_is_scanned():
    plain = R.build_reply("Click paypal.com to continue")
    hidden = R.build_reply("Click paypal.com to continue",
                           extra_urls=["https://pаypal.com/signin"])
    assert hidden.score > plain.score and hidden.level == "malicious"


def test_card_never_echoes_user_text():
    secret = "Zq9-unique-marker-777"
    card = R.build_reply(f"{SMISH} {secret}")
    assert secret not in card.to_html()


def test_html_escaping_of_dynamic_values():
    card = R.ReplyCard(level="suspicious", score=60, headline="<b>x</b>", advice="a<b",
                       reasons=("<script>",), subject="<i>s</i>")
    out = card.to_html()
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "&lt;b&gt;x&lt;/b&gt;" in out
    assert "<b>x</b>" not in out


def test_to_text_has_no_markup():
    t = R.build_reply(SMISH).to_text()
    assert "<b>" not in t and "<code>" not in t and "&amp;" not in t


def test_card_fits_telegram_limit_on_huge_input():
    card = R.build_reply(SMISH * 400)
    assert len(card.to_html()) <= R.MAX_CARD_CHARS


def test_engine_failure_yields_conservative_card():
    def boom(*a, **k):
        raise RuntimeError("engine down")

    card = R.build_reply("hello http://a.example.test", scan=boom)
    assert card.level == "suspicious" and card.kind == "error"


def test_scan_called_offline_and_without_persistence():
    seen = {}

    def spy(text, **opts):
        seen.update(opts)
        import uniphish
        return uniphish.scan_text("hello", **opts)

    R.build_reply("hello there", scan=spy)
    assert seen["online"] is False and seen["persist"] is False and seen["fetch_pages"] is False
    R.build_reply("hello there", online=True, fetch_pages=True, scan=spy)
    assert seen["online"] is True and seen["fetch_pages"] is True
    R.build_reply("hello there", online=False, fetch_pages=True, scan=spy)
    assert seen["fetch_pages"] is False   # fetching requires online


def test_verdict_not_persisted():
    from uniphish.store import get_store

    R.build_reply(SMISH)
    assert get_store().stats()["verdicts"] == 0


# ------------------------------- languages ---------------------------------- #
def test_pick_language():
    assert R.pick_language("pt-BR") == "pt"
    assert R.pick_language(None, ["xx", "es"]) == "es"
    assert R.pick_language("zz") == "en"
    assert R.pick_language(None) == "en"


def test_spanish_text_gets_spanish_card():
    card = R.build_reply("Su cuenta ha sido suspendida, verifique ahora o perderá el acceso "
                         "https://paypal-secure-login.example.test/verify")
    assert card.lang == "es"
    assert "Qué hacer" in card.to_html()


def test_language_hint_wins_for_benign():
    card = R.build_reply("hello how are you", lang="de")
    assert card.lang == "de" and card.headline == "Keine Bedrohung gefunden"


def test_every_language_has_every_key():
    base = set(R._STRINGS["en"])
    for code, table in R._STRINGS.items():
        assert set(table) == base, code


# ------------------------------- files --------------------------------------- #
EML = (b"From: PayPal Support <support@paypal-secure-login.example.test>\r\n"
       b"To: victim@example.test\r\nSubject: Account suspended <urgent>\r\n"
       b"Date: Mon, 01 Jan 2024 10:00:00 +0000\r\nMessage-ID: <1@example.test>\r\n"
       b"Content-Type: text/plain\r\n\r\n"
       b"Verify now or lose access: https://paypal-secure-login.example.test/verify\r\n")


def test_classify_upload():
    assert R.classify_upload(b"x", "a.EML") == "email"
    assert R.classify_upload(b"<!DOCTYPE html><html>", "n") == "page"
    assert R.classify_upload(b"x", "a.htm") == "page"
    assert R.classify_upload(b"MZ", "a.exe") == "file"


def test_eml_upload_scanned_as_email():
    card = R.build_file_reply(EML, "msg.eml")
    assert card.kind == "email"
    assert card.subject and "<" not in card.subject or "&lt;" not in card.subject
    assert "https://" not in card.to_html()


def test_html_upload_scanned_as_page():
    page = (b"<html><body><form action='https://c.example.test/p'>"
            b"<input type=password></form></body></html>")
    card = R.build_file_reply(page, "login.html")
    assert card.kind == "page"


def test_plain_file_and_empty():
    assert R.build_file_reply(b"hello world", "notes.txt").kind == "file"
    assert R.build_file_reply(b"", "x").level == "none"


def test_file_scan_failure_is_conservative():
    def boom(*a, **k):
        raise RuntimeError("x")

    card = R.build_file_reply(b"abc", "a.bin", scan_file=boom)
    assert card.level == "suspicious" and card.kind == "error"


# ------------------------------- limits -------------------------------------- #
def test_rate_limiter_window_and_notify_once():
    now = [0.0]
    rl = RateLimiter(2, 10.0, clock=lambda: now[0])
    assert rl.check(1).allowed and rl.check(1).allowed
    d = rl.check(1)
    assert not d.allowed and d.notify and 0 < d.retry_after <= 10
    d2 = rl.check(1)
    assert not d2.allowed and not d2.notify      # no reply spam
    assert rl.check(2).allowed                   # other chats unaffected
    now[0] = 10.5
    assert rl.check(1).allowed                   # window slid


def test_rate_limiter_disabled_and_bounded_memory():
    assert RateLimiter(0).check(1).allowed
    rl = RateLimiter(5, 60, max_chats=3)
    for i in range(50):
        rl.check(i)
    assert len(rl) == 3


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:fake")
    monkeypatch.setenv("UNIPHISH_BOT_RATE", "3")
    monkeypatch.setenv("UNIPHISH_BOT_ALLOWED_CHATS", "5, -100, x")
    monkeypatch.setenv("UNIPHISH_BOT_ONLINE", "yes")
    from uniphish.core.config import reset_settings

    reset_settings()
    cfg = BotConfig.from_env()
    assert cfg.token == "123:fake" and cfg.rate_limit == 3 and cfg.online
    assert cfg.allowed_chats == {5, -100} and cfg.permits(5) and not cfg.permits(6)
    assert "123:fake" not in repr(cfg)
    assert BotConfig().permits(999)


def test_lazy_package_exports():
    assert bot.build_reply is R.build_reply
    with pytest.raises(AttributeError):
        bot.nope


# ------------------------------- handlers (fakes) ---------------------------- #
_PURE_TESTS = {n for n in globals() if n.startswith("test_")}
try:
    import bot.telegram_bot as tb
except ImportError:  # pragma: no cover
    tb = None
HAVE_TG = tb is not None and tb.TELEGRAM_AVAILABLE


class FakeMessage:
    def __init__(self, text=None, *, entities=None, caption=None, document=None, photo=None,
                 reply_to=None):
        self.text, self.caption = text, caption
        self.entities, self.caption_entities = entities or [], []
        self.document, self.photo, self.reply_to_message = document, photo or [], reply_to
        self.sent: list[tuple[str, dict]] = []

    async def reply_text(self, text, **kw):
        self.sent.append((text, kw))


def make_update(msg, chat_id=1, lang="en"):
    return SimpleNamespace(effective_message=msg, effective_chat=SimpleNamespace(id=chat_id),
                           effective_user=SimpleNamespace(language_code=lang), inline_query=None)


def make_ctx(cfg=None, args=None, analyst=None):
    app = SimpleNamespace(bot_data={})
    app.bot_data[tb.SERVICE_KEY] = tb.BotService(cfg or BotConfig(rate_limit=100), analyst=analyst)
    return SimpleNamespace(application=app, args=args or [])


def run(coro):
    return asyncio.run(coro)


def test_on_text_replies_with_html_card_and_no_preview():
    msg = FakeMessage(SMISH)
    run(tb.on_text(make_update(msg), make_ctx()))
    text, kw = msg.sent[0]
    assert "hxxps://" in text and "https://" not in text
    assert kw["parse_mode"] == "HTML" and kw["link_preview_options"].is_disabled


def test_on_text_uses_hidden_text_link_entities():
    from telegram import MessageEntity

    ent = MessageEntity(type="text_link", offset=6, length=10, url="https://pаypal.com/x")
    msg = FakeMessage("Click paypal.com now", entities=[ent])
    run(tb.on_text(make_update(msg), make_ctx()))
    assert "xn--" in msg.sent[0][0]


def test_rate_limit_notifies_once():
    msg = FakeMessage("hello there friend")
    ctx = make_ctx(BotConfig(rate_limit=1, rate_window_s=60))
    upd = make_update(msg)
    for _ in range(4):
        run(tb.on_text(upd, ctx))
    assert len(msg.sent) == 2 and "Too many" in msg.sent[1][0]


def test_allowlist_denies():
    msg = FakeMessage("hello there friend")
    ctx = make_ctx(BotConfig(allowed_chats=frozenset({42})))
    run(tb.on_text(make_update(msg, chat_id=7), ctx))
    assert msg.sent == [("This bot is private.", {})]


def test_check_command_uses_reply_target_and_args():
    target = FakeMessage(SMISH)
    msg = FakeMessage("/check", reply_to=target)
    run(tb.on_check(make_update(msg), make_ctx()))
    assert "PayPal" in msg.sent[0][0]
    msg2 = FakeMessage("/check")
    run(tb.on_check(make_update(msg2), make_ctx(args=["hello", "friend", "how", "are", "you"])))
    assert "Risk" in msg2.sent[0][0]
    msg3 = FakeMessage("/check")
    run(tb.on_check(make_update(msg3), make_ctx()))
    assert msg3.sent[0][0].startswith(R.LEVEL_EMOJI["none"])


class FakeTgFile:
    def __init__(self, data, size=None):
        self.data, self.file_size, self.file_name = data, size, "msg.eml"

    async def get_file(self):
        return SimpleNamespace(download_as_bytearray=self._dl)

    async def _dl(self):
        return bytearray(self.data)


def test_document_size_cap_and_scan():
    cfg = BotConfig(rate_limit=100, max_file_bytes=1000)
    big = FakeMessage(document=FakeTgFile(b"x" * 10, size=5000))
    run(tb.on_document(make_update(big), make_ctx(cfg)))
    assert "too large" in big.sent[0][0]
    # declared size lies; the actual download is checked too
    liar = FakeMessage(document=FakeTgFile(b"x" * 5000, size=10))
    run(tb.on_document(make_update(liar), make_ctx(cfg)))
    assert "too large" in liar.sent[0][0]
    ok = FakeMessage(document=FakeTgFile(EML, size=len(EML)))
    run(tb.on_document(make_update(ok), make_ctx(BotConfig(rate_limit=100))))
    assert "hxxps" in ok.sent[0][0] or "Risk" in ok.sent[0][0]


def test_photo_is_scanned_without_crash():
    import io

    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (40, 40), "white").save(buf, "PNG")
    raw = buf.getvalue()
    photo = SimpleNamespace(file_size=len(raw), get_file=FakeTgFile(raw).get_file)
    msg = FakeMessage(photo=[photo])
    run(tb.on_photo(make_update(msg), make_ctx()))
    assert msg.sent and "Risk" in msg.sent[0][0]


def test_ai_note_added_defanged_and_failures_ignored():
    class Analyst:
        available = True

        async def narrative(self, verdict):
            return "Looks like http://evil.example.test credential theft"

    cfg = BotConfig(rate_limit=100, ai_note=True)
    msg = FakeMessage(SMISH)
    run(tb.on_text(make_update(msg), make_ctx(cfg, analyst=Analyst())))
    assert "hxxp://evil[.]example[.]test" in msg.sent[0][0]

    class Broken(Analyst):
        async def narrative(self, verdict):
            raise RuntimeError("down")

    msg2 = FakeMessage(SMISH)
    run(tb.on_text(make_update(msg2), make_ctx(cfg, analyst=Broken())))
    assert "PayPal" in msg2.sent[0][0]


def test_build_application_requires_token(monkeypatch):
    with pytest.raises(RuntimeError, match="TELEGRAM_BOT_TOKEN"):
        tb.build_application(BotConfig(token=None))


def test_build_application_registers_handlers():
    app = tb.build_application(BotConfig(token="123456:TEST-not-a-real-token"))
    assert tb.SERVICE_KEY in app.bot_data
    assert sum(len(v) for v in app.handlers.values()) >= 7


def test_handlers_do_not_block_other_work():
    # scanning runs in a thread: the event loop stays responsive meanwhile
    async def go():
        svc = tb.BotService(BotConfig(rate_limit=100))
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0)

        t = asyncio.create_task(ticker())
        card = await svc.scan_text(SMISH, lang="en")
        t.cancel()
        return card, ticks

    start = time.monotonic()
    card, ticks = run(go())
    assert card.is_threat and ticks > 1 and time.monotonic() - start < 30


# Handler tests need python-telegram-bot; the pure tests above always run.
for _name, _fn in list(globals().items()):
    if _name.startswith("test_") and _name not in _PURE_TESTS:
        globals()[_name] = pytest.mark.skipif(
            not HAVE_TG, reason="python-telegram-bot not installed")(_fn)
