"""UniPhish Telegram bot: the messaging-app surface.

Forward or paste a suspicious link / message / email; get an instant explainable verdict
card. This module is only the I/O layer. What the bot *says* is decided by the pure,
Telegram-free :mod:`bot.reply`, and abuse limits live in :mod:`bot.limits`.

Run::

    pip install "uniphish[bot]"
    export TELEGRAM_BOT_TOKEN=<token from @BotFather>
    python -m bot.telegram_bot

Security posture: offline engine by default, verdicts are never persisted, links in
replies are always defanged, replies never echo the user's text, scans are rate-limited
per chat and uploads are size-capped.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from bot.limits import BotConfig, RateLimiter
from bot.reply import (
    ReplyCard,
    build_file_reply,
    build_reply_with_verdict,
    empty_card,
    pick_language,
)

try:  # python-telegram-bot is an optional extra: degrade clearly when absent
    from telegram import (
        InlineQueryResultArticle,
        InputTextMessageContent,
        LinkPreviewOptions,
        Update,
    )
    from telegram.constants import MessageEntityType, ParseMode
    from telegram.ext import (
        Application,
        ApplicationBuilder,
        CommandHandler,
        ContextTypes,
        InlineQueryHandler,
        MessageHandler,
        filters,
    )

    TELEGRAM_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    TELEGRAM_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover
    from telegram import Message

log = logging.getLogger("uniphish.bot")

INSTALL_HINT = (
    "python-telegram-bot is not installed. Install the bot extra: "
    'pip install "uniphish[bot]"  (or pip install "python-telegram-bot>=21")'
)
SERVICE_KEY = "uniphish.service"
MIN_INLINE_CHARS = 8

_WELCOME = {
    "en": (
        "UniPhish checks links, messages and emails for phishing.\n\n"
        "Send or forward me a suspicious link or message, or upload an .eml / .html "
        "file or a screenshot with a QR code. I reply with a risk verdict, the brand "
        "being impersonated, why, and what to do. Links in my replies are always "
        "defanged, so they are never clickable.\n\n"
        "In groups, reply to a message with /check. I do not store what you send."
    ),
}
_HELP = (
    "<b>UniPhish</b>\n"
    "• Send / forward text or a link: I scan the whole message.\n"
    "• Upload .eml, .html, any file, or a photo with a QR code.\n"
    "• In groups: /check (as a reply, or /check &lt;text&gt;).\n"
    "• Inline: type @botname &lt;link&gt; in any chat.\n\n"
    "Verdicts: \U0001f534 likely phishing, \U0001f7e0 suspicious, \U0001f7e2 no threat "
    "found (not a guarantee). Never share passwords or one-time codes."
)
_RATE_MSG = "Too many requests, please wait {n} s and try again."
_TOO_BIG_MSG = "That file is too large to scan (limit {mb:.1f} MB)."
_DOWNLOAD_FAIL_MSG = "I could not download that file. Please try again."
_DENIED_MSG = "This bot is private."


class BotService:
    """Shared state for the handlers: config, rate limiter and scan concurrency.

    Kept separate from the Telegram objects so it can be tested with plain fakes.
    """

    def __init__(self, config: BotConfig | None = None, *, analyst: Any = None) -> None:
        self.config = config or BotConfig.from_env()
        self.limiter = RateLimiter(self.config.rate_limit, self.config.rate_window_s)
        self._sem: asyncio.Semaphore | None = None
        self.analyst = analyst

    @property
    def sem(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.config.max_concurrent_scans)
        return self._sem

    async def scan_text(
        self, text: str, *, lang: str | None, extra_urls: tuple[str, ...] = ()
    ) -> ReplyCard:
        """Run the (blocking) engine in a worker thread, bounded by the semaphore."""
        cfg = self.config
        async with self.sem:
            card, verdict = await asyncio.to_thread(
                build_reply_with_verdict,
                text,
                lang=lang,
                extra_urls=extra_urls,
                online=cfg.online,
                fetch_pages=cfg.fetch_pages,
            )
        return await self._annotate(card, verdict)

    async def scan_file(self, data: bytes, filename: str | None, *, lang: str | None) -> ReplyCard:
        cfg = self.config
        async with self.sem:
            return await asyncio.to_thread(
                build_file_reply,
                data,
                filename,
                lang=lang,
                online=cfg.online,
                fetch_pages=cfg.fetch_pages,
            )

    async def _annotate(self, card: ReplyCard, verdict: Any) -> ReplyCard:
        """Optionally add a defanged AI analyst note; failures never affect the verdict."""
        if not (
            self.config.ai_note
            and verdict is not None
            and card.is_threat
            and self.analyst is not None
            and getattr(self.analyst, "available", False)
        ):
            return card
        try:
            note = await self.analyst.narrative(verdict)
        except Exception:
            log.warning("analyst note failed", exc_info=True)
            return card
        return card.with_note(note)


def _hidden_urls(message: Message) -> tuple[str, ...]:
    """URLs hidden behind "text link" entities (anchor text differs from the target)."""
    out: list[str] = []
    for ents in (message.entities, message.caption_entities):
        for e in ents or ():
            if e.type == MessageEntityType.TEXT_LINK and e.url:
                out.append(e.url)
    return tuple(dict.fromkeys(out))


def _message_text(message: Message) -> str:
    return message.text or message.caption or ""


def _service(context: ContextTypes.DEFAULT_TYPE) -> BotService:
    return context.application.bot_data[SERVICE_KEY]


def _lang_of(update: Update) -> str | None:
    user = update.effective_user
    return user.language_code if user else None


async def _reply_card(message: Message, card: ReplyCard) -> None:
    await message.reply_text(
        card.to_html(),
        parse_mode=ParseMode.HTML,
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )


async def _gate(update: Update, svc: BotService) -> bool:
    """Allow-list + rate limit. Replies (once per window) when denying."""
    message, chat = update.effective_message, update.effective_chat
    if message is None or chat is None:
        return False
    if not svc.config.permits(chat.id):
        await message.reply_text(_DENIED_MSG)
        return False
    decision = svc.limiter.check(chat.id)
    if not decision.allowed:
        if decision.notify:
            await message.reply_text(_RATE_MSG.format(n=int(decision.retry_after) + 1))
        return False
    return True


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(_WELCOME["en"])


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(
            _HELP,
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Private chats: scan every text message and forwarded message."""
    svc = _service(context)
    message = update.effective_message
    if message is None or not await _gate(update, svc):
        return
    text = _message_text(message)
    if not text.strip():
        await _reply_card(message, empty_card(pick_language(_lang_of(update))))
        return
    card = await svc.scan_text(text, lang=_lang_of(update), extra_urls=_hidden_urls(message))
    await _reply_card(message, card)


async def on_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """``/check`` in any chat: scans the replied-to message, or the command arguments."""
    svc = _service(context)
    message = update.effective_message
    if message is None or not await _gate(update, svc):
        return
    target = message.reply_to_message
    if target is not None:
        text, hidden = _message_text(target), _hidden_urls(target)
    else:
        text, hidden = " ".join(context.args or []), ()
    card = await svc.scan_text(text, lang=_lang_of(update), extra_urls=hidden)
    await _reply_card(message, card)


async def _download(file_obj: Any, svc: BotService) -> bytes | None:
    try:
        data = bytes(await file_obj.download_as_bytearray())
    except Exception:
        log.warning("file download failed", exc_info=True)
        return None
    return data if len(data) <= svc.config.max_file_bytes else b""


async def _scan_upload(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    tg_file: Any,
    size: int | None,
    filename: str | None,
) -> None:
    svc = _service(context)
    message = update.effective_message
    if message is None or not await _gate(update, svc):
        return
    cap = svc.config.max_file_bytes
    if size is not None and size > cap:
        await message.reply_text(_TOO_BIG_MSG.format(mb=cap / 1_000_000))
        return
    data = await _download(await tg_file.get_file(), svc)
    if data is None:
        await message.reply_text(_DOWNLOAD_FAIL_MSG)
        return
    if not data:
        await message.reply_text(_TOO_BIG_MSG.format(mb=cap / 1_000_000))
        return
    card = await svc.scan_file(data, filename, lang=_lang_of(update))
    await _reply_card(message, card)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc = update.effective_message.document if update.effective_message else None
    if doc is not None:
        await _scan_upload(update, context, tg_file=doc, size=doc.file_size, filename=doc.file_name)


async def on_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Photos are scanned as images, so QR-code (quishing) payloads are decoded."""
    message = update.effective_message
    if message is None or not message.photo:
        return
    best = message.photo[-1]
    await _scan_upload(update, context, tg_file=best, size=best.file_size, filename="photo.jpg")


async def on_inline(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Inline mode: ``@bot <link or text>`` answers with a verdict card (offline)."""
    query = update.inline_query
    if query is None:
        return
    svc = _service(context)
    text = (query.query or "").strip()
    if len(text) < MIN_INLINE_CHARS or not svc.limiter.check(query.from_user.id).allowed:
        await query.answer([], cache_time=1, is_personal=True)
        return
    card = await svc.scan_text(text, lang=query.from_user.language_code)
    result = InlineQueryResultArticle(
        id=(card.verdict_id or "0")[:64],
        title=f"{card.emoji} {card.headline}",
        description=f"{card.score}/100",
        input_message_content=InputTextMessageContent(
            card.to_html(),
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        ),
    )
    await query.answer([result], cache_time=30, is_personal=True)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log the exception type only: tracebacks can embed message text or the bot token."""
    log.error("handler error: %s", type(context.error).__name__)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #
def build_application(config: BotConfig | None = None, *, analyst: Any = None) -> Application:
    """Create the configured :class:`telegram.ext.Application` (does not start polling)."""
    if not TELEGRAM_AVAILABLE:
        raise RuntimeError(INSTALL_HINT)
    cfg = config or BotConfig.from_env()
    if not cfg.token:
        raise RuntimeError("Set TELEGRAM_BOT_TOKEN (get a token from @BotFather).")
    app = ApplicationBuilder().token(cfg.token).build()
    app.bot_data[SERVICE_KEY] = BotService(cfg, analyst=analyst)
    private = filters.ChatType.PRIVATE
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("check", on_check))
    app.add_handler(MessageHandler(private & filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(MessageHandler(private & filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(private & filters.PHOTO, on_photo))
    app.add_handler(InlineQueryHandler(on_inline))
    app.add_error_handler(on_error)
    return app


def main() -> None:
    """Entry point: ``python -m bot.telegram_bot``."""
    if not TELEGRAM_AVAILABLE:
        raise SystemExit(INSTALL_HINT)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # httpx logs full request URLs at INFO, and Telegram URLs contain the bot token.
    for noisy in ("httpx", "httpcore", "telegram.ext.Application"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    cfg = BotConfig.from_env()
    if not cfg.token:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN (get a token from @BotFather).")
    analyst = None
    if cfg.ai_note:
        from uniphish.ai import AIAnalyst

        analyst = AIAnalyst()
    app = build_application(cfg, analyst=analyst)
    log.info(
        "UniPhish bot polling (online=%s, rate=%s/%ss)",
        cfg.online,
        cfg.rate_limit,
        cfg.rate_window_s,
    )
    app.run_polling(allowed_updates=[Update.MESSAGE, Update.INLINE_QUERY])


if __name__ == "__main__":
    main()
