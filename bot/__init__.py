"""UniPhish Telegram bot package.

The Telegram-free reply logic (:func:`build_reply`, :class:`ReplyCard`) is exported here
lazily so ``import bot`` works without ``python-telegram-bot`` installed. The I/O layer
is :mod:`bot.telegram_bot`.
"""

from __future__ import annotations

from typing import Any

_EXPORTS = {
    "build_reply": "bot.reply",
    "build_file_reply": "bot.reply",
    "ReplyCard": "bot.reply",
    "defang_url": "bot.reply",
    "defang_text": "bot.reply",
    "BotConfig": "bot.limits",
    "RateLimiter": "bot.limits",
}
__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    mod = _EXPORTS.get(name)
    if mod is None:
        raise AttributeError(f"module 'bot' has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(mod), name)
