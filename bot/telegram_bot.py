"""UniPhish Telegram bot (Track D) — the messaging-app surface from the paper.

Forward or paste a suspicious link; get an instant verdict with the impersonated
brand and plain-language reasons. This realizes the paper's actual use case: links
arriving in a messaging app, in any language, where no gateway scans them.

Setup:
    pip install "python-telegram-bot>=20"
    export TELEGRAM_BOT_TOKEN=<token from @BotFather>
    export UNIPHISH_MODEL=artifacts/uniphish_adv.keras
    python -m bot.telegram_bot
"""

from __future__ import annotations

import os
import re

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (ApplicationBuilder, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from uniphish.enrich import fused_risk
from uniphish.infer import UniPhishScorer

MODEL = os.environ.get("UNIPHISH_MODEL", "artifacts/uniphish_adv.keras")
_URL_RE = re.compile(r"(https?://[^\s]+|(?:[\w¡-￿-]+\.)+[\w¡-￿-]{2,}(?:/[^\s]*)?)")
_EMOJI = {"block": "🔴", "warn": "🟠", "safe": "🟢"}
_LABEL = {"block": "Likely phishing", "warn": "Suspicious", "safe": "Looks safe"}

_scorer: UniPhishScorer | None = None


def scorer() -> UniPhishScorer:
    global _scorer
    if _scorer is None:
        _scorer = UniPhishScorer(MODEL)
    return _scorer


def _verdict(url: str) -> str:
    prob = scorer().scan(url)["prob"]
    r = fused_risk(prob, url)
    lines = [f"{_EMOJI[r['tier']]} *{_LABEL[r['tier']]}* — risk {r['risk']}/100",
             f"`{url}`"]
    if r["brand"]:
        typ = {"homoglyph": "disguised as", "typo": "lookalike of",
               "subdomain": "hides real domain behind"}.get(r["brand"]["type"], "impersonates")
        lines.append(f"🎯 {typ} *{r['brand']['brand']}*")
    for reason in r["reasons"][:4]:
        lines.append(f"• {reason['text']}")
    return "\n".join(lines)


async def start(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *UniPhish* — send or forward me a link and I'll tell you if it's phishing, "
        "which brand it's faking, and why. Works in any language.",
        parse_mode=ParseMode.MARKDOWN)


async def scan_message(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = [m.group(0) for m in _URL_RE.finditer(text)][:5]
    if not urls:
        await update.message.reply_text("Send me a URL to check. 🔎")
        return
    for url in urls:
        if not url.startswith("http"):
            url = "http://" + url
        await update.message.reply_text(_verdict(url), parse_mode=ParseMode.MARKDOWN,
                                        disable_web_page_preview=True)


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN (get one from @BotFather).")
    scorer()  # load model up front
    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_message))
    print("UniPhish bot polling…")
    app.run_polling()


if __name__ == "__main__":
    main()
