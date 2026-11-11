# Spec: Telegram bot (messaging surface)
OWN: everything under bot/ (rewrite bot/telegram_bot.py, bot/__init__.py, bot/README.md),
tests/bot/test_bot.py. Depends on the engine (scan_text/scan_url/scan_email) +
uniphish.ai.analyst (optional). python-telegram-bot (extra 'bot'); degrade clearly if
absent.

Realize the paper's messaging thesis: forward a suspicious link / message / forwarded
email text to the bot, get an instant explainable verdict in the message's language-ish.
- handlers: /start, /help; a text/message handler that extracts URLs + scans the whole
  text (ArtifactKind.TEXT so smishing language + links are analysed), replies with a
  compact verdict card: risk, level emoji, impersonated brand, top reasons (defanged
  links), MITRE tags, and 'what to do'. Handle forwarded messages and documents (scan an
  uploaded .eml/.html/file via scan_file/scan_email, size-capped). Inline query optional.
- All links in replies DEFANGED; never render a clickable phishing link. Rate-limit per
  chat; never echo credentials. Offline engine by default (no server-side fetch unless
  configured). Token from settings.telegram_bot_token / env.
- Structure so the scanning logic is unit-testable WITHOUT a live Telegram connection
  (separate a pure `build_reply(update_text) -> ReplyCard` function from the I/O handlers).
TESTS (offline): build_reply on a smishing text -> suspicious/malicious card with brand +
defanged link; benign greeting -> safe; a pasted homoglyph URL flagged; no network, no real
bot token (mock the telegram objects or test the pure builder).
