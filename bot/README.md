# UniPhish Telegram bot

The messaging-app surface: forward or paste a suspicious link, message or email and get
an instant, explainable verdict card (risk, impersonated brand, reasons, MITRE ATT&CK
tags, what to do). Cards are localised (en, es, fr, de, pt, ru, hi) from the message
language or the sender's Telegram language; the engine's reason titles stay in English.

## Run it
```bash
pip install "uniphish[bot]"                      # python-telegram-bot>=21
export TELEGRAM_BOT_TOKEN=<token from @BotFather>   # message @BotFather -> /newbot
python -m bot.telegram_bot
```

Without the extra installed the module still imports and `python -m bot.telegram_bot`
exits with an install hint; `bot.reply` (the verdict logic) never needs Telegram.

## What it handles
| Input | Behaviour |
|---|---|
| Text / forwarded message (private chat) | whole text scanned as a TEXT artifact (smishing language + every link), incl. URLs hidden behind Telegram "text link" anchors |
| `.eml` | email analyzer (headers, auth, links, attachments) |
| `.html` | page analyzer |
| any other document, photo | file analyzer (QR codes in images are decoded and followed) |
| `/check` (groups) | scans the replied-to message, or the command arguments |
| inline `@bot <link>` | one card result, offline |

Example reply (HTML parse mode, links defanged, no preview):
```
🔴 Likely phishing — Risk 100/100
🎯 Impersonates: PayPal

Why
• Message uses pressure tactics typical of phishing
• Message names PayPal but links to an unrelated site

Links
🔴 hxxps://paypal-secure-login[.]example[.]test/verify?…

What to do
Do not click, reply or enter any details. …
```

## Safety properties
* Every link is defanged (`hxxps://a[.]b`), stripped of user-info, query and fragment, and
  never clickable. User text is never echoed; secret-looking strings are redacted.
* Offline engine by default. Verdicts are **not persisted**. Message content is not logged.
* Per-chat sliding-window rate limit (one "slow down" reply per window), upload size cap,
  bounded scan concurrency, optional chat allow-list.

## Configuration (environment)
| Variable | Default | Meaning |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | - | bot token (`Settings.telegram_bot_token`) |
| `UNIPHISH_BOT_ONLINE` | 0 | enable DNS / RDAP / TLS / feed enrichment |
| `UNIPHISH_BOT_FETCH` | 0 | fetch linked pages (requires online) |
| `UNIPHISH_BOT_AI` | 0 | add an AI analyst note when `ANTHROPIC_API_KEY` is set |
| `UNIPHISH_BOT_RATE` / `_RATE_WINDOW` | 10 / 60 | scans per window per chat (0 disables) |
| `UNIPHISH_BOT_MAX_FILE_BYTES` | 5000000 | upload cap |
| `UNIPHISH_BOT_CONCURRENCY` | 4 | parallel scans |
| `UNIPHISH_BOT_ALLOWED_CHATS` | all | comma-separated chat ids |

## Layout
* `bot/reply.py` - pure `build_reply(text) -> ReplyCard`, `build_file_reply`, defanging.
* `bot/limits.py` - `BotConfig`, `RateLimiter`.
* `bot/telegram_bot.py` - handlers and wiring (thin I/O layer).

Tests: `python -m pytest tests/bot -q` (offline; Telegram objects are fakes).
