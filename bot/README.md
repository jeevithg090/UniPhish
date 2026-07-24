# UniPhish Telegram bot

The messaging-app surface from the paper: forward or paste a link, get an instant
verdict — phishing risk, the **impersonated brand**, and **why** — in any language.

## Run it
```bash
pip install "python-telegram-bot>=20"
export TELEGRAM_BOT_TOKEN=<token from @BotFather>     # message @BotFather -> /newbot
export UNIPHISH_MODEL=artifacts/uniphish_adv.keras
python -m bot.telegram_bot
```
Then message your bot. Example reply:

```
🔴 Likely phishing — risk 100/100
`https://pаypаl.com/login`
🎯 disguised as paypal
• Uses the character "а", which looks like "a" but is a different Unicode letter.
• Domain disguises itself as “paypal”.
```

The bot loads the same model + enrichment as the API, so verdicts match the extension
and `/enrich` endpoint. It only reads URLs you send it and stores nothing.
