# Spec: multilingual social-engineering language model (lexical)
OWN: uniphish/nlp/__init__.py, uniphish/nlp/social_engineering.py,
uniphish/assets/se_lexicons.yaml, tests/nlp/test_social_engineering.py.

PURPOSE: score the *language* of a message/email body for social-engineering pressure —
the manipulation tactics phishing/BEC/smishing share — across many languages, without a
heavy ML dependency (lexicon + rules; deterministic, explainable).

se_lexicons.yaml: weighted term/phrase lexicons per tactic, each entry {lang, weight,
tactic}, covering tactics: urgency (act now, immediately, within 24 hours, expires),
threat/fear (account suspended, legal action, unauthorized login, will be deleted),
authority (IT department, security team, CEO, bank, government, compliance), reward/greed
(you won, refund, prize, gift card, inheritance), scarcity, secrecy/isolation
(confidential, do not tell, keep this between us — BEC), payment/action (wire transfer,
gift cards, pay invoice, update payment, buy, purchase), credential/verify (verify your
account, confirm your identity, re-enter your password), delivery/parcel, tax/refund,
tech-support (your computer is infected, call this number), crypto (seed phrase, wallet
validation, airdrop). Cover 20+ languages incl. English, es, pt, fr, de, it, ru, uk, tr,
ar, fa, hi (+ romanized), zh-Hans, zh-Hant, ja, ko, vi, id, th, nl, pl. All synthetic
example phrasing; inert.

social_engineering.py: analyze_text(text, *, lang_hint=None) -> SEResult(score (0..1
pressure), tactics: list[TacticHit(tactic, lang, weight, term, start, end)], languages
(detected scripts/guessed langs), dominant_tactic, has_call_to_action, has_credential_ask,
has_payment_ask, has_otp_ask (asks for a one-time code/2FA — strong smishing signal),
urgency_score, authority_score). Lightweight language guess from script + stopwords (no
heavy dep). One compiled linear-time multi-term matcher; Latin token-aware, CJK/other
substring. detect_otp_request(text) and detect_phone_number(text) -> list[str] (E.164-ish,
for callback/TOAD-style lures) helpers. Convert hits to log-odds-friendly weights.

TESTS: multilingual pressure phrases flagged with right tactic; OTP-ask detection; phone
extraction; benign text scores low; performance on 50KB.
