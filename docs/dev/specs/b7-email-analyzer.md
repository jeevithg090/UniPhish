# Spec: email analyzer (headers, auth, spoofing, BEC)
OWN: uniphish/analyzers/email.py, tests/analyzers/test_email_analyzer.py.
stage=0, blocking=True, kinds={ArtifactKind.EMAIL}. Depends on uniphish.mail.parse +
uniphish.mail.auth (a6), uniphish.url.brandkb (a2), uniphish.url.parse, uniphish.nlp
(a9, optional). Share the parse via ctx.memo(mail.parse.MEMO_KEY, ...).

Emit signals (category 'email'/'auth'/'social'):
- auth: DMARC fail / not aligned (+2.5 T1566), SPF fail (+1.5), DKIM fail (+1),
  aligned-pass from a known sender -> NEGATIVE (-1.5). Use AuthResult.
- sender spoof: From display-name shows a brand but the From addr domain is freemail /
  unrelated / look-alike (+3.5, set BrandMatch technique='sender', mitre T1656); reply-to
  domain differs from From and is freemail/unrelated (+2); return-path mismatch (+1);
  look-alike sender domain (homoglyph/typo of a brand via brands.py) (+3).
- BEC indicators: no links + urgency + payment/wire/gift-card ask from a lookalike/freemail
  exec impersonation (+3, via nlp SEResult over html_text/text_body); 'sent from mobile'
  excuse + reply-to swap.
- content/transport: suspicious Received chain (originating IP in a residential/odd ASN —
  note only; infra analyzer does live), newly-seen sender, mismatched Message-ID domain.
- children: every link (origin='email.link', pass anchor text in meta), every attachment
  as a FILE artifact (origin='email.attachment'), every inline image as a FILE artifact
  for QR scanning (origin='email.image'), every attached message/rfc822 as an EMAIL
  artifact (origin='email.attached'). The engine recurses and propagates their risk.
- Indicators: email-src (From), domains, urls, attachment hashes.
meta: subject, from, auth summary, counts.
TESTS: display-name brand spoof + freemail; DMARC-fail; aligned legit low; BEC gift-card;
phishing link child raises parent; attachment hash indicator; forwarded-phish attachment.
Use the a6 fixtures / add your own synthetic .eml.
