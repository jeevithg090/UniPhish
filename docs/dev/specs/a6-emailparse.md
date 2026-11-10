# Spec: hostile-input email parsing + authentication analysis
OWN: uniphish/mail/__init__.py, uniphish/mail/parse.py, uniphish/mail/auth.py,
tests/mail/test_parse.py, tests/mail/test_auth.py, tests/mail/fixtures/ (synthetic .eml
+ README). Package name is 'mail' (not 'email').

parse.py:
- MEMO_KEY = 'mail.parsed' (analyzers share the parse via ctx.memo(MEMO_KEY, ...)).
- parse_email(raw: bytes, *, max_depth=3) -> ParsedEmail. Use email.message_from_bytes
  with policy.default, fall back to compat32 on broken headers; never raise. ParsedEmail:
  message_id, subject (RFC2047 decoded), from_ (Address(display_name,addr,local,domain)),
  sender, reply_to[], return_path, to/cc[], date (aware|None), date_raw, headers[(name,
  value) in order], received[ReceivedHop(raw,from_host,from_ip,by_host,with_proto,
  timestamp)] top->bottom, x_mailer, list_unsubscribe, in_reply_to, text_body, html_body,
  html_text (visible text; script/style stripped via bs4/lxml), attachments[Attachment(
  filename (RFC2231 decoded), content_type, size, sha256/sha1/md5, data (size-capped),
  disposition, content_id, is_inline)], images (inline/embedded incl. cid: and data: URIs
  as bytes for QR scanning), attached_messages[ParsedEmail] (message/rfc822 parts),
  links[EmailLink(url, text (anchor), source: html_href|html_form|html_img|text|meta_refresh,
  in_html)], anomalies[str codes], raw_size.
- Import uniphish.url.parse.extract_urls LAZILY for text-body links.

auth.py: analyze_auth(email: ParsedEmail) -> AuthResult(spf, dkim, dmarc each with
status [pass/fail/none/softfail/neutral/temperror/permperror] parsed from the
Authentication-Results and Received-SPF headers; the authenticated/aligned domain;
alignment: does the RFC5321.MailFrom / DKIM d= domain align (relaxed, registrable-level)
with the RFC5322.From domain?; dmarc_aligned: bool; arc info; notes). display_name_spoof
helpers: from_display_name_contains_other_domain(email) and
reply_to_differs_from_from(email). Parse headers only — no DNS (the infra analyzer does
live SPF/DKIM when online). Be robust to missing/duplicate/garbled auth headers.

TESTS: fixtures covering aligned-pass legit mail, display-name spoof (From shows a brand
but addr is a freemail/foreign domain), reply-to mismatch, DMARC fail, forwarded-as-
attachment phish (message/rfc822), base64/quoted-printable bodies, RFC2047 encoded
subjects, data:-URI inline image, malformed MIME. All synthetic/inert; reserved domains.
