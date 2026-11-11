# Mail fixtures

All messages here are **synthetic and inert**. They use only reserved domains
(`.example`, `.test`, `.invalid`, `example.com`) and documentation IP ranges
(RFC 5737 / RFC 3849). No working payloads, real credentials or real victims.

| File | Purpose |
|------|---------|
| `legit_aligned.eml` | Legitimate mail, SPF+DKIM+DMARC pass and aligned; RFC 2047 subject; QP bodies |
| `display_name_spoof.eml` | From display name shows a brand address, real address is on another domain; Reply-To mismatch |
| `dmarc_fail.eml` | Executive impersonation: spf=fail, dkim=none, dmarc=fail |
| `forwarded_phish.eml` | Phish delivered as a `message/rfc822` attachment (forwarded-as-attachment) |
| `encoded_bodies.eml` | base64 (latin-1) text part and quoted-printable (utf-8) HTML part |
| `data_uri_inline_image.eml` | HTML with a `data:image/png;base64,...` image (QR-scan input path), meta refresh, form |
| `malformed.eml` | Broken MIME: missing boundary, duplicate From, unparseable Date, garbage header |
| `forged_auth_results.eml` | Sender-planted `Authentication-Results` below the real one (must be ignored) |
