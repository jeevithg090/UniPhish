# Spec: phishing-kit / AiTM / ClickFix signature analyzer
OWN: uniphish/analyzers/kits.py, uniphish/assets/rules/kit_signatures.yaml,
tests/analyzers/test_kits.py, tests/analyzers/fixtures/.
stage=0, blocking=True, kinds={ArtifactKind.PAGE}. Also usable on the HTML of a fetched
page. Depends on uniphish.page.html (a7); may reuse favicon hash.

A declarative signature engine for known phishing patterns (DETECTION signatures, like AV
or Sigma — descriptions of indicators, not working kits). kit_signatures.yaml: list of
signatures {id, name, family (aitm_proxy|clickfix|bitb|cred_harvester|oauth_consent|
callback_toad|crypto_drainer|captcha_lure|generic_kit), severity_weight, mitre: [...],
any_of/all_of: matchers over PageModel fields — matcher kinds: text_contains (visible
text), html_regex (ReDoS-safe, bounded), form_action_cross_origin, has_clipboard_write,
title_regex, resource_host_suffix, meta, favicon_mmh3, script_src_regex, dom_pattern}.
Include well-grounded, *indicator-level* signatures for:
- AiTM reverse-proxy pages (telltale of a proxied real login portal on a look-alike host),
- ClickFix / fake-CAPTCHA 'verify you are human' pages that instruct the user to paste
  into a system dialog (detect the instructional text + clipboard write), T1204.004,
- Browser-in-the-Browser fake window chrome, OAuth-consent/device-code phishing, callback
  (phone-number) phishing pages, crypto wallet-drainer connect prompts.
Keep signatures as pattern DESCRIPTIONS; do NOT include functional kit code or payloads.

kits.py: compile signatures once (bounded regexes); evaluate against PageModel; emit one
Signal per matched signature (id=f'kit.{sig.id}', category 'kit', weight=severity_weight,
detail naming the family + what matched, mitre from the sig) and set techniques. Provide
match_html(html, url=None) helper for reuse by the fetch analyzer.
TESTS: each family's synthetic fixture matches exactly its signature; a benign page matches
none; regexes are bounded (no catastrophic backtracking on a long adversarial string —
include a timing guard test).
