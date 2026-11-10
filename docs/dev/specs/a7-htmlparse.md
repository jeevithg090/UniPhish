# Spec: HTML structural parsing for phishing pages
OWN: uniphish/page/__init__.py, uniphish/page/html.py, uniphish/page/favicon.py,
tests/page/test_html.py, tests/page/test_favicon.py, tests/page/fixtures/.

PURPOSE: turn an HTML document into the structural facts a credential-harvesting page
reveals. Parse with bs4+lxml; never execute anything; size-bounded.

html.py: parse_html(html: str, base_url: str|None=None) -> PageModel dataclass:
title, meta (description, refresh target + delay, csp, referrer, generator, og:site_name,
theme-color), lang, visible_text (script/style/noscript removed, collapsed),
text_len, forms[FormModel(action (resolved absolute), method, is_cross_origin (action
host differs from base registrable), has_password, has_hidden_credential (hidden inputs
named like credentials), input_names[], submits_to_data_uri, submits_offsite_js (onsubmit
handler posts via fetch/XHR), autocomplete_off)], password_input_count, links[(href
resolved, text, rel, target)], external_link_hosts[], scripts[ScriptRef(src resolved,
inline_len, is_external, host)], iframes[(src resolved, sandbox, hidden)], images[(src,
alt)], favicons[(href resolved, rel)], has_eval_like (inline JS containing eval/Function/
atob/unescape/document.write/fromCharCode — count only, as an obfuscation indicator),
inline_script_entropy (max base64-ish blob length + Shannon entropy), external_form_post
(bool), resource_hosts (set of all external hosts referenced), brand_text_hits (lowercase
brand keyword occurrences — use a simple pass; analyzer cross-checks with BrandKB),
password_field_present, meta_refresh_offsite (bool), clipboard_write (JS writes to
navigator.clipboard — a ClickFix indicator; count only), suspicious_comment_count.
Resolve all URLs against base_url with urllib.parse.urljoin. Be resilient to broken HTML.

favicon.py: favicon_mmh3(data: bytes) -> int (Shodan-style MurmurHash3 of the
base64-with-newlines encoding, using mmh3) for favicon-based brand/kit fingerprinting;
helper known_favicon_brand(h, table) lookup against a small provided dict.

TESTS: a credential form posting cross-origin; a data:-URI form action; meta-refresh to
another host; obfuscated inline script; hidden iframe; favicon hash stability. Synthetic
fixtures only, reserved domains, no live payloads.
