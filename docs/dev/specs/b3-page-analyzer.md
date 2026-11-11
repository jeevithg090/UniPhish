# Spec: HTML page analyzer
OWN: uniphish/analyzers/page.py, tests/analyzers/test_page_analyzer.py.
Depends on uniphish.page.html (a7), uniphish.url.brandkb (a2), uniphish.url.parse,
uniphish.assets.lists (a3). stage=0, blocking=True, kinds={ArtifactKind.PAGE}.

Emit signals (category 'page') from the PageModel:
- credential form posting cross-origin (+4, T1056.003) — detail: which action host;
  password form to a data: URI (+5); password present with offsite JS submit (+3).
- brand/content vs domain mismatch: page's visible text / title / og:site_name strongly
  references a brand (BrandKB.brands_mentioned_in) but the page URL's registrable domain is
  not that brand's official domain (+3.5, category 'brand', set BrandMatch technique=
  'content'); if the favicon hash matches a brand's known favicon but domain differs (+3).
- obfuscation: high inline-script entropy / big base64 blobs / eval-like density (+2,
  T1027), clipboard write present (+2.5, ClickFix indicator T1204.004), meta-refresh
  offsite (+1.5), hidden iframe to another host (+2).
- login form with no password but OTP/2FA field + offsite post (AiTM-ish) (+2.5).
- emit child Artifacts: the form action URL (origin='page.form_action'), external script
  hosts of interest, meta-refresh target (origin='page.refresh'); dedupe; cap.
- If URL is known official brand domain and content matches that brand -> small NEGATIVE
  (-1) 'consistent branding'.
Each signal carries detail + evidence + mitre. Set meta {'title':..,'forms':n,
'password_fields':n}. Read ctx.brand()/ctx.results['url'] when present (page served with a
URL) to align brand reasoning.
TESTS: cross-origin credential form; brand-content mismatch; clipboard/ClickFix indicator;
data-uri form; benign same-origin login page low. Synthetic HTML fixtures.
