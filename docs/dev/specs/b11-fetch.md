# Spec: fetch + sandbox-detonation analyzer (active, online)
OWN: uniphish/analyzers/fetch.py, uniphish/intel/detonate.py, tests/analyzers/test_fetch.py,
tests/intel/test_detonate.py. Depends on uniphish.core.net (a5), uniphish.page.html (a7),
uniphish.analyzers.kits.match_html (b4, optional), uniphish.analyzers.injection.scan_html
(b5, optional). kinds={ArtifactKind.URL}.

Two behaviours:
1) Static fetch (stage=30, requires_online, enabled by options.fetch_pages): safe_fetch
   the URL (SSRF-guarded), follow the redirect chain; emit the final landing URL + each
   redirect hop as Indicators and the resolved page as a child PAGE Artifact (origin=
   'fetch.page') so the page/kit/injection analyzers run on real content; signal if the
   redirect chain crosses into a LOTS host / shortener-terminal / different brand (+1.5),
   if it ends at a data: URI, or if the fetch was blocked for SSRF (+2 'tried to reach a
   private address' — note). Also surface the server IP (role 'landing') and TLS.
2) Detonation (stage=30, requires_detonation + requires_online, options.detonate): render
   in a sandboxed headless browser (Playwright chromium, --no-sandbox off/hardened, no
   downloads, blocked navigation to file:, short timeout, offline resources disabled) to
   catch JS-built phishing (client-side redirects, dynamically written credential forms,
   ClickFix clipboard writes, BitB). Capture final URL, rendered DOM HTML, console errors,
   clipboard-write attempts, navigation chain, and (optional) a screenshot path. Feed the
   rendered DOM to page/kit/injection matchers -> signals (category 'fetch'); +2.5 if the
   rendered page differs materially from the static HTML (cloaking), +3 clipboard write at
   runtime (ClickFix), +2 JS client-side redirect to another brand/host. Playwright may be
   absent -> skip cleanly with a note.
Everything time-bounded and fault-isolated. Never execute downloaded binaries.
TESTS (offline): mock core.net.safe_fetch to return a redirect chain + HTML; assert the
landing page becomes a child artifact and chain hops are indicators; SSRF-blocked fetch
yields the note signal. Detonation test: skip if Playwright missing; otherwise render a
local inline HTML string (data/file) with a clipboard write and assert the signal (mark
slow). No external network.
