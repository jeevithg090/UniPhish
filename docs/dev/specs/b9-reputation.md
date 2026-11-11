# Spec: reputation analyzer (local DB + top-sites + optional feeds)
OWN: uniphish/analyzers/reputation.py, tests/analyzers/test_reputation.py. Depends on
uniphish.store.db (a8), uniphish.assets.lists (a3, top_sites), uniphish.url.parse.
kinds={ArtifactKind.URL, ArtifactKind.EMAIL}, stage=10 (reads ctx + store; can be online
for optional external feeds but core is offline).

Offline core (always):
- top-site allow evidence: if the registrable domain is in the Tranco top-N AND is not a
  LOTS/user-content host AND the URL shows no strong impersonation from ctx.results['url']
  -> NEGATIVE weight scaled by rank (e.g. top-1k -> -3, top-10k -> -2, top-100k -> -1),
  category 'reputation', id 'rep.top_site'. Guard: never apply to LOTS hosts or when a
  brand-impersonation signal already fired.
- local reputation DB: lookup_reputation(domain/url/ip); deny -> strong positive
  (+ its weight), allow -> negative; id 'rep.local_denylist'/'rep.local_allowlist'.
- first-seen novelty: if the store has never seen this registrable domain -> tiny +0.3
  'never-before-seen domain' (contextual only).
Optional online (requires_online, degrade gracefully, cached via core.cache): Google Safe
Browsing lookup (if settings.safebrowsing_api_key) -> +6 on a hit; urlscan.io /
VirusTotal domain/url reputation (if keys) -> map verdicts to weights. These live here but
MUST be no-ops without keys and never block/raise.
Indicators carry malicious= from denylist hits.
TESTS (offline): top-site negative; denylist positive; allowlist negative; LOTS host gets
NO top-site bonus even if parent domain is popular; novelty. Mock the store; no network.
