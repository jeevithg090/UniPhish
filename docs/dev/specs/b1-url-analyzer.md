# Spec: URL analyzer (registers with the engine)
OWN: uniphish/analyzers/url.py, tests/analyzers/test_url_analyzer.py.
Reads build-contract section 5. Depends on uniphish.url.{parse,lexical,techniques,brands,
confusables,scripts,idn_policy}, uniphish.url.brandkb, uniphish.assets.lists.

@register class UrlAnalyzer(Analyzer): name='url'; kinds={ArtifactKind.URL}; stage=0;
blocking=True (CPU-bound; implement analyze_sync). Produce Signals (signed log-odds, see
contract weight scale) + Indicators + BrandMatch + techniques + meta. Signal families and
suggested weights:
- brand impersonation (homoglyph +4.5 / idn +4 / typosquat +3 / combosquat +2.5 /
  subdomain +2.5 / path +1.5) with span over the offending chars; mitre T1583.001/T1036.
- official domain -> NEGATIVE weight (-3) brand(official=True) so legit brand URLs are
  confidently benign (but NOT for user-content hosts).
- unicode: homoglyph/confusable host (+3.5), mixed-script host (+2), invisible/bidi/tag
  chars (+3), punycode decoding to a lookalike (+3). Use idn_policy.assess_host with the
  brand skeletons as top_domain_skeletons.
- structure: ip host (+1.5), ip obfuscation (+3), '@' redirect (+3 T1036), url shortener
  (+1), dynamic dns (+1.5), LOTS hosting (+1.5 — and note: do not give a reputation bonus),
  open-redirect abuse (+2 + emit the decoded destination as a child URL artifact),
  abused tld (weight from tld_risk), many subdomains (+1), credential lure words in
  host/path (sum, capped), suspicious file ext in path (+2), data/js scheme (+3),
  excessive length/hyphens (small).
Each Signal: id (url.*/unicode.*/brand.*), title, detail with specifics, category
(brand/unicode/url), evidence, mitre, span where possible. Emit Indicators (url, domain,
ipv4) with roles. If an open-redirect/shortener destination is embedded, return it as a
child Artifact (origin='redirect'/'shortener') so the engine recurses (string-only;
network resolution is the fetch analyzer's job).
TESTS: homoglyph/typo/combosquat/IP-obf/at-trick/shortener/LOTS/official cases produce the
right top signal, brand, techniques, and (official) negative evidence; spans index into
the URL.
