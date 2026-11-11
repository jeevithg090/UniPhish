# UniPhish reference data (`uniphish/assets`)

Reference lists used by the detection engine. Access them through
`uniphish.assets.lists` (typed, lazy, cached, validated); never hard-code a list in an
analyzer. All lists are defensive reference data; none contain malware, credentials or
victim data.

| File | What | Provenance |
|---|---|---|
| `tlds.yaml` | Abused TLDs with a risk weight (0.3-1.5 log-odds) | Curated by the maintainers from public abuse research: Spamhaus "most abused TLDs", Interisle *Phishing Landscape* reports, Netcraft / SURBL / Cloudflare abuse-rate summaries. Weights are judgement-calibrated priors, **not** measured per-TLD likelihood ratios. |
| `lots.yaml` | "Living off trusted sites": legitimate hosts abused for phishing hosting | Curated from vendor abuse reports and public threat research (Cloudflare, Microsoft, Google, Proofpoint, Cofense, Netskope, Unit 42). |
| `shorteners.yaml` | URL shortener / link-redirect domains | Curated from public shortener inventories and vendor documentation. |
| `dyndns.yaml` | Dynamic-DNS provider zones (DuckDNS, No-IP family, afraid.org, Dynu, ...) | Curated from provider documentation and public DDNS-abuse research. |
| `freemail.yaml` | Free / consumer mailbox providers, global and regional | Curated from public provider and free-email-domain lists. |
| `open_redirects.yaml` | Link-wrapper / open-redirect endpoints and the parameter holding the destination | Vendor documentation (Google, Microsoft, Proofpoint, Facebook, X, LinkedIn, Mimecast, Barracuda) and public phishing write-ups. Only endpoints with a documented or widely reported destination parameter are listed. |
| `lures.yaml` | Credential / urgency / delivery lure terms, 30 language tags | Vocabulary from public phishing-campaign research (Cofense, Proofpoint, Kaspersky, Group-IB, APWG), hand-translated. **Lower-resource languages (bn, ta, sw, tl, fa, ms, th, vi) have had no native-speaker review; contributions welcome.** |
| `disposable_domains.txt.gz` | Disposable-mailbox domains (10,181) | [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) `disposable_email_blocklist.conf`, **CC0-1.0**, fetched 2026-11-10. |
| `top_sites.txt.gz` | Top 100,000 registrable domains in rank order (line *n* of data = rank *n*) | [Tranco](https://tranco-list.eu) top-1M (Le Pochat et al., NDSS 2019), the daily list downloaded 2026-11-10 (file dated 2026-11-09); the specific Tranco list ID was not retrievable from the download and is therefore not recorded. Tranco data is published under CC BY-NC 4.0 for research use; check that licence fits your redistribution before shipping this file commercially. |

## Notes and limits

* Presence in `tlds.yaml`, `shorteners.yaml`, `freemail.yaml` or `lots.yaml` is
  **context, not proof**; each maps to a weak-to-moderate signal.
* A top-ranked domain is not automatically trustworthy: platforms in `lots.yaml`
  (`github.io`, `pages.dev`, ...) rank highly because they host arbitrary content.
  Always consult `lots_match` before granting top-site credit.
* The Tranco and disposable lists are point-in-time snapshots; refresh them
  periodically (re-run the fetch described in `docs/dev/specs/a3-threatdata.md`).
* Lure matching is token-aware for space-delimited scripts and substring-based for
  CJK, kana, Hangul and Thai. Short generic words carry low weights on purpose.
