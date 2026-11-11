# Spec: Certificate Transparency threat-hunter
OWN: uniphish/hunt/__init__.py, uniphish/hunt/ct.py, tests/hunt/test_ct.py. Depends on the
engine (scan_url / a lightweight domain scan), uniphish.url.brandkb (a2), uniphish.store.db
(a8), uniphish.export.stix (a12), core.events.bus. websockets extra for the live firehose.

PURPOSE: catch phishing domains at certificate-issuance time — before the site is live and
before blocklists. Modernise the legacy scripts/ct_hunter.py.
ct.py:
- async stream_certstream(on_cert) : connect to a CT firehose (certstream-compatible
  wss URL, configurable) and call on_cert(domain, cert_meta) for each new domain; robust
  reconnect/backoff; bounded queue. Also support replaying a JSONL/sample file for offline
  demo + tests (source='sample').
- class CTHunter(engine, store, *, threshold, watch_brands=None): process(domain) scores
  the domain (build a URL 'https://{domain}/', run a FAST subset — url analyzer + brandkb,
  skip network) -> if risk>=threshold or it impersonates a watched brand, record a
  hunt_event in the store, build a STIX bundle, append to the TAXII objects store, and
  publish a 'hunt' event on the bus (for the dashboard live feed). Keep per-run stats.
- async run(source, ...) the main loop; a sync hunt_once(domains) for tests/CLI.
- Freshly-issued-cert + brand-lookalike is itself a strong signal — reflect that in the
  recorded score (you may add an 'issued just now' context weight).
Dedup domains; rate/volume bounded; never fetch the sites (issuance-time detection only).
TESTS (offline): feed a sample list incl. homoglyph/typo/combosquat lookalikes + benign
domains; assert only the lookalikes produce hunt_events with the right brand + a stored
STIX object + a bus event; benign domains ignored; watch_brands filter works. Mock/replay;
no network.
