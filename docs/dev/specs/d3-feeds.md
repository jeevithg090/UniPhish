# Spec: threat-feed ingestion + connectors
OWN: uniphish/intel/feeds.py, uniphish/intel/connectors.py, tests/intel/test_feeds.py.
Depends on core.net (a5, SSRF-guarded fetch + DiskCache), store.db (a8), url.parse. All
network gated by online + cached + off in tests.

feeds.py: pluggable public-feed importers that populate the local reputation/IOC DB so the
reputation analyzer can flag known-bad offline afterwards. Each importer: async
fetch()->list[FeedEntry(type,value,source,first_seen)] via safe_fetch, parse, and
store.bulk_set reputation (verdict='deny', source=feed, ttl). Importers for well-known
OPEN feeds (respect their licenses; document in a FEEDS.md): OpenPhish community, URLhaus
(abuse.ch), PhishTank-style, a generic 'domains blocklist' importer (one-host-per-line),
and a generic STIX/TAXII puller (pull indicators from a TAXII 2.1 collection into the DB).
A sync update_all(online) orchestrator with per-feed error isolation + a summary. Large
responses streamed + capped.
connectors.py: thin typed clients for optional enrichment APIs used by the reputation/infra
analyzers when keys are present — VirusTotalClient(url/domain/file lookups), UrlscanClient
(search/result), GoogleSafeBrowsingClient(lookup). All via core.net; all optional; clear
'no key' behaviour; never raise.
TESTS (offline, mock safe_fetch): each importer parses a sample response into FeedEntries
and writes deny-reputation rows; TAXII puller ingests a sample STIX bundle; a VT/urlscan
client parses a sample JSON; no key -> no-op; malformed response -> isolated error, no
crash. No real network.
