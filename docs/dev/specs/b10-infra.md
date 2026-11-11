# Spec: infrastructure analyzer (DNS / RDAP age / TLS / ASN) — online
OWN: uniphish/intel/__init__.py, uniphish/intel/dns.py, uniphish/intel/rdap.py,
uniphish/intel/tls.py, uniphish/intel/asn.py, uniphish/analyzers/infra.py,
tests/intel/test_infra.py, tests/analyzers/test_infra_analyzer.py. Depends on
uniphish.core.net (a5, resolve + safe_fetch + cache), uniphish.url.parse.
kinds={ArtifactKind.URL}, stage=20, requires_online=True.

intel/dns.py: async lookups via core.net.resolve (A/AAAA/MX/NS/TXT/CNAME); detect
fast-flux-ish (many A records / low TTL note), no MX, parked indicators; DNSResult.
intel/rdap.py: async domain_age via RDAP (bootstrap rdap.org or IANA RDAP; cached on
DiskCache); return registration date, age_days, registrar, nameservers; graceful None.
intel/tls.py: async fetch leaf certificate over TLS (use ssl/cryptography through a direct
connection to a PINNED public IP — reuse core.net SSRF guard; or parse via safe_fetch's
TLS) -> TlsInfo(issuer, subject, SANs, not_before, not_after, age_days, is_lets_encrypt/
free_ca, self_signed, wildcard, cert_sha256, san_count). intel/asn.py: map resolved IP to
ASN/org via Team Cymru DNS-based whois (origin.asn.cymru.com TXT, cached) -> AsnInfo(asn,
org, country, is_hosting/bulletproof-ish note from a small provider list).

analyzers/infra.py: orchestrate the above (parallel, bounded, all cached); emit signals
(category 'infra'):
- domain age: < 7 days +2.5, < 30 days +1.5, < 90 days +0.5 (T1583.001); > 2 years -1.
- cert: issued < 7 days ago +1, free CA + brand impersonation present +0.5, self-signed on
  a creds page +1, SAN mismatch with host +2.
- DNS: no MX on a 'login/brand' domain +0.5, very-low-TTL many-A fast-flux +1.
- ASN: domain impersonating a brand but hosted on a residential/odd ASN +1; brand's real
  domains are on the brand's expected infra (note).
Indicators: ipv4/ipv6 (resolved, role 'resolved'), cert_sha256, asn. Everything degrades to
'unavailable' notes when a lookup fails; never block the whole analysis.
TESTS (offline, mock core.net.resolve + safe_fetch + a fake RDAP/cert): young-domain
signal, old-domain negative, self-signed, ASN mapping; all via mocks (no real network).
