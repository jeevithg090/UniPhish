# Spec: SSRF-proof network gateway + cache
OWN: uniphish/core/net.py, uniphish/core/cache.py, tests/core/test_net.py,
tests/core/test_cache.py.

PURPOSE: the ONLY way the platform touches the network. It must be impossible to use
UniPhish to reach internal/cloud-metadata services. Async (httpx + dnspython).

net.py:
- is_public_ip(ip): reject private, loopback, link-local (incl. 169.254.169.254),
  CGNAT 100.64/10, multicast, reserved, unspecified, 0/8, 192.0.0/24, 198.18/15, 240/4,
  broadcast, IPv6 ULA/link-local, IPv4-mapped/compat IPv6 to non-public, NAT64 64:ff9b::/96.
- async resolve(host, rdtype='A', *, timeout)->list[str] (injectable resolver for tests);
  resolve_ips(host) (A+AAAA). class BlockedDestination(Exception).
- async safe_fetch(url, *, method='GET', headers=None, max_bytes=None, timeout=None,
  follow_redirects=True, max_redirects=5, allowed_ports=frozenset({80,443,8080,8443}),
  allow_private=False, transport=None) -> FetchResult. Per hop: http/https only; port
  allowlist; resolve host; every resolved IP must be public; connect to the pinned IP
  (defeat DNS-rebinding/TOCTOU) while preserving Host header + TLS SNI + cert hostname
  verification; manual redirect handling with per-hop validation + loop detection; stream
  with a hard byte cap AND a decompressed-size cap (gzip/brotli-bomb safe); no persisted
  cookies; UA from settings; total deadline. FetchResult(url, final_url, status, headers
  [lowercased], body, truncated, chain [Hop(url,status,ip,location)], ip, elapsed_ms,
  error, blocked_reason, content_type, charset; .text()). Never raises for network errors.
- global concurrency semaphore + per-host politeness limiter.

cache.py: TTLCache (thread-safe LRU+TTL); async_cached(ttl,maxsize,key=...) decorator
(dedups concurrent identical coroutine calls); DiskCache(namespace,ttl) tiny SQLite KV
in settings.data_dir for DNS/RDAP/feed responses (JSON, size-bounded, multiprocess-safe).

TESTS (offline): exhaustive SSRF table; redirect-to-private blocked; DNS-rebinding
(resolver returns public then private) cannot reach private IP; decimal/hex IP hosts
blocked; byte + decompression-bomb caps; scheme/port blocks; redirect loop; timeout;
injectable resolver + httpx.MockTransport. Cache: concurrency dedup + TTL expiry.
