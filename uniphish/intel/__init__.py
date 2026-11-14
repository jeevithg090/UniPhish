"""Network intelligence helpers (online): DNS, RDAP domain age, TLS certificates, ASN.

Each module is small, async, cached, and routes every outbound byte through
:mod:`uniphish.core.net` (or, for the TLS probe, the same SSRF guard). All lookups
degrade to "unavailable" results instead of raising, so a slow registry never blocks
an analysis.
"""

from __future__ import annotations

from uniphish.intel.asn import AsnInfo, classify_asn, lookup_asn
from uniphish.intel.dns import DNSResult, lookup_dns
from uniphish.intel.rdap import RdapInfo, domain_age
from uniphish.intel.tls import TlsInfo, fetch_tls

__all__ = [
    "AsnInfo",
    "DNSResult",
    "RdapInfo",
    "TlsInfo",
    "classify_asn",
    "domain_age",
    "fetch_tls",
    "lookup_asn",
    "lookup_dns",
]
