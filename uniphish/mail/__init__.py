"""Email analysis building blocks (package is ``mail``, not ``email``, to avoid shadowing).

* :mod:`uniphish.mail.parse` — hostile-input-safe MIME/RFC 5322 parsing.
* :mod:`uniphish.mail.auth` — header-only SPF/DKIM/DMARC/ARC and sender-spoof analysis.
"""

from __future__ import annotations

from uniphish.mail.auth import (
    AuthResult,
    analyze_auth,
    from_display_name_contains_other_domain,
    reply_to_differs_from_from,
)
from uniphish.mail.parse import MEMO_KEY, ParsedEmail, parse_email

__all__ = [
    "MEMO_KEY",
    "AuthResult",
    "ParsedEmail",
    "analyze_auth",
    "from_display_name_contains_other_domain",
    "parse_email",
    "reply_to_differs_from_from",
]
