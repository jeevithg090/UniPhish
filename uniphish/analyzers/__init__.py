"""Built-in analyzers. Each module registers its analyzers via ``@register``.

Modules are imported tolerantly: an analyzer whose optional dependency is missing
(OpenCV for QR codes, Playwright for detonation, ...) is skipped with a debug log
instead of breaking the engine.
"""

from __future__ import annotations

import importlib
import logging

log = logging.getLogger("uniphish.analyzers")

BUILTIN_MODULES: tuple[str, ...] = (
    "uniphish.analyzers.url",  # lexical, unicode, brand impersonation, techniques
    "uniphish.analyzers.ml",  # byte-level CNN (TF-free numpy runtime)
    "uniphish.analyzers.page",  # HTML structure: forms, brand/title mismatch, obfuscation
    "uniphish.analyzers.kits",  # phishing-kit / AiTM / ClickFix signature rules
    "uniphish.analyzers.injection",  # prompt injection aimed at AI agents
    "uniphish.analyzers.text",  # smishing / chat / social-engineering language
    "uniphish.analyzers.email",  # headers, auth, sender spoofing, BEC
    "uniphish.analyzers.file",  # attachments: HTML smuggling, SVG, archives, macros, QR
    "uniphish.analyzers.reputation",  # local IOC DB, feeds, top-sites, optional VT/urlscan
    "uniphish.analyzers.infra",  # DNS, RDAP age, TLS certificate, ASN (online)
    "uniphish.analyzers.fetch",  # SSRF-safe fetch + redirect chain; sandbox detonation
)

_loaded = False


def load_builtin_analyzers() -> list[str]:
    """Import every built-in analyzer module once; return the modules that loaded."""
    global _loaded
    ok: list[str] = []
    for mod in BUILTIN_MODULES:
        try:
            importlib.import_module(mod)
            ok.append(mod)
        except ModuleNotFoundError as e:
            if e.name == mod:
                log.debug("analyzer module %s not present", mod)
            else:
                log.warning("analyzer module %s skipped (missing dependency %s)", mod, e.name)
        except Exception:
            log.exception("analyzer module %s failed to import", mod)
    _loaded = True
    return ok
