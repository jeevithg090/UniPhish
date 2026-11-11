"""UniPhish HTTP API (FastAPI).

The server exposes the detection engine over a versioned REST API (``/v1``), a live SSE
feed, a read-only TAXII 2.1 threat-intel server and the built SOC dashboard. Build an app
with :func:`create_app`; the module-level ``app`` is the ASGI entry point::

    uvicorn uniphish.server.app:app --host 127.0.0.1 --port 8000

``create_app`` and ``app`` are re-exported here for convenience; import the ``app``
*instance* from the submodule (``uniphish.server.app:app``) when running under an ASGI
server, since the package attribute ``app`` shadows the submodule of the same name.
"""

from __future__ import annotations

from uniphish.server.app import app, create_app

__all__ = ["app", "create_app"]
