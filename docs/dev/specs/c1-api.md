# Spec: HTTP API server (FastAPI)
OWN: uniphish/server/__init__.py, uniphish/server/app.py, uniphish/server/security.py,
uniphish/server/schemas.py, uniphish/server/routes/__init__.py, uniphish/server/routes/
{scan.py,intel.py,taxii.py,stream.py,meta.py}, tests/server/test_api.py. Depends on the
engine (core.engine.default_engine), core.events.bus, store.db, export.* (stix),
core.analyzer.AnalysisOptions. FastAPI + pydantic v2.

Endpoints (prefix /v1, plus compatibility):
- GET /v1/health, GET /v1/meta/analyzers (signal catalog via core.analyzer.signal_catalog),
  GET /v1/meta/version.
- POST /v1/scan {input_type? , url?|text?|email(base64)?|html?|file(base64,filename)?,
  options?} -> Verdict JSON. Auto-detect type when input_type omitted. Enforce size limits;
  options map to AnalysisOptions (online/fetch_pages/detonate gated by server policy +
  settings).
- POST /v1/scan/url, /v1/scan/text, /v1/scan/email, /v1/scan/page, /v1/scan/file
  (multipart upload) convenience routes.
- POST /v1/scan/batch {items:[...]} bounded (<=50) concurrent.
- POST /v1/explain (force options.explain + ai_report if available).
- GET /v1/verdicts (recent, filters), GET /v1/verdicts/{id}, GET /v1/stats,
  GET /v1/indicators?type=&value= (store lookups).
- POST /v1/export/{stix|misp|sigma|suricata|yara|ecs} {verdict_id|url|...} -> the export.
- GET /v1/stream (Server-Sent Events from core.events.bus: live verdicts + hunt alerts).
- TAXII 2.1: GET /taxii2/, /taxii2/api/, /taxii2/api/collections/,
  /taxii2/api/collections/{id}/objects/ (reads store STIX objects). Keep the legacy
  /scan and /stix shapes working as thin shims if cheap.
- Serve the built dashboard: mount uniphish/server/static at / (StaticFiles, html=True);
  tolerate missing static dir.

security.py: API-key auth dependency (settings.api_keys; disabled => open in dev, but
return a header noting auth-disabled); constant-time compare; simple in-memory
rate-limiter (settings.rate_limit_per_minute, per key/IP, token bucket); strict request
size cap; CORS from settings.cors_origins; security headers middleware (X-Content-Type-
Options, Referrer-Policy, a strict CSP for the dashboard); never reflect untrusted input
into responses unescaped; the API must itself be injection-safe (treat all inputs as data).
Register a verdict->store persistence hook on the engine at startup (respect options.persist).
app.py: create_app(settings=None)->FastAPI (lifespan sets up store + hook + engine warm),
module-level app = create_app() for uvicorn.
TESTS: TestClient (no network; online analyzers off by default); scan url/text/email/file
happy paths; batch; auth required when keys set + rejected bad key; rate limit trips;
export endpoints; SSE yields an event on a scan; size-limit rejection; TAXII discovery.
