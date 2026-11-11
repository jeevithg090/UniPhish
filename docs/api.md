# HTTP API

The API is a FastAPI application (`uniphish.server.app:app`) that wraps the engine, the
SQLite store and the live event bus. It also serves the SOC console at `/`. Interactive
OpenAPI docs are at `/docs` and `/openapi.json` while it runs.

```bash
pip install -e '.[server]'
uniphish serve                                   # 127.0.0.1:8080
uniphish serve --host 0.0.0.0 --port 8080        # warns if no API keys are configured
# or: uvicorn uniphish.server.app:app --host 127.0.0.1 --port 8080
```

All `/v1` paths below are relative to the server root.

## Security model in one screen

| Control | Behaviour |
|---|---|
| **Auth** | Set `UNIPHISH_API_KEYS=key1,key2`. Send `X-API-Key: <key>` or `Authorization: Bearer <key>`. Comparison is constant-time. With no keys configured the API is **open** (developer mode) and every response carries `X-UniPhish-Auth: disabled`. |
| **Which routes need a key** | `/v1/scan*`, `/v1/explain`, `/v1/verdicts*`, `/v1/stats`, `/v1/indicators`, `/v1/export/*`, `/v1/stream`. **Not covered today:** `/v1/health`, `/v1/meta/*` (intentionally public), the static console, and, as a **known gap**, the TAXII routes (`/taxii2/*`) and the legacy `POST /scan` and `POST /stix`. See [threat model](threat-model.md#known-gaps). |
| **Rate limit** | In-memory token bucket per API key (or client IP), `UNIPHISH_RATE_LIMIT` requests per minute (default 120; 0 disables). Per process; behind a reverse proxy the client IP is the proxy's unless you terminate limits at the proxy. 429 with `Retry-After: 1`. |
| **Size cap** | Requests with `Content-Length` above 40 MB get 413. Artifact caps then apply: URL 8,192 chars, text 1 M chars, page 5 MB, email and file 25 MB each (413). |
| **Network policy** | A request cannot push the server online. `online` is honoured only if the operator set `UNIPHISH_ONLINE=1`; `fetch_pages` and `detonate` are forced off whenever the effective scan is offline. |
| **Budget clamps** | `max_depth` <= 4, `max_children` <= 50, `timeout_s` <= 120, `analyzer_timeout_s` <= 60. |
| **Headers** | Every response (including the SSE stream) gets a strict CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP and a restrictive Permissions-Policy. |
| **CORS** | Off unless `UNIPHISH_CORS_ORIGINS` lists origins; no credentials. |

Run behind TLS (a reverse proxy) for anything beyond localhost.

## Scanning

`POST /v1/scan` takes one polymorphic body and returns a [verdict](#the-verdict-object).

```bash
curl -s localhost:8080/v1/scan -H 'content-type: application/json' -H 'x-api-key: $KEY' -d '{
  "url": "https://pаypal-secure.top/signin",
  "options": {"explain": true}
}'
```

| Field | Type | Notes |
|---|---|---|
| `input_type` | `url` `text` `email` `html` `page` `file` | optional; inferred from whichever payload is present |
| `url` | string | |
| `text` | string | SMS, chat, LLM context |
| `email` | base64 string | raw `.eml` |
| `html` | string | HTML document (`url` may accompany it to say where it was served from) |
| `file` + `filename` | base64 string + string | any file; images are checked for QR codes |
| `options` | object | see below |

Unknown top-level fields are rejected (422). Convenience routes with narrower schemas:

| Route | Body |
|---|---|
| `POST /v1/scan/url` | `{"url", "options"}` |
| `POST /v1/scan/text` | `{"text", "options"}` |
| `POST /v1/scan/email` | `{"email": <base64>}` or `{"raw": <utf-8 text>}`, plus `options` |
| `POST /v1/scan/page` | `{"html", "url"?, "options"}` |
| `POST /v1/scan/file` | multipart: `file` (upload), optional `options` (JSON string field) |
| `POST /v1/scan/batch` | `{"items": [<scan bodies>], "options"?}`, 1 to 50 items, 8 at a time. Returns `{"count", "results": [{"index", "ok", "verdict" \| "error"}]}`; one bad item never fails the batch. |
| `POST /v1/explain` | same body as `/v1/scan`; forces `explain` on and adds `report: {narrative, triage, ai_available}` from the analyst (an LLM when `ANTHROPIC_API_KEY` is set, a deterministic template otherwise). The analyst only describes the verdict; it never changes the score. |

### Options

| Option | Default | Effect |
|---|---|---|
| `online` | server default | DNS, RDAP, TLS, ASN, feeds. Needs operator opt-in. |
| `fetch_pages` | false | safely fetch the URL and analyse the landing page (needs online) |
| `detonate` | false | render in a sandboxed headless browser (needs online and Playwright) |
| `explain` | false | expensive explanations such as byte saliency |
| `ai_report` | false | LLM analyst narrative |
| `max_depth` / `max_children` | 2 / 25 | child-artifact recursion bounds (clamped) |
| `timeout_s` / `analyzer_timeout_s` | 30 / 10 | whole-scan and per-analyzer budgets (clamped) |
| `enable` / `disable` | all | analyzer name allow-list / deny-list |
| `persist` | true | store the verdict (set false for scans you do not want kept) |

### The verdict object

```jsonc
{
  "id": "0719f792...",            "created_at": "2026-11-10T21:52:05Z",   "engine_version": "2.0.0",
  "kind": "url",                  "target": "https://pаypal-secure.top/signin",
  "risk": 0.8808, "score": 88,    "logit": 2.0,
  "level": "malicious",           "action": "block",     "confidence": 0.233,
  "summary": "Malicious (88/100): Byte-level ML model flags this URL as likely phishing.",
  "signals": [{
      "id": "ml.cnn.phishing", "title": "...", "detail": "...", "weight": 4.0, "category": "ml",
      "severity": "critical", "confidence": 1.0, "analyzer": "ml",
      "evidence": {"prob": 1.0}, "mitre": [], "span": null, "contribution": 4.0 }],
  "indicators": [{"type": "domain", "value": "...", "role": "host", "malicious": null}],
  "brand": {"brand": "paypal", "name": "PayPal", "technique": "idn", "confidence": 0.85, "official": false},
  "techniques": ["idn_homograph", "punycode"],
  "mitre": [{"id": "T1566.002", "name": "...", "tactic": "initial-access", "framework": "attack"}],
  "children": [ /* verdicts of links, attachments, QR payloads */ ],
  "analyzers": [{"name": "url", "status": "ok", "duration_ms": 9.6, "signals": 8, "error": null}],
  "meta": {}, "duration_ms": 31.2
}
```

Always check `analyzers[].status`: an analyzer that timed out or errored contributed no
evidence. (This is a real effect: the example above is what a cold-start first scan looks
like when the `url` analyzer times out; a warm scan of the same URL scores 100.)

## Reading stored data

| Route | Purpose |
|---|---|
| `GET /v1/verdicts?limit=50&min_score=0&kind=&level=` | newest-first metadata rows (limit 1 to 500) |
| `GET /v1/verdicts/{id}` | the full verdict |
| `GET /v1/stats` | counts by level and kind, 10-bucket score histogram, store sizes |
| `GET /v1/indicators?type=&value=&limit=100&malicious_only=` | look up an IOC by type and exact value, or list recent ones |
| `GET /v1/meta/analyzers` | the detection catalog: analyzers with stage, kinds, flags and every signal id and title |
| `GET /v1/meta/version` | package, engine and schema versions |
| `GET /v1/health` | liveness plus configuration snapshot (`online`, `auth`, analyzer list) |

## Live stream (SSE)

`GET /v1/stream` is a `text/event-stream`. The engine emits a `verdict` event after each
top-level scan; hunters and AgentGuard publish alerts too. A `: ping` comment is sent every
15 s. Events come from an in-process bus: with several worker processes a client only sees
events from the worker it is connected to.

```bash
curl -N -H 'x-api-key: $KEY' localhost:8080/v1/stream
# event: verdict
# data: {"id": "...", "kind": "url", "target": "...", "score": 100, "level": "malicious", ...}
```

Browsers cannot set headers on `EventSource`; use `fetch` with a streaming reader (the SOC
console does) when keys are enforced.

## Exports

`POST /v1/export/{fmt}` with `fmt` in `stix`, `misp`, `ecs` (JSON) or `sigma`, `suricata`,
`yara` (text). The body is either `{"verdict_id": "..."}` for a stored verdict or an
ad-hoc scan body (`url`, `text`, `email`, `html`, `file`), plus `allow_benign` (default false)
and `options`. Returns 404 for an unknown format or verdict and 422 when there is nothing
safe to export (for example a benign verdict). The exporters share one conservative IOC
selection that drops brands' legitimate hosts and never produces domain-level rules for
shared hosting platforms.

```bash
curl -s localhost:8080/v1/export/sigma -H 'content-type: application/json' \
     -d '{"url": "https://paypal-login-secure.top/verify"}'
```

## TAXII 2.1

A read-only TAXII 2.1 server publishes STIX 2.1 indicators from the local store with
MITRE ATT&CK references. One collection, `phishing-iocs`.

| Route | |
|---|---|
| `GET /taxii2/` | discovery |
| `GET /taxii2/api/` | API root |
| `GET /taxii2/api/collections/` and `/{id}/` | collection list and detail |
| `GET /taxii2/api/collections/phishing-iocs/objects/` | the objects; query `limit` (1 to 10,000, default 1,000) and `added_after`. There is no pagination cursor: `more` is always `false`. |

Discovery and collection responses use `application/taxii+json;version=2.1`; the objects
envelope uses the STIX media type. **These routes are not behind API-key
auth in this release**; restrict them at the network edge or do not expose the server
publicly if the IOCs are sensitive.

## Legacy routes

`POST /scan` (`{"url"}` returns `url, score, risk, level, action, summary`) and `POST /stix`
exist for compatibility with the 1.x demo extension and bot. They are hidden from OpenAPI,
run the default offline engine, and are **not** behind API-key auth. Prefer `/v1`.

## Errors

| Status | When |
|---|---|
| 400 | malformed `options` form field |
| 401 | key required and missing or wrong (`WWW-Authenticate: Bearer`) |
| 404 | unknown verdict or export format |
| 413 | body or artifact over the size caps |
| 422 | schema violation, or nothing to export |
| 429 | rate limit |

Error bodies are `{"detail": "..."}` and never echo raw input unescaped.

## Python client sketch

```python
import httpx

with httpx.Client(base_url="http://127.0.0.1:8080", headers={"x-api-key": "KEY"}) as c:
    v = c.post("/v1/scan", json={"text": "Your parcel is held, reply with the code"}).json()
    print(v["level"], v["score"], [s["id"] for s in v["signals"][:3]])
```
