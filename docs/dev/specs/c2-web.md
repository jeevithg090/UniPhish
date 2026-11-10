# Spec: SOC console (React + TypeScript dashboard)
OWN: everything under web/ (Vite + React + TypeScript + Tailwind), and the BUILD OUTPUT
committed to uniphish/server/static/ (so the API serves it with no Node needed at runtime).
Do NOT edit server routes; consume the /v1 API. tests: a vitest unit test for the
risk/scoring presentation util is enough; the heavy value is a clean, impressive UI.

Build a genuinely impressive single-page analyst console:
- A prominent 'analyze' box: paste a URL / message / email source / upload a file; pick
  options (online, fetch, detonate, explain). Calls POST /v1/scan.
- Verdict view: big risk gauge (0-100) + level + action; the impersonated brand; a
  signal 'waterfall' showing each signal's log-odds contribution building up from the
  prior (use Verdict.signals[].contribution) — this is the explainability showpiece;
  a highlighted rendering of the URL/text with salient spans (Signal.span) colour-coded;
  MITRE ATT&CK/ATLAS chips (link to technique URLs); extracted IOCs with copy/defang
  toggle; the child-artifact tree (email -> links/attachments/QR) as an expandable tree
  with each child's own verdict; per-analyzer run table (status/ms); one-click export
  buttons (STIX/Sigma/Suricata/YARA/MISP/ECS) hitting /v1/export/*; optional AI narrative.
- A live 'threat feed' panel subscribing to GET /v1/stream (SSE) showing incoming verdicts
  + CT-hunt alerts in real time.
- A 'recent verdicts' + 'stats' view (GET /v1/verdicts, /v1/stats) with a small timeline
  chart and a detection catalog page (GET /v1/meta/analyzers).
Clean dark theme, accessible, responsive, fast. No secrets in the bundle. Use a tiny fetch
client; handle errors/loading. Vite config must output to ../uniphish/server/static with a
relative base so it works when served from the API root. COMMIT the built assets. In your
summary give the exact build command and confirm the build succeeded and output landed in
uniphish/server/static.
Env: node/npm available. Keep dependencies lean and pinned; no telemetry.
