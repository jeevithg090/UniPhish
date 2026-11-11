# UniPhish 2 SOC console

React + TypeScript + Tailwind SPA. It consumes the `/v1` API and is built into
`uniphish/server/static/`, which the API serves at `/` (no Node needed at runtime).

    cd web && npm ci && npm run build   # typecheck + vite build -> ../uniphish/server/static
    npm test                            # vitest unit tests (risk, defang, input, SSE parsing)
    npm run dev                         # dev server on :5173, proxies /v1 to 127.0.0.1:8080

No secrets are bundled. An API key (when the server enforces auth) is entered in Settings and
kept in sessionStorage only. No telemetry, no external requests (system fonts, relative URLs).
