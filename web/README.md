# UniPhish 2 SOC console

React + TypeScript + Tailwind SPA. It consumes the `/v1` API and is built into
`uniphish/server/static/`, which the API serves at `/` (no Node needed at runtime).

    cd web && npm ci && npm run build   # typecheck + vite build -> ../uniphish/server/static
    npm test                            # vitest unit tests (risk, defang, input, SSE parsing, routing)
    npm run dev                         # dev server on :5173, proxies /v1 to 127.0.0.1:8080

No secrets are bundled. An API key (when the server enforces auth) is entered in Settings and
kept in sessionStorage only. No telemetry, no external requests (system fonts, relative URLs).

Views are selected by the URL hash (`#/analyze`, `#/feed`, `#/history`, `#/catalog`;
anything else shows a not-found view). Colours are CSS variables in `src/index.css`; the
theme follows the OS unless the header toggle saves a choice, which `public/theme-init.js`
applies before first paint (a separate file because the server's CSP forbids inline scripts).
