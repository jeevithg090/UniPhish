// Tiny fetch client for the UniPhish /v1 API. URLs are resolved against the page base so
// the console works from the API root or any sub-path. The optional API key lives only in
// sessionStorage (never in the bundle) and is sent as X-API-Key + Bearer.
import type {
  AnalyzerInfo,
  CatalogEntry,
  LiveEvent,
  Stats,
  TimelineBucket,
  Verdict,
  VerdictRow,
} from "./types";

const KEY_STORE = "uniphish.apikey";

export function getApiKey(): string {
  try {
    return sessionStorage.getItem(KEY_STORE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) sessionStorage.setItem(KEY_STORE, key);
    else sessionStorage.removeItem(KEY_STORE);
  } catch {
    /* storage unavailable (private mode): key lives for this call chain only */
  }
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function apiUrl(path: string): string {
  return new URL(path.replace(/^\/+/, ""), document.baseURI).toString();
}

function authHeaders(): Record<string, string> {
  const k = getApiKey();
  return k ? { "X-API-Key": k, Authorization: `Bearer ${k}` } : {};
}

async function errorFrom(res: Response): Promise<ApiError> {
  let msg = `${res.status} ${res.statusText || "request failed"}`;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object") {
      const o = body as Record<string, unknown>;
      const d = o.detail ?? o.error ?? o.message;
      if (typeof d === "string") msg = d;
      else if (Array.isArray(d))
        msg =
          d
            .map((x) =>
              typeof x === "object" && x
                ? String((x as Record<string, unknown>).msg ?? "")
                : String(x),
            )
            .filter(Boolean)
            .join("; ") || msg;
    }
  } catch {
    /* not JSON */
  }
  if (res.status === 401 || res.status === 403) msg = `${msg} (set an API key in Settings)`;
  if (res.status === 429) msg = "Rate limit reached. Wait a moment and retry.";
  return new ApiError(msg, res.status);
}

async function request(
  path: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(apiUrl(path), {
      ...init,
      signal,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...authHeaders(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError("Cannot reach the UniPhish API. Is the server running?", 0);
  }
  if (!res.ok) throw await errorFrom(res);
  return res;
}

async function json<T>(path: string, init?: RequestInit, signal?: AbortSignal): Promise<T> {
  const res = await request(path, init, signal);
  return (await res.json()) as T;
}

function post<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return json<T>(
    path,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
    signal,
  );
}

export const api = {
  scan: (body: Record<string, unknown>, signal?: AbortSignal) =>
    post<Verdict>("v1/scan", body, signal),
  explain: (body: Record<string, unknown>, signal?: AbortSignal) =>
    post<Verdict>("v1/explain", body, signal),
  verdicts: (
    params: { limit?: number; min_score?: number; level?: string; kind?: string } = {},
    signal?: AbortSignal,
  ) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params))
      if (v !== undefined && v !== "") q.set(k, String(v));
    return json<unknown>(`v1/verdicts?${q}`, undefined, signal).then(normaliseRows);
  },
  verdict: (id: string, signal?: AbortSignal) =>
    json<Verdict>(`v1/verdicts/${encodeURIComponent(id)}`, undefined, signal),
  stats: (signal?: AbortSignal) =>
    json<StatsResponse>("v1/stats", undefined, signal).then(normaliseStats),
  analyzers: (signal?: AbortSignal) =>
    json<unknown>("v1/meta/analyzers", undefined, signal).then(normaliseCatalog),
  version: (signal?: AbortSignal) =>
    json<Record<string, unknown>>("v1/meta/version", undefined, signal),
  health: (signal?: AbortSignal) => json<Record<string, unknown>>("v1/health", undefined, signal),
  /** Export a persisted verdict. Returns the body as text plus a suggested filename. */
  async exportVerdict(
    format: ExportFormat,
    verdictId: string,
  ): Promise<{ text: string; filename: string; mime: string }> {
    const res = await request(`v1/export/${format}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "*/*" },
      body: JSON.stringify({ verdict_id: verdictId }),
    });
    const ct = res.headers.get("content-type") ?? "text/plain";
    let text = await res.text();
    const isJson = /json/i.test(ct);
    if (isJson) {
      try {
        text = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        /* keep raw */
      }
    }
    return {
      text,
      filename: `uniphish-${verdictId.slice(0, 8)}.${EXPORT_EXT[format]}`,
      mime: isJson ? "application/json" : "text/plain",
    };
  },
};

export type ExportFormat = "stix" | "misp" | "sigma" | "suricata" | "yara" | "ecs";
export const EXPORT_FORMATS: { id: ExportFormat; label: string; hint: string }[] = [
  { id: "stix", label: "STIX 2.1", hint: "Threat-intel bundle (TAXII compatible)" },
  { id: "misp", label: "MISP", hint: "MISP event JSON" },
  { id: "sigma", label: "Sigma", hint: "Detection rules (proxy / DNS / email)" },
  { id: "suricata", label: "Suricata", hint: "Network IDS rules" },
  { id: "yara", label: "YARA", hint: "Content match rule" },
  { id: "ecs", label: "Elastic ECS", hint: "Elastic Common Schema event" },
];
const EXPORT_EXT: Record<ExportFormat, string> = {
  stix: "json",
  misp: "json",
  sigma: "yml",
  suricata: "rules",
  yara: "yar",
  ecs: "json",
};

// ---- response normalisers: tolerate bare arrays or {items|verdicts|...} envelopes ---- //
function asArray(x: unknown, keys: string[]): unknown[] {
  if (Array.isArray(x)) return x;
  if (x && typeof x === "object") {
    for (const k of keys) {
      const v = (x as Record<string, unknown>)[k];
      if (Array.isArray(v)) return v;
    }
  }
  return [];
}

function normaliseRows(x: unknown): VerdictRow[] {
  return asArray(x, ["verdicts", "items", "results", "data"]).filter(
    (r): r is VerdictRow => !!r && typeof r === "object" && "id" in r,
  );
}

export interface StatsResponse extends Stats {
  timeline?: TimelineBucket[];
}
export interface StatsView {
  stats: Stats;
  timeline: TimelineBucket[];
}

function normaliseStats(x: StatsResponse): StatsView {
  const raw = (x && typeof x === "object" ? x : {}) as StatsResponse;
  const stats: Stats = {
    ...raw,
    verdicts: Number(raw.verdicts ?? 0),
    by_level: raw.by_level ?? {},
    by_kind: raw.by_kind ?? {},
    score_histogram: Array.isArray(raw.score_histogram)
      ? raw.score_histogram
      : new Array(10).fill(0),
    indicators: Number(raw.indicators ?? 0),
    malicious_indicators: Number(raw.malicious_indicators ?? 0),
  };
  return { stats, timeline: Array.isArray(raw.timeline) ? raw.timeline : [] };
}

export interface CatalogView {
  signals: CatalogEntry[];
  analyzers: AnalyzerInfo[];
}

/** Accepts {signals:{id:{title,analyzer}}, analyzers:[...]} or a bare {id:{title,analyzer}} map. */
function normaliseCatalog(x: unknown): CatalogView {
  const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
  const sigSrc = (o.signals ??
    o.catalog ??
    (Array.isArray(o.analyzers) ? undefined : o)) as unknown;
  const signals: CatalogEntry[] = [];
  if (Array.isArray(sigSrc)) {
    for (const e of sigSrc) {
      if (e && typeof e === "object") {
        const r = e as Record<string, unknown>;
        if (typeof r.id === "string")
          signals.push({
            id: r.id,
            title: String(r.title ?? ""),
            analyzer: String(r.analyzer ?? ""),
          });
      }
    }
  } else if (sigSrc && typeof sigSrc === "object") {
    for (const [id, v] of Object.entries(sigSrc as Record<string, unknown>)) {
      if (v && typeof v === "object" && "title" in (v as object)) {
        const r = v as Record<string, unknown>;
        signals.push({ id, title: String(r.title ?? ""), analyzer: String(r.analyzer ?? "") });
      }
    }
  }
  const analyzers: AnalyzerInfo[] = asArray(o.analyzers, []).flatMap((a) => {
    if (!a || typeof a !== "object") return [];
    const r = a as Record<string, unknown>;
    if (typeof r.name !== "string") return [];
    return [
      {
        name: r.name,
        description: String(r.description ?? ""),
        stage: typeof r.stage === "number" ? r.stage : undefined,
        kinds: Array.isArray(r.kinds) ? r.kinds.map(String) : [],
        requires_online: typeof r.requires_online === "boolean" ? r.requires_online : undefined,
      },
    ];
  });
  signals.sort((a, b) => a.id.localeCompare(b.id));
  return { signals, analyzers };
}

// ---- Server-Sent Events over fetch (so the API key header can be sent) ---- //
export interface StreamHandle {
  close(): void;
}

export function openStream(
  onEvent: (e: LiveEvent) => void,
  onStatus: (s: "connecting" | "live" | "error", detail?: string) => void,
): StreamHandle {
  let stopped = false;
  let ctrl: AbortController | null = null;
  let retry = 1000;

  const run = async () => {
    while (!stopped) {
      ctrl = new AbortController();
      onStatus("connecting");
      try {
        const res = await fetch(apiUrl("v1/stream"), {
          headers: { Accept: "text/event-stream", ...authHeaders() },
          signal: ctrl.signal,
          credentials: "same-origin",
        });
        if (!res.ok || !res.body) throw new ApiError(`stream ${res.status}`, res.status);
        onStatus("live");
        retry = 1000;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += value.replace(/\r\n/g, "\n");
          for (let idx = buf.indexOf("\n\n"); idx >= 0; idx = buf.indexOf("\n\n")) {
            const frame = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const ev = parseSseFrame(frame);
            if (ev) onEvent(ev);
          }
          if (buf.length > 1_000_000) buf = "";
        }
      } catch (e) {
        if (stopped) return;
        onStatus("error", e instanceof Error ? e.message : "stream error");
      }
      if (stopped) return;
      await new Promise((r) => setTimeout(r, retry));
      retry = Math.min(retry * 2, 15000);
    }
  };
  void run();
  return {
    close() {
      stopped = true;
      ctrl?.abort();
    },
  };
}

/** Parse one SSE frame into a LiveEvent. Comments/heartbeats yield null. */
export function parseSseFrame(frame: string): LiveEvent | null {
  let name = "";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const field = i < 0 ? line : line.slice(0, i);
    const val = i < 0 ? "" : line.slice(i + 1).replace(/^ /, "");
    if (field === "event") name = val;
    else if (field === "data") dataLines.push(val);
  }
  if (!dataLines.length) return null;
  try {
    const parsed: unknown = JSON.parse(dataLines.join("\n"));
    if (parsed && typeof parsed === "object") {
      const o = parsed as Record<string, unknown>;
      if (typeof o.type === "string" && "data" in o) {
        return {
          type: o.type,
          ts: String(o.ts ?? new Date().toISOString()),
          data: (o.data && typeof o.data === "object" ? o.data : { value: o.data }) as Record<
            string,
            unknown
          >,
        };
      }
      return { type: name || "message", ts: new Date().toISOString(), data: o };
    }
  } catch {
    /* non-JSON payload */
  }
  return null;
}
