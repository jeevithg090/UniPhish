import { useEffect, useRef, useState } from "react";
import { openStream } from "../api/client";
import type { LiveEvent } from "../api/types";
import { LEVEL_STYLE, levelFromScore, normLevel } from "../lib/risk";
import { Card, Chip, Empty, relTime } from "../components/ui";

const MAX_EVENTS = 200;

interface Row {
  key: number;
  type: string;
  ts: string;
  title: string;
  score: number | null;
  level: string | null;
  sub: string;
  verdictId: string | null;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : typeof v === "number" ? String(v) : "";
}

/** Map any bus event to a display row. Verdict events may carry a full or slim verdict. */
export function toRow(e: LiveEvent, key: number): Row {
  const d = (e.data ?? {}) as Record<string, unknown>;
  const v = (d.verdict && typeof d.verdict === "object" ? d.verdict : d) as Record<string, unknown>;
  const score = typeof v.score === "number" ? v.score : typeof d.score === "number" ? d.score : null;
  const level = str(v.level) || (score !== null ? levelFromScore(score) : null);
  const brand = v.brand && typeof v.brand === "object" ? str((v.brand as Record<string, unknown>).name) : str(v.brand);
  if (e.type.includes("hunt") || "domain" in d) {
    return {
      key, type: e.type, ts: e.ts, title: str(d.domain) || str(v.target) || "(unknown domain)", score, level,
      sub: [str(d.source) && `source ${str(d.source)}`, brand && `brand ${brand}`, Array.isArray(d.techniques) && d.techniques.length ? (d.techniques as unknown[]).map(String).join(", ") : ""].filter(Boolean).join(" · "),
      verdictId: null,
    };
  }
  return {
    key, type: e.type, ts: e.ts, title: str(v.target) || str(d.target) || str(d.message) || e.type, score, level,
    sub: [str(v.kind), brand && `impersonates ${brand}`, str(v.summary)].filter(Boolean).join(" · "),
    verdictId: str(v.id) || null,
  };
}

export function FeedView({ onOpenVerdict }: { onOpenVerdict: (id: string) => void }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [status, setStatus] = useState<"connecting" | "live" | "error">("connecting");
  const [detail, setDetail] = useState("");
  const [paused, setPaused] = useState(false);
  const [minScore, setMinScore] = useState(0);
  const pausedRef = useRef(false);
  const seq = useRef(0);
  pausedRef.current = paused;

  useEffect(() => {
    const h = openStream(
      (e) => {
        if (pausedRef.current) return;
        const row = toRow(e, ++seq.current);
        setRows((r) => [row, ...r].slice(0, MAX_EVENTS));
      },
      (s, d) => { setStatus(s); setDetail(d ?? ""); },
    );
    return () => h.close();
  }, []);

  const shown = rows.filter((r) => (r.score ?? 100) >= minScore);
  const dot = status === "live" ? "bg-ok pulse-dot" : status === "connecting" ? "bg-warn pulse-dot" : "bg-bad";
  return (
    <Card
      title="Live threat feed"
      right={
        <div className="flex flex-wrap items-center gap-3 text-xs text-mute">
          <span className="flex items-center gap-1.5" role="status"><span className={`h-2 w-2 rounded-full ${dot}`} aria-hidden="true" />{status === "live" ? "Streaming" : status === "connecting" ? "Connecting…" : `Reconnecting${detail ? ` (${detail})` : ""}`}</span>
          <label className="flex items-center gap-1.5">Min score
            <input type="range" min={0} max={100} step={5} value={minScore} onChange={(e) => setMinScore(Number(e.target.value))} className="w-24 accent-accent" />
            <span className="w-6 tabular-nums">{minScore}</span>
          </label>
          <button type="button" onClick={() => setPaused(!paused)} className="rounded-md border border-line px-2 py-0.5 hover:text-ink" aria-pressed={paused}>{paused ? "Resume" : "Pause"}</button>
          <button type="button" onClick={() => setRows([])} className="rounded-md border border-line px-2 py-0.5 hover:text-ink">Clear</button>
        </div>
      }
    >
      {shown.length === 0 ? (
        <Empty>Waiting for events. Verdicts from any client of this server and certificate-transparency hunt alerts appear here in real time.</Empty>
      ) : (
        <ul className="divide-y divide-line" aria-live="off">
          {shown.map((r) => {
            const lv = normLevel(r.level);
            return (
              <li key={r.key} className="slide-in flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
                <Chip className={`w-12 justify-center ${LEVEL_STYLE[lv].chip}`}>{r.score ?? "–"}</Chip>
                <Chip className="border-line bg-panel2 text-mute">{r.type}</Chip>
                <div className="min-w-0 flex-1">
                  {r.verdictId ? (
                    <button type="button" onClick={() => onOpenVerdict(r.verdictId!)} className="block max-w-full truncate text-left font-mono text-sm hover:text-accent" title={r.title}>{r.title}</button>
                  ) : (
                    <span className="block truncate font-mono text-sm" title={r.title}>{r.title}</span>
                  )}
                  {r.sub && <span className="block truncate text-xs text-mute" title={r.sub}>{r.sub}</span>}
                </div>
                <time className="text-xs text-mute" dateTime={r.ts}>{relTime(r.ts)}</time>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
