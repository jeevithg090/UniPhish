import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type StatsView } from "../api/client";
import type { TimelineBucket, VerdictRow } from "../api/types";
import { Card, Chip, Empty, ErrorBox, relTime, Spinner } from "../components/ui";
import { LEVEL_STYLE, normLevel } from "../lib/risk";

function useLoad<T>(fn: (s: AbortSignal) => Promise<T>, deps: readonly unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: callers pass `deps` explicitly; `fn` is re-created every render, `tick` forces a reload
  useEffect(() => {
    const c = new AbortController();
    setLoading(true);
    setError(null);
    fn(c.signal)
      .then(setData, (e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setError(e instanceof Error ? e.message : "Request failed");
      })
      .finally(() => {
        if (!c.signal.aborted) setLoading(false);
      });
    return () => c.abort();
  }, [tick, ...deps]);
  return { data, error, loading, reload: useCallback(() => setTick((t) => t + 1), []) };
}

export function Timeline({ buckets }: { buckets: TimelineBucket[] }) {
  const W = 720,
    H = 150,
    P = { l: 28, r: 6, t: 8, b: 20 };
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const bw = (W - P.l - P.r) / Math.max(buckets.length, 1);
  const y = (n: number) => (n / max) * (H - P.t - P.b);
  if (!buckets.length) return <Empty>No timeline data yet.</Empty>;
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="w-full"
      role="img"
      aria-label={`Verdicts per hour over the last ${buckets.length} hours, peak ${max}`}
    >
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line
            x1={P.l}
            x2={W - P.r}
            y1={H - P.b - f * (H - P.t - P.b)}
            y2={H - P.b - f * (H - P.t - P.b)}
            stroke="var(--color-line)"
            strokeWidth="1"
          />
          <text
            x={P.l - 4}
            y={H - P.b - f * (H - P.t - P.b) + 3}
            textAnchor="end"
            fontSize="9"
            fill="var(--color-mute)"
          >
            {Math.round(max * f)}
          </text>
        </g>
      ))}
      {buckets.map((b, i) => {
        const x = P.l + i * bw + bw * 0.12;
        const w = bw * 0.76;
        let base = H - P.b;
        const parts: [number, string][] = [
          [b.benign, "var(--color-ok)"],
          [b.suspicious, "var(--color-warn)"],
          [b.malicious, "var(--color-bad)"],
        ];
        return (
          <g key={b.hour}>
            <title>{`${b.hour.slice(5, 16).replace("T", " ")}: ${b.total} (benign ${b.benign}, suspicious ${b.suspicious}, malicious ${b.malicious})`}</title>
            {parts.map(([n, c], k) => {
              if (!n) return null;
              const h = y(n);
              base -= h;
              return <rect key={k} x={x} y={base} width={w} height={h} fill={c} rx="1" />;
            })}
          </g>
        );
      })}
      {[0, Math.floor(buckets.length / 2), buckets.length - 1].map((i) => (
        <text
          key={i}
          x={P.l + i * bw + bw / 2}
          y={H - 5}
          textAnchor="middle"
          fontSize="9"
          fill="var(--color-mute)"
        >
          {buckets[i].hour.slice(11, 13)}:00
        </text>
      ))}
    </svg>
  );
}

function Histogram({ bins }: { bins: number[] }) {
  const max = Math.max(1, ...bins);
  return (
    <div
      className="flex h-28 items-end gap-1"
      role="img"
      aria-label="Score distribution in 10 buckets"
    >
      {bins.map((n, i) => (
        <div
          key={i}
          className="flex flex-1 flex-col items-center justify-end gap-1"
          title={`${i * 10}–${i === 9 ? 100 : i * 10 + 9}: ${n}`}
        >
          <span className="text-[10px] tabular-nums text-mute">{n || ""}</span>
          <div
            className="w-full rounded-t"
            style={{
              height: `${(n / max) * 80}%`,
              minHeight: n ? 3 : 1,
              background:
                i >= 8 ? "var(--color-bad)" : i >= 5 ? "var(--color-warn)" : "var(--color-ok)",
              opacity: n ? 1 : 0.2,
            }}
          />
          <span className="text-[10px] text-mute">{i * 10}</span>
        </div>
      ))}
    </div>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-panel2/60 px-4 py-3">
      <div className="text-xs uppercase tracking-wider text-mute">{label}</div>
      <div className={`mt-1 text-2xl font-bold tabular-nums ${tone ?? ""}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

export function VerdictsView({ onOpenVerdict }: { onOpenVerdict: (id: string) => void }) {
  const [level, setLevel] = useState("");
  const [kind, setKind] = useState("");
  const [minScore, setMinScore] = useState(0);
  const stats = useLoad<StatsView>((s) => api.stats(s));
  const rowsParams = useMemo(
    () => ({ limit: 100, level, kind, min_score: minScore || undefined }),
    [level, kind, minScore],
  );
  const rows = useLoad<VerdictRow[]>((s) => api.verdicts(rowsParams, s), [rowsParams]);

  return (
    <div className="space-y-4">
      <Card
        title="Overview"
        right={
          <button
            type="button"
            onClick={() => {
              stats.reload();
              rows.reload();
            }}
            className="rounded-md border border-line px-2 py-0.5 text-xs text-mute hover:text-ink"
          >
            Refresh
          </button>
        }
      >
        {stats.error ? (
          <ErrorBox error={stats.error} onRetry={stats.reload} />
        ) : !stats.data ? (
          <Spinner label="Loading stats" />
        ) : (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <StatTile label="Verdicts" value={stats.data.stats.verdicts} />
              <StatTile
                label="Malicious"
                value={stats.data.stats.by_level.malicious ?? 0}
                tone="text-bad"
              />
              <StatTile
                label="Suspicious"
                value={stats.data.stats.by_level.suspicious ?? 0}
                tone="text-warn"
              />
              <StatTile
                label="Malicious IOCs"
                value={stats.data.stats.malicious_indicators}
                tone="text-accent"
              />
            </div>
            <div className="grid gap-5 lg:grid-cols-2">
              <div>
                <h3 className="mb-2 text-xs uppercase tracking-wider text-mute">
                  Verdicts per hour (24 h)
                </h3>
                <Timeline buckets={stats.data.timeline} />
              </div>
              <div>
                <h3 className="mb-2 text-xs uppercase tracking-wider text-mute">
                  Score distribution
                </h3>
                <Histogram bins={stats.data.stats.score_histogram} />
              </div>
            </div>
            {Object.keys(stats.data.stats.by_kind).length > 0 && (
              <div className="flex flex-wrap gap-2 text-xs">
                <span className="text-mute">By kind</span>
                {Object.entries(stats.data.stats.by_kind).map(([k, n]) => (
                  <Chip key={k} className="border-line bg-panel2 text-mute">
                    {k} · {n}
                  </Chip>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <Card
        title="Recent verdicts"
        right={
          <div className="flex flex-wrap items-center gap-2 text-xs text-mute">
            <select
              aria-label="Filter by level"
              value={level}
              onChange={(e) => setLevel(e.target.value)}
              className="rounded-md border border-line bg-panel2 px-2 py-1"
            >
              <option value="">All levels</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="benign">Benign</option>
            </select>
            <select
              aria-label="Filter by kind"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              className="rounded-md border border-line bg-panel2 px-2 py-1"
            >
              <option value="">All kinds</option>
              {["url", "page", "email", "file", "text"].map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1">
              Min
              <input
                type="number"
                min={0}
                max={100}
                value={minScore}
                onChange={(e) =>
                  setMinScore(Math.max(0, Math.min(100, Number(e.target.value) || 0)))
                }
                className="w-14 rounded-md border border-line bg-panel2 px-2 py-1"
              />
            </label>
          </div>
        }
      >
        {rows.error ? (
          <ErrorBox error={rows.error} onRetry={rows.reload} />
        ) : rows.loading && !rows.data ? (
          <Spinner label="Loading verdicts" />
        ) : !rows.data || rows.data.length === 0 ? (
          <Empty>No verdicts match. Analyze something to populate history.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[34rem] text-left text-sm">
              <caption className="sr-only">Recent verdicts</caption>
              <thead className="text-xs uppercase tracking-wider text-mute">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">Score</th>
                  <th className="py-1.5 pr-3 font-medium">Kind</th>
                  <th className="py-1.5 pr-3 font-medium">Target</th>
                  <th className="py-1.5 pr-3 font-medium">Brand</th>
                  <th className="py-1.5 text-right font-medium">When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.data.map((r) => (
                  <tr key={r.id} className="hover:bg-panel2/60">
                    <td className="py-2 pr-3">
                      <Chip
                        className={`w-12 justify-center ${LEVEL_STYLE[normLevel(r.level)].chip}`}
                      >
                        {r.score}
                      </Chip>
                    </td>
                    <td className="py-2 pr-3 text-mute">{r.kind}</td>
                    <td className="max-w-[28rem] py-2 pr-3">
                      <button
                        type="button"
                        onClick={() => onOpenVerdict(r.id)}
                        className="block max-w-full truncate text-left font-mono hover:text-accent"
                        title={r.target}
                      >
                        {r.target}
                      </button>
                    </td>
                    <td className="py-2 pr-3 text-mute">{r.brand ?? ""}</td>
                    <td className="py-2 text-right text-xs text-mute">
                      <time dateTime={r.created_at}>{relTime(r.created_at)}</time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
