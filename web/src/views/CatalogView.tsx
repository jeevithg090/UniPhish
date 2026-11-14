import { useEffect, useMemo, useState } from "react";
import { api, type CatalogView as Catalog } from "../api/client";
import { Card, Chip, Empty, ErrorBox, Spinner } from "../components/ui";

export function CatalogView() {
  const [data, setData] = useState<Catalog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [analyzer, setAnalyzer] = useState("");
  const [tick, setTick] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `tick` is the retry trigger
  useEffect(() => {
    const c = new AbortController();
    setError(null);
    api.analyzers(c.signal).then(setData, (e: unknown) => {
      if (!(e instanceof DOMException && e.name === "AbortError"))
        setError(e instanceof Error ? e.message : "Request failed");
    });
    return () => c.abort();
  }, [tick]);

  const names = useMemo(
    () => [...new Set(data?.signals.map((s) => s.analyzer).filter(Boolean))].sort(),
    [data],
  );
  const shown = useMemo(() => {
    const n = q.trim().toLowerCase();
    return (data?.signals ?? []).filter(
      (s) =>
        (!analyzer || s.analyzer === analyzer) &&
        (!n || s.id.toLowerCase().includes(n) || s.title.toLowerCase().includes(n)),
    );
  }, [data, q, analyzer]);

  if (error) return <ErrorBox error={error} onRetry={() => setTick((t) => t + 1)} />;
  if (!data) return <Spinner label="Loading detection catalog" />;
  return (
    <div className="space-y-4">
      {data.analyzers.length > 0 && (
        <Card title={`Analyzers (${data.analyzers.length})`}>
          <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {data.analyzers.map((a) => (
              <li key={a.name} className="rounded-xl border border-line bg-panel2/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <b className="font-mono text-sm">{a.name}</b>
                  {a.requires_online && (
                    <Chip className="border-warn/40 bg-warn/10 text-warn">online</Chip>
                  )}
                </div>
                <p className="mt-1 text-xs leading-5 text-mute">{a.description}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {a.kinds.map((k) => (
                    <Chip key={k} className="border-line text-mute">
                      {k}
                    </Chip>
                  ))}
                  {a.stage !== undefined && (
                    <Chip className="border-line text-mute">stage {a.stage}</Chip>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card
        title={`Detection catalog (${shown.length}${shown.length !== data.signals.length ? ` of ${data.signals.length}` : ""} signals)`}
        right={
          <div className="flex flex-wrap gap-2 text-xs">
            <input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter signals…"
              aria-label="Filter signals"
              className="rounded-md border border-line bg-panel2 px-2 py-1 text-ink"
            />
            <select
              value={analyzer}
              onChange={(e) => setAnalyzer(e.target.value)}
              aria-label="Filter by analyzer"
              className="rounded-md border border-line bg-panel2 px-2 py-1 text-mute"
            >
              <option value="">All analyzers</option>
              {names.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {shown.length === 0 ? (
          <Empty>No signals match the filter.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[30rem] text-left text-sm">
              <caption className="sr-only">Detection signals</caption>
              <thead className="text-xs uppercase tracking-wider text-mute">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">Signal id</th>
                  <th className="py-1.5 pr-3 font-medium">Detects</th>
                  <th className="py-1.5 font-medium">Analyzer</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {shown.map((s) => (
                  <tr key={s.id}>
                    <td className="py-1.5 pr-3 font-mono text-xs text-accent">{s.id}</td>
                    <td className="py-1.5 pr-3">{s.title}</td>
                    <td className="py-1.5 font-mono text-xs text-mute">{s.analyzer}</td>
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
