import type { AnalyzerRun } from "../api/types";
import { formatMs } from "../lib/risk";
import { Chip } from "./ui";

const STATUS: Record<string, string> = {
  ok: "border-ok/40 bg-ok/10 text-ok",
  skipped: "border-line bg-panel2 text-mute",
  timeout: "border-warn/40 bg-warn/10 text-warn",
  error: "border-bad/40 bg-bad/10 text-bad",
};

export function AnalyzerTable({ runs, totalMs }: { runs: AnalyzerRun[]; totalMs: number }) {
  if (!runs.length) return <p className="text-sm text-mute">No analyzer runs recorded.</p>;
  const max = Math.max(...runs.map((r) => r.duration_ms), 1);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[30rem] text-left text-sm">
        <caption className="sr-only">Analyzer runs</caption>
        <thead className="text-xs uppercase tracking-wider text-mute">
          <tr>
            <th className="py-1.5 pr-3 font-medium">Analyzer</th>
            <th className="py-1.5 pr-3 font-medium">Status</th>
            <th className="py-1.5 pr-3 text-right font-medium">Signals</th>
            <th className="py-1.5 font-medium">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {runs.map((r, i) => (
            <tr key={`${r.name}${i}`}>
              <td className="py-1.5 pr-3 font-mono">{r.name}</td>
              <td className="py-1.5 pr-3">
                <Chip className={STATUS[r.status] ?? STATUS.skipped} title={r.error ?? undefined}>{r.status}</Chip>
                {r.error && <span className="ml-2 text-xs text-bad">{r.error}</span>}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums">{r.signals}</td>
              <td className="py-1.5">
                <span className="flex items-center gap-2">
                  <span className="h-1.5 w-24 overflow-hidden rounded bg-panel2"><span className="block h-full rounded bg-accent/70" style={{ width: `${(r.duration_ms / max) * 100}%` }} /></span>
                  <span className="font-mono text-xs tabular-nums text-mute">{formatMs(r.duration_ms)}</span>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-mute">Wall-clock total: {formatMs(totalMs)} (analyzers run concurrently within a stage).</p>
    </div>
  );
}
