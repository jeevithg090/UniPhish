import { useMemo, useState } from "react";
import type { Verdict } from "../api/types";
import { buildWaterfall, formatLogOdds, sigmoid, type WaterfallStep } from "../lib/risk";
import { Chip } from "./ui";

const SEV: Record<string, string> = {
  critical: "border-bad/50 bg-bad/10 text-bad",
  high: "border-bad/40 bg-bad/10 text-bad",
  medium: "border-warn/40 bg-warn/10 text-warn",
  low: "border-info/40 bg-info/10 text-info",
  info: "border-line bg-panel2 text-mute",
};

function barColor(step: WaterfallStep): string {
  if (step.kind === "prior") return "var(--color-mute)";
  if (step.kind === "total") return "var(--color-accent)";
  return step.delta >= 0 ? "var(--color-bad)" : "var(--color-ok)";
}

/**
 * The explainability showpiece: prior -> each signal's effective log-odds -> fused result.
 * Bars float on a shared log-odds axis so the running total is visible at a glance.
 */
export function Waterfall({ verdict }: { verdict: Verdict }) {
  const steps = useMemo(() => buildWaterfall(verdict), [verdict]);
  const [open, setOpen] = useState<string | null>(null);
  const { lo, hi } = useMemo(() => {
    let lo = Infinity;
    let hi = -Infinity;
    for (const s of steps) {
      lo = Math.min(lo, s.from, s.to);
      hi = Math.max(hi, s.from, s.to);
    }
    lo = Math.min(lo, 0);
    hi = Math.max(hi, 0);
    const pad = (hi - lo) * 0.04 || 0.5;
    return { lo: lo - pad, hi: hi + pad };
  }, [steps]);
  const span = hi - lo || 1;
  const pct = (v: number) => ((v - lo) / span) * 100;
  const zero = pct(0);

  if (steps.length <= 2 && verdict.signals.length === 0) {
    return <p className="text-sm text-mute">No signals fired. The score is the prior base rate.</p>;
  }

  return (
    <div>
      <p className="mb-3 text-xs text-mute">
        Each bar is one signal&apos;s effective log-odds after damping of correlated evidence. Red
        pushes toward phishing, green toward legitimate. The dashed line is log-odds 0 (50% risk).
      </p>
      <ol className="space-y-1.5" aria-label="Signal contributions waterfall">
        {steps.map((s) => {
          const a = Math.min(s.from, s.to);
          const b = Math.max(s.from, s.to);
          const isPoint = s.kind === "prior" || s.kind === "total";
          const left = isPoint ? pct(s.to) - 0.5 : pct(a);
          const width = isPoint ? 1 : Math.max(pct(b) - pct(a), 0.6);
          const expandable = s.kind === "signal" && s.signal;
          const isOpen = open === s.key;
          return (
            <li key={s.key}>
              <button
                type="button"
                disabled={!expandable}
                aria-expanded={expandable ? isOpen : undefined}
                onClick={() => setOpen(isOpen ? null : s.key)}
                className={`group grid w-full grid-cols-1 items-center gap-x-3 gap-y-1 rounded-lg px-2 py-1.5 text-left sm:grid-cols-[minmax(0,15rem)_1fr_6.5rem] ${expandable ? "hover:bg-panel2" : "cursor-default"} ${s.kind === "total" ? "border-t border-line pt-2" : ""}`}
              >
                <span className="flex items-center gap-2 truncate text-sm">
                  {expandable && (
                    <span
                      aria-hidden="true"
                      className="text-mute transition-transform group-aria-expanded:rotate-90"
                    >
                      ▸
                    </span>
                  )}
                  <span
                    className={`truncate ${s.kind === "total" ? "font-semibold" : ""}`}
                    title={s.label}
                  >
                    {s.label}
                  </span>
                </span>
                <span className="relative h-4 rounded bg-panel2">
                  <span
                    className="absolute inset-y-0 border-l border-dashed border-mute/50"
                    style={{ left: `${zero}%` }}
                    aria-hidden="true"
                  />
                  <span
                    className="absolute inset-y-0.5 rounded-sm"
                    style={{
                      left: `${left}%`,
                      width: `${width}%`,
                      background: barColor(s),
                      transition: "all .4s ease",
                    }}
                    aria-hidden="true"
                  />
                </span>
                <span className="text-right font-mono text-xs tabular-nums">
                  {s.kind === "prior" && (
                    <span className="text-mute">
                      {formatLogOdds(s.to)} · {Math.round(sigmoid(s.to) * 100)}%
                    </span>
                  )}
                  {s.kind === "total" && (
                    <b className="text-accent">
                      {formatLogOdds(s.to)} · {Math.round(sigmoid(s.to) * 100)}%
                    </b>
                  )}
                  {(s.kind === "signal" || s.kind === "children") && (
                    <span className={s.delta >= 0 ? "text-bad" : "text-ok"}>
                      {formatLogOdds(s.delta)}
                    </span>
                  )}
                </span>
              </button>
              {isOpen && s.signal && <SignalDetail step={s} />}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function SignalDetail({ step }: { step: WaterfallStep }) {
  const sig = step.signal!;
  const ev = Object.entries(sig.evidence ?? {});
  return (
    <div className="slide-in mx-2 mb-2 mt-1 space-y-2 rounded-lg border border-line bg-bg/60 p-3 text-sm">
      {sig.detail && <p className="text-ink/90">{sig.detail}</p>}
      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        <Chip className={SEV[sig.severity ?? "info"] ?? SEV.info}>{sig.severity ?? "info"}</Chip>
        <Chip className="border-line bg-panel2 text-mute">{sig.category}</Chip>
        {sig.analyzer && (
          <Chip className="border-line bg-panel2 text-mute">analyzer: {sig.analyzer}</Chip>
        )}
        <Chip className="border-line bg-panel2 text-mute">
          weight {formatLogOdds(sig.weight)} × conf {sig.confidence.toFixed(2)}
        </Chip>
        <code className="rounded bg-panel2 px-1.5 py-0.5 text-mute">{sig.id}</code>
        {sig.mitre.map((m) => (
          <Chip key={m} className="border-info/30 bg-info/10 text-info">
            {m}
          </Chip>
        ))}
      </div>
      {ev.length > 0 && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-xs">
          {ev.slice(0, 12).map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-mute">{k}</dt>
              <dd className="break-all text-ink/90">
                {typeof v === "string" ? v : JSON.stringify(v)}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
