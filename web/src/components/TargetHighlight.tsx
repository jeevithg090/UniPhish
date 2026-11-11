import { useMemo, useState } from "react";
import type { Verdict } from "../api/types";
import { buildSegments, formatLogOdds, revealInvisible, segmentClass, signalContribution } from "../lib/risk";

/** Renders the analysed target with each Signal.span highlighted by strength. */
export function TargetHighlight({ verdict }: { verdict: Verdict }) {
  const [reveal, setReveal] = useState(false);
  const spanned = useMemo(() => verdict.signals.filter((s) => s.span), [verdict.signals]);
  const segments = useMemo(() => buildSegments(verdict.target, spanned), [verdict.target, spanned]);
  const display = (t: string) => (reveal ? revealInvisible(t) : t);
  const hasInvisible = revealInvisible(verdict.target) !== verdict.target;

  return (
    <div>
      <div className="flex items-center justify-between gap-2 pb-2">
        <span className="text-xs uppercase tracking-wider text-mute">{verdict.kind} target</span>
        {hasInvisible && (
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-mute">
            <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} className="accent-accent" />
            Reveal invisible characters
          </label>
        )}
      </div>
      <p className="max-h-48 overflow-auto break-all rounded-xl border border-line bg-bg/70 p-3 font-mono text-sm leading-7 scroll-thin" dir="ltr">
        {segments.length === 0 && <span className="text-mute">(empty)</span>}
        {segments.map((seg, i) => {
          if (seg.signals.length === 0) return <span key={i}>{display(seg.text)}</span>;
          const tip = seg.signals.map((id) => `${spanned[id].title} (${formatLogOdds(signalContribution(spanned[id]))})`).join("\n");
          return (
            <mark key={i} title={tip} className={`rounded-sm px-0.5 ${segmentClass(seg.weight)}`}>
              {display(seg.text)}
            </mark>
          );
        })}
      </p>
      {spanned.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-mute">
          {spanned.map((s, i) => (
            <li key={`${s.id}${i}`} className="flex items-center gap-1.5">
              <span className={`inline-block h-2.5 w-2.5 rounded-sm ${signalContribution(s) < 0 ? "bg-ok" : signalContribution(s) >= 2.5 ? "bg-bad" : signalContribution(s) >= 1 ? "bg-warn" : "bg-info"}`} aria-hidden="true" />
              {s.title}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-xs text-mute">No signal pointed at a specific span of the target.</p>
      )}
    </div>
  );
}
