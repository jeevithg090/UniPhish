import type { Verdict } from "../api/types";

/** Pull an AI/analyst narrative out of the verdict meta wherever the server put it. */
export function narrativeOf(v: Verdict): string | null {
  const m = v.meta ?? {};
  const cands: unknown[] = [m.ai_report, m.narrative, m.ai_narrative, (m.ai as Record<string, unknown> | undefined)?.narrative, (m.ai_report as Record<string, unknown> | undefined)?.narrative];
  for (const c of cands) if (typeof c === "string" && c.trim()) return c;
  return null;
}

/** Plain-text rendering only: model output is untrusted and never injected as HTML. */
export function Narrative({ text, busy, onGenerate }: { text: string | null; busy: boolean; onGenerate?: () => void }) {
  if (text) {
    return (
      <div className="space-y-2">
        {text.split(/\n{2,}/).map((p, i) => <p key={i} className="whitespace-pre-wrap text-sm leading-6 text-ink/90">{p}</p>)}
        <p className="text-xs text-mute">AI-generated summary of the evidence above. Verify against the signals before acting.</p>
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm text-mute">
      <span>No AI narrative was requested for this scan.</span>
      {onGenerate && (
        <button type="button" onClick={onGenerate} disabled={busy} className="rounded-lg border border-line bg-panel2 px-3 py-1 text-ink hover:border-accent/60 disabled:opacity-50">
          {busy ? "Generating…" : "Generate narrative"}
        </button>
      )}
    </div>
  );
}
