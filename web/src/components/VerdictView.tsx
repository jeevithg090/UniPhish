import type { ReactNode } from "react";
import type { Verdict } from "../api/types";
import { LEVEL_STYLE, formatMs, normLevel } from "../lib/risk";
import { AnalyzerTable } from "./AnalyzerTable";
import { ChildTree } from "./ChildTree";
import { ExportBar } from "./ExportBar";
import { Gauge } from "./Gauge";
import { Indicators } from "./Indicators";
import { MitreChips } from "./MitreChips";
import { Narrative, narrativeOf } from "./Narrative";
import { TargetHighlight } from "./TargetHighlight";
import { Waterfall } from "./Waterfall";
import { Card, Chip } from "./ui";

export function VerdictView({
  verdict,
  onOpenChild,
  onGenerateNarrative,
  narrativeBusy,
  trail,
}: {
  verdict: Verdict;
  onOpenChild: (v: Verdict) => void;
  onGenerateNarrative?: () => void;
  narrativeBusy: boolean;
  trail?: ReactNode;
}) {
  const lv = normLevel(verdict.level);
  const st = LEVEL_STYLE[lv];
  const brand = verdict.brand;
  const techniques = verdict.techniques ?? [];
  const meta = Object.entries(verdict.meta ?? {}).filter(([, v]) => ["string", "number", "boolean"].includes(typeof v)).slice(0, 12);
  return (
    <div className="slide-in space-y-4" aria-live="polite">
      {trail}
      <Card>
        <div className="grid gap-6 md:grid-cols-[17rem_1fr]">
          <Gauge score={verdict.score} level={verdict.level} action={verdict.action} />
          <div className="min-w-0 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Chip className={st.chip}>{st.label}</Chip>
              <Chip className="border-line bg-panel2 text-mute">{verdict.kind}</Chip>
              <Chip className="border-line bg-panel2 text-mute" title="Margin-based decision confidence">confidence {Math.round(verdict.confidence * 100)}%</Chip>
              <Chip className="border-line bg-panel2 text-mute">{formatMs(verdict.duration_ms)}</Chip>
              {verdict.origin && <Chip className="border-line bg-panel2 text-mute">from {verdict.origin}</Chip>}
            </div>
            <p className="text-lg font-semibold leading-snug">{verdict.summary || "Analysis complete."}</p>
            {brand && (
              <div className={`rounded-xl border px-3 py-2 text-sm ${brand.official ? "border-ok/40 bg-ok/10" : "border-bad/40 bg-bad/10"}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs uppercase tracking-wider text-mute">{brand.official ? "Official asset of" : "Impersonates"}</span>
                  <b className="text-base">{brand.name}</b>
                  <Chip className="border-line bg-panel2 text-mute">{brand.technique}</Chip>
                  <span className="text-xs text-mute">{Math.round(brand.confidence * 100)}% match</span>
                </div>
                {brand.evidence && <p className="mt-1 text-xs text-mute">{brand.evidence}</p>}
                {!brand.official && brand.legit_domains.length > 0 && (
                  <p className="mt-1 text-xs text-mute">Legitimate domains: <span className="font-mono text-ink/90">{brand.legit_domains.slice(0, 4).join(", ")}</span></p>
                )}
              </div>
            )}
            {techniques.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <span className="text-mute">Techniques</span>
                {techniques.map((t) => <Chip key={t} className="border-warn/30 bg-warn/10 text-warn">{t.replace(/_/g, " ")}</Chip>)}
              </div>
            )}
          </div>
        </div>
      </Card>

      <Card title="Target">
        <TargetHighlight verdict={verdict} />
      </Card>

      <Card title="Why this score: signal waterfall" right={<span className="font-mono text-xs text-mute">{verdict.signals.length} signals · logit {verdict.logit.toFixed(2)}</span>}>
        <Waterfall verdict={verdict} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="MITRE ATT&CK / ATLAS"><MitreChips techniques={verdict.mitre ?? []} /></Card>
        <Card title="AI analyst narrative"><Narrative text={narrativeOf(verdict)} busy={narrativeBusy} onGenerate={onGenerateNarrative} /></Card>
      </div>

      <Card title="Extracted indicators (IOCs)"><Indicators verdict={verdict} /></Card>
      <Card title="Artifact tree"><ChildTree verdict={verdict} onOpen={onOpenChild} /></Card>
      <Card title="Analyzer runs"><AnalyzerTable runs={verdict.analyzers ?? []} totalMs={verdict.duration_ms} /></Card>
      <Card title="Export detection content"><ExportBar verdictId={verdict.id} /></Card>

      {meta.length > 0 && (
        <Card title="Artifact facts">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            {meta.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-mute">{k.replace(/_/g, " ")}</dt>
                <dd className="break-all font-mono text-xs leading-6">{String(v)}</dd>
              </div>
            ))}
          </dl>
        </Card>
      )}
    </div>
  );
}
