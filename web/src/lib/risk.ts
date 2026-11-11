// Presentation helpers for risk/score rendering. Pure, DOM-free and unit tested.
import type { Level, Signal, Verdict } from "../api/types";

/** Prior log-odds used by the engine (uniphish.core.scoring.PRIOR_LOGIT). */
export const PRIOR_LOGIT = -2.0;

export function sigmoid(x: number): number {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const e = Math.exp(x);
  return e / (1 + e);
}

export function clamp(x: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, x));
}

/** Level for a 0..100 score using the engine defaults (0.5 suspicious, 0.85 malicious). */
export function levelFromScore(score: number): Level {
  if (score >= 85) return "malicious";
  if (score >= 50) return "suspicious";
  return "benign";
}

export function normLevel(level: string | undefined | null): Level {
  return level === "malicious" || level === "suspicious" ? level : "benign";
}

export interface LevelStyle {
  label: string;
  /** CSS colour (a CSS variable reference) used for strokes/fills. */
  color: string;
  /** Tailwind classes for chips. */
  chip: string;
}

export const LEVEL_STYLE: Record<Level, LevelStyle> = {
  benign: { label: "Benign", color: "var(--color-ok)", chip: "border-ok/40 bg-ok/10 text-ok" },
  suspicious: {
    label: "Suspicious",
    color: "var(--color-warn)",
    chip: "border-warn/40 bg-warn/10 text-warn",
  },
  malicious: {
    label: "Malicious",
    color: "var(--color-bad)",
    chip: "border-bad/40 bg-bad/10 text-bad",
  },
};

export const ACTION_LABEL: Record<string, string> = {
  allow: "Allow",
  warn: "Warn the user",
  block: "Block",
};

export function formatLogOdds(x: number, digits = 2): string {
  const v = Number.isFinite(x) ? x : 0;
  const s = v.toFixed(digits);
  return v > 0 ? `+${s}` : s;
}

export function formatMs(ms: number): string {
  if (!Number.isFinite(ms)) return "-";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

export function signalContribution(s: Pick<Signal, "contribution" | "weight">): number {
  return typeof s.contribution === "number" && Number.isFinite(s.contribution)
    ? s.contribution
    : s.weight;
}

export interface WaterfallStep {
  key: string;
  label: string;
  kind: "prior" | "signal" | "children" | "total";
  /** Log-odds change (0 for prior/total). */
  delta: number;
  /** Cumulative log-odds before this step. */
  from: number;
  /** Cumulative log-odds after this step. */
  to: number;
  signal?: Signal;
}

/**
 * Build the explainability waterfall: prior -> each signal's effective contribution
 * (largest positive first, then benign evidence) -> optional "child artifacts" step
 * (the part of the verdict logit that came from children) -> final logit.
 */
export function buildWaterfall(v: Pick<Verdict, "signals" | "logit">): WaterfallStep[] {
  const steps: WaterfallStep[] = [];
  let acc = PRIOR_LOGIT;
  steps.push({ key: "prior", label: "Prior (base rate)", kind: "prior", delta: 0, from: acc, to: acc });
  const sorted = [...v.signals]
    .map((s, i) => ({ s, i, c: signalContribution(s) }))
    .filter((x) => x.c !== 0)
    .sort((a, b) => b.c - a.c || a.i - b.i);
  for (const { s, i, c } of sorted) {
    steps.push({
      key: `${s.id}#${i}`,
      label: s.title || s.id,
      kind: "signal",
      delta: c,
      from: acc,
      to: acc + c,
      signal: s,
    });
    acc += c;
  }
  const finalLogit = Number.isFinite(v.logit) ? v.logit : acc;
  const rest = finalLogit - acc;
  if (Math.abs(rest) > 0.05) {
    steps.push({
      key: "children",
      label: rest > 0 ? "Evidence from child artifacts" : "Benign child artifacts",
      kind: "children",
      delta: rest,
      from: acc,
      to: finalLogit,
    });
    acc = finalLogit;
  }
  steps.push({ key: "total", label: "Fused log-odds", kind: "total", delta: 0, from: acc, to: acc });
  return steps;
}

export interface Segment {
  text: string;
  /** Indices (into the input signal array) of signals covering this segment. */
  signals: number[];
  /** Strongest signal contribution covering the segment (0 if none). */
  weight: number;
}

/**
 * Split `text` into segments by signal spans. Spans are [start, end) in Unicode code
 * points (Python str indices), so we index by code point, not UTF-16 unit.
 */
export function buildSegments(text: string, signals: Pick<Signal, "span" | "weight" | "contribution">[]): Segment[] {
  const chars = Array.from(text);
  const n = chars.length;
  if (n === 0) return [];
  const cover: number[][] = Array.from({ length: n }, () => []);
  signals.forEach((s, idx) => {
    if (!s.span) return;
    const a = clamp(Math.floor(s.span[0]), 0, n);
    const b = clamp(Math.floor(s.span[1]), 0, n);
    for (let i = a; i < b; i++) cover[i].push(idx);
  });
  const out: Segment[] = [];
  let cur: Segment | null = null;
  let curKey = "";
  for (let i = 0; i < n; i++) {
    const ids = cover[i];
    const key = ids.join(",");
    if (cur && key === curKey) {
      cur.text += chars[i];
    } else {
      const w = ids.reduce((m, id) => {
        const c = signalContribution(signals[id]);
        return Math.abs(c) > Math.abs(m) ? c : m;
      }, 0);
      cur = { text: chars[i], signals: ids, weight: w };
      curKey = key;
      out.push(cur);
    }
  }
  return out;
}

/** Tailwind classes for a highlighted segment by its strongest contribution. */
export function segmentClass(weight: number): string {
  if (weight === 0) return "";
  if (weight < 0) return "bg-ok/20 text-ok underline decoration-ok/60 decoration-2 underline-offset-4";
  if (weight >= 2.5) return "bg-bad/25 text-bad underline decoration-bad decoration-2 underline-offset-4";
  if (weight >= 1.0) return "bg-warn/25 text-warn underline decoration-warn decoration-2 underline-offset-4";
  return "bg-info/20 text-info underline decoration-info/70 decoration-2 underline-offset-4";
}

/** Show characters that are invisible or confusable-prone so analysts can see them. */
export function revealInvisible(text: string): string {
  // eslint-disable-next-line no-misleading-character-class
  return text.replace(/[​-‏‪-‮⁠-⁤⁦-⁩﻿]/g, (c) =>
    `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`,
  );
}

/** Flatten a verdict tree (depth-first) with depth, for counting and tables. */
export function flattenVerdicts(v: Verdict, depth = 0): { v: Verdict; depth: number }[] {
  return [{ v, depth }, ...v.children.flatMap((c) => flattenVerdicts(c, depth + 1))];
}

/** Collect distinct indicators from a verdict tree (type+value, case-insensitive). */
export function collectIndicators(v: Verdict): Verdict["indicators"] {
  const seen = new Map<string, Verdict["indicators"][number]>();
  for (const { v: node } of flattenVerdicts(v)) {
    for (const i of node.indicators) {
      const key = `${i.type}\u0000${i.value.toLowerCase()}`;
      if (!seen.has(key)) seen.set(key, i);
    }
  }
  return [...seen.values()];
}
