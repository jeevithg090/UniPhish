// Mirrors uniphish.core.types (Verdict and friends) as served by the /v1 API.
export type Level = "benign" | "suspicious" | "malicious";
export type Action = "allow" | "warn" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ArtifactKind = "url" | "page" | "email" | "file" | "text";

export interface Signal {
  id: string;
  title: string;
  detail: string;
  weight: number;
  category: string;
  severity?: Severity | null;
  confidence: number;
  analyzer: string;
  evidence: Record<string, unknown>;
  mitre: string[];
  tags: string[];
  span?: [number, number] | null;
  contribution?: number | null;
}

export interface Indicator {
  type: string;
  value: string;
  role?: string | null;
  malicious?: boolean | null;
  context?: string | null;
}

export interface BrandMatch {
  brand: string;
  name: string;
  technique: string;
  confidence: number;
  legit_domains: string[];
  evidence: string;
  official: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  framework: string;
  url: string;
}

export interface AnalyzerRun {
  name: string;
  status: string;
  duration_ms: number;
  signals: number;
  error?: string | null;
}

export interface Verdict {
  id: string;
  created_at: string;
  engine_version: string;
  kind: ArtifactKind;
  target: string;
  artifact_id: string;
  origin?: string | null;
  risk: number;
  score: number;
  logit: number;
  level: Level;
  action: Action;
  confidence: number;
  summary: string;
  signals: Signal[];
  indicators: Indicator[];
  brand?: BrandMatch | null;
  techniques: string[];
  mitre: MitreTechnique[];
  children: Verdict[];
  analyzers: AnalyzerRun[];
  meta: Record<string, unknown>;
  duration_ms: number;
}

/** A row from GET /v1/verdicts (metadata only). */
export interface VerdictRow {
  id: string;
  created_at: string;
  kind: string;
  target: string;
  score: number;
  level: string;
  brand?: string | null;
  summary?: string | null;
  source?: string | null;
}

export interface Stats {
  verdicts: number;
  by_level: Record<string, number>;
  by_kind: Record<string, number>;
  score_histogram: number[];
  indicators: number;
  malicious_indicators: number;
  hunt_events?: number;
  stix_objects?: number;
  [k: string]: unknown;
}

export interface TimelineBucket {
  hour: string;
  total: number;
  benign: number;
  suspicious: number;
  malicious: number;
}

export interface CatalogEntry {
  id: string;
  title: string;
  analyzer: string;
}

export interface AnalyzerInfo {
  name: string;
  description: string;
  stage?: number;
  kinds: string[];
  requires_online?: boolean;
}

export interface ScanOptions {
  online: boolean;
  fetch: boolean;
  detonate: boolean;
  explain: boolean;
  ai: boolean;
}

export type InputType = "auto" | "url" | "text" | "email" | "html" | "file";

export interface LiveEvent {
  type: string;
  ts: string;
  data: Record<string, unknown>;
}
