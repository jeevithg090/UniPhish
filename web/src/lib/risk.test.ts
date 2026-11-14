import { describe, expect, it } from "vitest";
import type { Verdict } from "../api/types";
import { defang, refang } from "./defang";
import {
  buildSegments,
  buildWaterfall,
  collectIndicators,
  formatLogOdds,
  formatMs,
  levelFromScore,
  normLevel,
  PRIOR_LOGIT,
  revealInvisible,
  segmentClass,
  sigmoid,
} from "./risk";

const sig = (id: string, weight: number, contribution?: number, span?: [number, number]) => ({
  id,
  title: id,
  detail: "",
  weight,
  category: "url",
  confidence: 1,
  analyzer: "t",
  evidence: {},
  mitre: [],
  tags: [],
  span: span ?? null,
  contribution: contribution ?? null,
});

describe("levels", () => {
  it("maps scores to engine default thresholds", () => {
    expect(levelFromScore(0)).toBe("benign");
    expect(levelFromScore(49)).toBe("benign");
    expect(levelFromScore(50)).toBe("suspicious");
    expect(levelFromScore(84)).toBe("suspicious");
    expect(levelFromScore(85)).toBe("malicious");
    expect(levelFromScore(100)).toBe("malicious");
  });
  it("normalises unknown levels to benign", () => {
    expect(normLevel("malicious")).toBe("malicious");
    expect(normLevel("???")).toBe("benign");
    expect(normLevel(undefined)).toBe("benign");
  });
});

describe("formatting", () => {
  it("signs log-odds", () => {
    expect(formatLogOdds(1.234)).toBe("+1.23");
    expect(formatLogOdds(-0.5)).toBe("-0.50");
    expect(formatLogOdds(0)).toBe("0.00");
    expect(formatLogOdds(Number.NaN)).toBe("0.00");
  });
  it("formats durations", () => {
    expect(formatMs(12.4)).toBe("12 ms");
    expect(formatMs(2500)).toBe("2.50 s");
    expect(formatMs(Number.NaN)).toBe("-");
  });
  it("sigmoid is stable at extremes", () => {
    expect(sigmoid(0)).toBeCloseTo(0.5);
    expect(sigmoid(800)).toBe(1);
    expect(sigmoid(-800)).toBe(0);
  });
});

describe("waterfall", () => {
  it("starts at the prior, orders by contribution and ends at the fused logit", () => {
    const steps = buildWaterfall({
      signals: [sig("a", 1, 1), sig("b", 4, 4), sig("c", -2, -2), sig("zero", 0, 0)],
      logit: PRIOR_LOGIT + 3,
    });
    expect(steps[0].kind).toBe("prior");
    expect(steps[0].to).toBe(PRIOR_LOGIT);
    expect(steps.filter((s) => s.kind === "signal").map((s) => s.label)).toEqual(["b", "a", "c"]);
    const last = steps[steps.length - 1];
    expect(last.kind).toBe("total");
    expect(last.to).toBeCloseTo(PRIOR_LOGIT + 3);
    expect(steps.some((s) => s.kind === "children")).toBe(false);
  });
  it("falls back to weight when contribution is missing", () => {
    const steps = buildWaterfall({ signals: [sig("w", 2.5)], logit: PRIOR_LOGIT + 2.5 });
    expect(steps[1].delta).toBe(2.5);
  });
  it("adds a child-evidence step for the logit not explained by own signals", () => {
    const steps = buildWaterfall({ signals: [sig("a", 1, 1)], logit: 3 });
    const child = steps.find((s) => s.kind === "children");
    expect(child).toBeDefined();
    expect(child!.delta).toBeCloseTo(3 - (PRIOR_LOGIT + 1));
    expect(steps[steps.length - 1].to).toBe(3);
  });
});

describe("segments", () => {
  it("returns a single plain segment without spans", () => {
    expect(buildSegments("hello", [sig("a", 1)])).toEqual([
      { text: "hello", signals: [], weight: 0 },
    ]);
  });
  it("splits on spans and rebuilds the original text", () => {
    const text = "https://paypa1.test/login";
    const segs = buildSegments(text, [sig("a", 3, 3, [8, 14]), sig("b", 1, 1, [20, 25])]);
    expect(segs.map((s) => s.text).join("")).toBe(text);
    expect(segs.find((s) => s.text === "paypa1")?.weight).toBe(3);
    expect(segs.find((s) => s.text === "login")?.weight).toBe(1);
    expect(segs.find((s) => s.text === "https://")?.weight).toBe(0);
  });
  it("handles overlapping spans by keeping the strongest weight", () => {
    const segs = buildSegments("abcdef", [sig("a", 1, 1, [0, 4]), sig("b", 4, 4, [2, 6])]);
    expect(segs.map((s) => s.text)).toEqual(["ab", "cd", "ef"]);
    expect(segs[1].weight).toBe(4);
    expect(segs[1].signals).toEqual([0, 1]);
  });
  it("clamps out-of-range spans and indexes by code point", () => {
    const text = "a\u{1F600}b";
    const segs = buildSegments(text, [sig("a", 2, 2, [1, 2]), sig("o", 2, 2, [2, 99])]);
    expect(segs.map((s) => s.text)).toEqual(["a", "\u{1F600}", "b"]);
    expect(buildSegments("", [])).toEqual([]);
  });
  it("styles negative, strong and weak evidence differently", () => {
    expect(segmentClass(0)).toBe("");
    expect(segmentClass(-1)).toContain("ok");
    expect(segmentClass(3)).toContain("bad");
    expect(segmentClass(1.5)).toContain("warn");
    expect(segmentClass(0.5)).toContain("info");
  });
  it("reveals invisible characters", () => {
    expect(revealInvisible("a​b‮")).toBe("a<U+200B>b<U+202E>");
  });
});

describe("defang", () => {
  it("defangs and refangs URLs round-trip", () => {
    const u = "https://evil.example.test/a.b?x=1.2";
    const d = defang(u, "url");
    expect(d).toBe("hxxps://evil[.]example[.]test/a.b?x=1.2");
    expect(refang(d)).toBe(u);
  });
  it("defangs domains, emails and IPs; leaves hashes alone", () => {
    expect(defang("a.example.test", "domain")).toBe("a[.]example[.]test");
    expect(defang("bob@x.example", "email")).toBe("bob[@]x[.]example");
    expect(defang("203.0.113.7", "ipv4")).toBe("203[.]0[.]113[.]7");
    expect(defang("abc123", "sha256")).toBe("abc123");
  });
});

describe("indicators", () => {
  it("de-duplicates across the tree", () => {
    const mk = (children: Verdict[], values: string[]): Verdict =>
      ({
        indicators: values.map((value) => ({ type: "domain", value })),
        children,
      }) as unknown as Verdict;
    const tree = mk([mk([], ["B.test", "c.test"])], ["a.test", "b.test"]);
    expect(collectIndicators(tree).map((i) => i.value)).toEqual(["a.test", "b.test", "c.test"]);
  });
});
