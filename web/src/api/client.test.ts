import { describe, expect, it } from "vitest";
import { parseSseFrame } from "./client";

describe("parseSseFrame", () => {
  it("parses the bus envelope", () => {
    const ev = parseSseFrame(
      'event: verdict\ndata: {"type":"verdict","ts":"2026-01-01T00:00:00Z","data":{"score":91}}',
    );
    expect(ev).toEqual({ type: "verdict", ts: "2026-01-01T00:00:00Z", data: { score: 91 } });
  });
  it("uses the event name for bare payloads", () => {
    const ev = parseSseFrame('event: hunt\ndata: {"domain":"x.example.test"}');
    expect(ev?.type).toBe("hunt");
    expect(ev?.data.domain).toBe("x.example.test");
  });
  it("joins multi-line data and ignores comments and bad json", () => {
    expect(parseSseFrame(": ping")).toBeNull();
    expect(parseSseFrame("data: not json")).toBeNull();
    expect(parseSseFrame('data: {"a":\ndata: 1}')?.data).toEqual({ a: 1 });
  });
});
