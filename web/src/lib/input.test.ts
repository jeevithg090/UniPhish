import { describe, expect, it } from "vitest";
import { buildScanBody, detectInputType, optionsPayload, toBase64, utf8ToBase64 } from "./input";
import type { ScanOptions } from "../api/types";

const base: ScanOptions = { online: false, fetch: true, detonate: true, explain: false, ai: false };

describe("detectInputType", () => {
  it("detects URLs, bare hosts, html, email and text", () => {
    expect(detectInputType("https://paypa1.example.test/login")).toBe("url");
    expect(detectInputType("login.example.test/a?b=c")).toBe("url");
    expect(detectInputType("<!DOCTYPE html><html><body>x</body></html>")).toBe("html");
    expect(detectInputType("From: a@example.test\nSubject: hi\nReceived: by x\n\nbody")).toBe("email");
    expect(detectInputType("Your parcel is held, pay at https://x.example.test")).toBe("text");
    expect(detectInputType("   ")).toBe("text");
  });
  it("does not treat a sentence with a colon as an email", () => {
    expect(detectInputType("Subject: urgent\nplease call us")).toBe("text");
  });
});

describe("options", () => {
  it("gates fetch/detonate on online", () => {
    expect(optionsPayload(base)).toMatchObject({ online: false, fetch_pages: false, detonate: false });
    expect(optionsPayload({ ...base, online: true })).toMatchObject({ fetch_pages: true, detonate: true });
  });
});

describe("buildScanBody", () => {
  it("builds url/text/email/html bodies", () => {
    expect(buildScanBody({ type: "auto", text: " https://a.example.test " }, base)).toMatchObject({
      input_type: "url",
      url: "https://a.example.test",
    });
    expect(buildScanBody({ type: "text", text: "hello" }, base)).toMatchObject({ input_type: "text", text: "hello" });
    const e = buildScanBody({ type: "email", text: "From: x\n" }, base);
    expect(e.email).toBe(utf8ToBase64("From: x\n"));
    expect(buildScanBody({ type: "html", text: "<p>x</p>" }, base)).toMatchObject({ input_type: "page" });
  });
  it("encodes files, routing .eml to email", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(buildScanBody({ type: "auto", text: "", file: { name: "a.eml", bytes } }, base)).toMatchObject({
      input_type: "email",
      email: toBase64(bytes),
    });
    expect(buildScanBody({ type: "auto", text: "", file: { name: "a.pdf", bytes } }, base)).toMatchObject({
      input_type: "file",
      filename: "a.pdf",
    });
  });
  it("rejects empty input", () => {
    expect(() => buildScanBody({ type: "auto", text: "  " }, base)).toThrow();
  });
  it("base64-encodes unicode safely", () => {
    expect(atob(utf8ToBase64("pаypal"))).toHaveLength(new TextEncoder().encode("pаypal").length);
  });
});
