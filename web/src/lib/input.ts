// Turn what the analyst pasted/uploaded into a POST /v1/scan request body.
import type { InputType, ScanOptions } from "../api/types";

export const MAX_UPLOAD_BYTES = 25_000_000;

const URL_RE = /^(?:[a-z][a-z0-9+.-]*:\/\/|www\.)\S+$/i;
const BARE_HOST_RE = /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$/i;
const EMAIL_HEADER_RE =
  /^(?:received|from|to|subject|date|message-id|return-path|mime-version|delivered-to|x-[a-z-]+|content-type|authentication-results|dkim-signature):/im;

/** Heuristically classify pasted text. */
export function detectInputType(raw: string): Exclude<InputType, "auto" | "file"> {
  const s = raw.trim();
  if (!s) return "text";
  if (!/\s/.test(s) && (URL_RE.test(s) || BARE_HOST_RE.test(s))) return "url";
  if (/^<(?:!doctype html|html|head|body|\?xml|svg)/i.test(s)) return "html";
  const head = s.slice(0, 4000);
  const headerLines = head
    .split(/\r?\n/)
    .slice(0, 40)
    .filter((l) => EMAIL_HEADER_RE.test(l));
  if (headerLines.length >= 2 && /^[A-Za-z][A-Za-z0-9-]*:\s/.test(s)) return "email";
  if (/^<[a-z!][^>]*>/i.test(s) && /<\/[a-z]+>/i.test(s)) return "html";
  return "text";
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function utf8ToBase64(text: string): string {
  return toBase64(new TextEncoder().encode(text));
}

export function optionsPayload(o: ScanOptions): Record<string, boolean> {
  return {
    online: o.online,
    fetch_pages: o.online && o.fetch,
    detonate: o.online && o.detonate,
    explain: o.explain,
    ai_report: o.ai,
  };
}

export interface ScanInput {
  type: InputType;
  text: string;
  file?: { name: string; bytes: Uint8Array } | null;
}

/** Build the JSON body for POST /v1/scan. Throws Error with a user-facing message. */
export function buildScanBody(input: ScanInput, options: ScanOptions): Record<string, unknown> {
  const opts = optionsPayload(options);
  if (input.file) {
    if (input.file.bytes.length > MAX_UPLOAD_BYTES) {
      throw new Error(`File is larger than ${MAX_UPLOAD_BYTES / 1_000_000} MB.`);
    }
    const lower = input.file.name.toLowerCase();
    if (lower.endsWith(".eml")) {
      return { input_type: "email", email: toBase64(input.file.bytes), options: opts };
    }
    return {
      input_type: "file",
      file: toBase64(input.file.bytes),
      filename: input.file.name,
      options: opts,
    };
  }
  const text = input.text.trim();
  if (!text) throw new Error("Paste a URL, message, email source or HTML, or choose a file.");
  const type = input.type === "auto" || input.type === "file" ? detectInputType(text) : input.type;
  switch (type) {
    case "url":
      return { input_type: "url", url: text, options: opts };
    case "email":
      return { input_type: "email", email: utf8ToBase64(input.text), options: opts };
    case "html":
      return { input_type: "page", html: input.text, options: opts };
    default:
      return { input_type: "text", text: input.text, options: opts };
  }
}
