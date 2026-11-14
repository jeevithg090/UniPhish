import { type DragEvent, useRef, useState } from "react";
import type { InputType, ScanOptions } from "../api/types";
import { detectInputType, MAX_UPLOAD_BYTES } from "../lib/input";
import { Spinner } from "./ui";

export interface Submission {
  type: InputType;
  text: string;
  file: { name: string; bytes: Uint8Array } | null;
  options: ScanOptions;
}

const TYPES: { id: InputType; label: string }[] = [
  { id: "auto", label: "Auto-detect" },
  { id: "url", label: "URL" },
  { id: "text", label: "Message" },
  { id: "email", label: "Email source" },
  { id: "html", label: "HTML page" },
];

const OPTS: { key: keyof ScanOptions; label: string; hint: string; needsOnline?: boolean }[] = [
  {
    key: "online",
    label: "Online enrichment",
    hint: "DNS, RDAP, TLS, ASN and reputation feeds (server policy applies)",
  },
  {
    key: "fetch",
    label: "Fetch page",
    hint: "Statically fetch the URL through the SSRF-safe client",
    needsOnline: true,
  },
  {
    key: "detonate",
    label: "Detonate",
    hint: "Render in a sandboxed headless browser",
    needsOnline: true,
  },
  { key: "explain", label: "Explain (saliency)", hint: "Slower model explanations" },
  { key: "ai", label: "AI narrative", hint: "LLM-written analyst summary, if configured" },
];

export function AnalyzeBox({
  busy,
  onSubmit,
}: {
  busy: boolean;
  onSubmit: (s: Submission) => void;
}) {
  const [type, setType] = useState<InputType>("auto");
  const [text, setText] = useState("");
  const [file, setFile] = useState<Submission["file"]>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [options, setOptions] = useState<ScanOptions>({
    online: false,
    fetch: false,
    detonate: false,
    explain: false,
    ai: false,
  });
  const input = useRef<HTMLInputElement>(null);

  const load = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_UPLOAD_BYTES) {
      setFileError(`${f.name} is larger than ${MAX_UPLOAD_BYTES / 1_000_000} MB.`);
      return;
    }
    setFileError(null);
    setFile({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    void load(e.dataTransfer.files[0]);
  };
  const guessed = !file && text.trim() ? detectInputType(text) : null;
  const canSubmit = !busy && (!!file || text.trim().length > 0);
  const submit = () => canSubmit && onSubmit({ type, text, file, options });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
      className={`rounded-2xl border bg-panel/80 p-4 backdrop-blur transition-colors ${drag ? "border-accent" : "border-line"}`}
      aria-label="Analyze an artifact"
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <label htmlFor="analyze-input" className="text-sm font-semibold">
          Analyze
        </label>
        {/* biome-ignore lint/a11y/useSemanticElements: an inline toggle-button group; a fieldset would break the flex row layout */}
        <div role="group" aria-label="Input type" className="flex flex-wrap gap-1">
          {TYPES.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setType(t.id)}
              aria-pressed={type === t.id}
              className={`rounded-md border px-2 py-0.5 text-xs ${type === t.id ? "border-accent/60 bg-accent/10 text-accent" : "border-line text-mute hover:text-ink"}`}
            >
              {t.label}
            </button>
          ))}
        </div>
        {guessed && type === "auto" && (
          <span className="text-xs text-mute">
            looks like: <b className="text-ink">{guessed}</b>
          </span>
        )}
      </div>

      {file ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-bg/70 px-3 py-3 text-sm">
          <span className="min-w-0 truncate font-mono">
            {file.name}{" "}
            <span className="text-mute">· {(file.bytes.length / 1024).toFixed(1)} KB</span>
          </span>
          <button
            type="button"
            onClick={() => {
              setFile(null);
              if (input.current) input.current.value = "";
            }}
            className="rounded-md border border-line px-2 py-0.5 text-xs text-mute hover:text-ink"
          >
            Remove
          </button>
        </div>
      ) : (
        <textarea
          id="analyze-input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter") submit();
          }}
          rows={5}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          placeholder="Paste a URL, an SMS or chat message, a raw email (headers + body), or HTML. Drop a file here to scan an attachment, image or .eml."
          className="block w-full resize-y rounded-xl border border-line bg-bg/70 p-3 font-mono text-sm leading-6 placeholder:text-mute/70 focus:border-accent/60"
        />
      )}
      {fileError && (
        <p role="alert" className="mt-2 text-sm text-bad">
          {fileError}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        {OPTS.map((o) => {
          const disabled = !!o.needsOnline && !options.online;
          return (
            <label
              key={o.key}
              title={o.hint}
              className={`flex items-center gap-1.5 text-xs ${disabled ? "cursor-not-allowed opacity-40" : "cursor-pointer text-mute hover:text-ink"}`}
            >
              <input
                type="checkbox"
                disabled={disabled}
                checked={options[o.key] && !disabled}
                onChange={(e) => setOptions({ ...options, [o.key]: e.target.checked })}
                className="accent-accent"
              />
              {o.label}
            </label>
          );
        })}
        <span className="flex-1" />
        <input
          ref={input}
          type="file"
          className="sr-only"
          id="analyze-file"
          onChange={(e) => void load(e.target.files?.[0])}
        />
        <label
          htmlFor="analyze-file"
          className="cursor-pointer rounded-lg border border-line px-3 py-1.5 text-sm text-mute hover:border-accent/50 hover:text-ink"
        >
          Choose file
        </label>
        <button
          type="submit"
          disabled={!canSubmit}
          className="rounded-lg bg-accent px-5 py-1.5 text-sm font-semibold text-bg hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? <Spinner label="Analyzing" /> : "Analyze"}
        </button>
      </div>
      <p className="mt-2 text-xs text-mute">
        Content is sent only to your UniPhish server and is never executed. Ctrl/Cmd+Enter to
        analyze.
      </p>
    </form>
  );
}
