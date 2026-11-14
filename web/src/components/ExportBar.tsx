import { useState } from "react";
import { api, EXPORT_FORMATS, type ExportFormat } from "../api/client";
import { CopyButton, downloadText, Spinner } from "./ui";

export function ExportBar({ verdictId }: { verdictId: string }) {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<{
    format: ExportFormat;
    text: string;
    filename: string;
    mime: string;
  } | null>(null);

  const run = async (format: ExportFormat) => {
    setBusy(format);
    setError(null);
    try {
      const r = await api.exportVerdict(format, verdictId);
      setPreview({ format, ...r });
    } catch (e) {
      setPreview(null);
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <div className="flex flex-wrap gap-2">
        {EXPORT_FORMATS.map((f) => (
          <button
            key={f.id}
            type="button"
            title={f.hint}
            disabled={busy !== null}
            onClick={() => void run(f.id)}
            className="rounded-lg border border-line bg-panel2 px-3 py-1.5 text-sm hover:border-accent/60 disabled:opacity-50"
          >
            {busy === f.id ? <Spinner label={f.label} /> : f.label}
          </button>
        ))}
      </div>
      {error && (
        <p
          role="alert"
          className="mt-3 rounded-lg border border-bad/40 bg-bad/10 px-3 py-2 text-sm text-bad"
        >
          {error}
        </p>
      )}
      {preview && (
        <div className="slide-in mt-3 rounded-xl border border-line bg-bg/70">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2 text-xs text-mute">
            <span>
              {preview.filename} · {preview.text.length.toLocaleString()} chars
            </span>
            <span className="flex gap-2">
              <CopyButton text={preview.text} />
              <button
                type="button"
                onClick={() => downloadText(preview.filename, preview.text, preview.mime)}
                className="rounded-md border border-line px-2 py-0.5 text-mute hover:border-accent/50 hover:text-ink"
              >
                Download
              </button>
            </span>
          </div>
          <pre className="max-h-72 overflow-auto p-3 font-mono text-xs leading-5 scroll-thin">
            {preview.text.slice(0, 60_000)}
            {preview.text.length > 60_000
              ? "\n… (truncated preview; download for the full export)"
              : ""}
          </pre>
        </div>
      )}
    </div>
  );
}
