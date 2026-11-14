import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, getApiKey, setApiKey } from "./api/client";
import type { Verdict } from "./api/types";
import { AnalyzeBox, type Submission } from "./components/AnalyzeBox";
import { ErrorBox } from "./components/ui";
import { VerdictView } from "./components/VerdictView";
import { buildScanBody } from "./lib/input";
import { CatalogView } from "./views/CatalogView";
import { FeedView } from "./views/FeedView";
import { VerdictsView } from "./views/VerdictsView";

type Tab = "analyze" | "feed" | "history" | "catalog";
const TABS: { id: Tab; label: string }[] = [
  { id: "analyze", label: "Analyze" },
  { id: "feed", label: "Live feed" },
  { id: "history", label: "Verdicts & stats" },
  { id: "catalog", label: "Catalog" },
];

function tabFromHash(): Tab {
  const h = window.location.hash.replace(/^#\/?/, "");
  return TABS.some((t) => t.id === h) ? (h as Tab) : "analyze";
}

export default function App() {
  const [tab, setTab] = useState<Tab>(tabFromHash);
  const [stack, setStack] = useState<Verdict[]>([]); // navigation trail into child verdicts
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [narrBusy, setNarrBusy] = useState(false);
  const [health, setHealth] = useState<"ok" | "down" | "unknown">("unknown");
  const [version, setVersion] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [key, setKey] = useState(getApiKey);
  const lastBody = useRef<Record<string, unknown> | null>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    const onHash = () => setTab(tabFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const probe = useCallback(() => {
    api.health().then(
      () => setHealth("ok"),
      (e: unknown) => setHealth(e instanceof ApiError && e.status > 0 ? "ok" : "down"),
    );
    api.version().then(
      (v) => setVersion(String(v.version ?? v.engine_version ?? "")),
      () => undefined,
    );
  }, []);
  useEffect(probe, [probe]);

  const go = (t: Tab) => {
    window.location.hash = `/${t}`;
    setTab(t);
  };
  const current = stack[stack.length - 1] ?? null;

  const analyze = async (s: Submission) => {
    setError(null);
    let body: Record<string, unknown>;
    try {
      body = buildScanBody({ type: s.type, text: s.text, file: s.file }, s.options);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid input");
      return;
    }
    abort.current?.abort();
    const ctrl = new AbortController();
    abort.current = ctrl;
    setBusy(true);
    try {
      const v = await api.scan(body, ctrl.signal);
      lastBody.current = body;
      setStack([v]);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      if (abort.current === ctrl) setBusy(false);
    }
  };

  const openStored = async (id: string) => {
    go("analyze");
    setError(null);
    setBusy(true);
    try {
      const v = await api.verdict(id);
      lastBody.current = null;
      setStack([v]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load verdict");
    } finally {
      setBusy(false);
    }
  };

  const generateNarrative = async () => {
    const body = lastBody.current;
    if (!body) return;
    setNarrBusy(true);
    try {
      const v = await api.explain({
        ...body,
        options: { ...(body.options as object), ai_report: true, explain: true },
      });
      setStack([v]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Narrative failed");
    } finally {
      setNarrBusy(false);
    }
  };

  const saveKey = () => {
    setApiKey(key.trim());
    setShowSettings(false);
    probe();
  };

  const trail = stack.length > 1 && (
    <nav aria-label="Artifact trail" className="flex flex-wrap items-center gap-1 text-sm">
      {stack.map((v, i) => (
        <span key={`${v.id}${i}`} className="flex items-center gap-1">
          {i > 0 && (
            <span className="text-mute" aria-hidden="true">
              ›
            </span>
          )}
          {i < stack.length - 1 ? (
            <button
              type="button"
              onClick={() => setStack(stack.slice(0, i + 1))}
              className="max-w-[16rem] truncate rounded-md border border-line px-2 py-0.5 text-mute hover:text-ink"
            >
              {i === 0 ? "Root" : v.kind}: {v.target || v.kind}
            </button>
          ) : (
            <span className="max-w-[16rem] truncate rounded-md border border-accent/40 bg-accent/10 px-2 py-0.5 text-accent">
              {v.kind}: {v.target || v.kind}
            </span>
          )}
        </span>
      ))}
    </nav>
  );

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-4 pb-16 sm:px-6">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-2 focus:rounded focus:bg-accent focus:px-3 focus:py-1 focus:text-bg"
      >
        Skip to content
      </a>
      <header className="flex flex-wrap items-center gap-x-6 gap-y-3 py-5">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="h-9 w-9" aria-hidden="true">
            <rect width="32" height="32" rx="8" fill="var(--color-panel2)" />
            <path
              d="M16 5 6 9v7c0 6 4.3 9.6 10 11 5.7-1.4 10-5 10-11V9z"
              fill="none"
              stroke="var(--color-accent)"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path
              d="m11.5 16 3 3 6-6"
              fill="none"
              stroke="var(--color-accent)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div>
            <h1 className="text-lg font-bold leading-tight tracking-tight">
              UniPhish <span className="text-accent">2</span>{" "}
              <span className="font-normal text-mute">SOC console</span>
            </h1>
            <p className="text-xs text-mute">
              Explainable phishing detection for humans and AI agents
            </p>
          </div>
        </div>
        <nav
          aria-label="Primary"
          className="order-3 flex w-full gap-1 overflow-x-auto sm:order-none sm:w-auto sm:flex-1"
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => go(t.id)}
              aria-current={tab === t.id ? "page" : undefined}
              className={`whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-medium ${tab === t.id ? "bg-panel2 text-accent" : "text-mute hover:text-ink"}`}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-xs text-mute">
          <span className="flex items-center gap-1.5" title="API health">
            <span
              className={`h-2 w-2 rounded-full ${health === "ok" ? "bg-ok" : health === "down" ? "bg-bad" : "bg-warn"}`}
              aria-hidden="true"
            />
            {health === "ok" ? "API online" : health === "down" ? "API unreachable" : "Checking…"}
            {version && ` · v${version}`}
          </span>
          <button
            type="button"
            onClick={() => setShowSettings(!showSettings)}
            aria-expanded={showSettings}
            className="rounded-md border border-line px-2 py-1 hover:text-ink"
          >
            Settings
          </button>
        </div>
      </header>

      {showSettings && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveKey();
          }}
          className="slide-in mb-4 flex flex-wrap items-end gap-3 rounded-2xl border border-line bg-panel/80 p-4"
        >
          <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-mute">
            API key (only needed when the server enforces auth)
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="Not set"
              className="rounded-md border border-line bg-bg/70 px-3 py-1.5 font-mono text-sm text-ink"
            />
          </label>
          <button
            type="submit"
            className="rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-bg"
          >
            Save
          </button>
          <p className="basis-full text-xs text-mute">
            Kept in this tab&apos;s session storage only and sent to this server as a request
            header. It is never embedded in the bundle.
          </p>
        </form>
      )}

      <main id="main" className="flex-1 space-y-4">
        {tab === "analyze" && (
          <>
            <AnalyzeBox busy={busy} onSubmit={(s) => void analyze(s)} />
            {error && <ErrorBox error={error} />}
            {current ? (
              <VerdictView
                key={`${current.id}-${stack.length}`}
                verdict={current}
                trail={trail}
                narrativeBusy={narrBusy}
                onGenerateNarrative={
                  stack.length === 1 && lastBody.current
                    ? () => void generateNarrative()
                    : undefined
                }
                onOpenChild={(v) => {
                  if (v !== current) setStack([...stack, v]);
                }}
              />
            ) : !busy && !error ? (
              <Welcome />
            ) : null}
          </>
        )}
        {tab === "feed" && <FeedView onOpenVerdict={(id) => void openStored(id)} />}
        {tab === "history" && <VerdictsView onOpenVerdict={(id) => void openStored(id)} />}
        {tab === "catalog" && <CatalogView />}
      </main>

      <footer className="pt-10 text-center text-xs text-mute">
        UniPhish 2 · open-source defensive tooling · submitted content is analysed, never executed
      </footer>
    </div>
  );
}

function Welcome() {
  const items = [
    ["URLs", "Homoglyph / IDN spoofing, brand impersonation, abused hosting, redirects"],
    ["Emails", "Authentication, display-name spoofing, links, attachments, QR codes"],
    ["Pages", "AiTM kits, ClickFix, fake CAPTCHA, credential forms, obfuscation"],
    ["Messages", "Smishing and BEC pressure tactics, callback scams, prompt injection"],
  ];
  return (
    <section aria-label="What you can analyze" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {items.map(([h, p]) => (
        <div key={h} className="rounded-2xl border border-line bg-panel/60 p-4">
          <h3 className="text-sm font-semibold text-accent">{h}</h3>
          <p className="mt-1 text-xs leading-5 text-mute">{p}</p>
        </div>
      ))}
    </section>
  );
}
