import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, getApiKey, setApiKey } from "./api/client";
import type { Verdict } from "./api/types";
import { AnalyzeBox, type Submission } from "./components/AnalyzeBox";
import { ThemeToggle } from "./components/ThemeToggle";
import { ErrorBox, Spinner, useTimeout } from "./components/ui";
import { VerdictView } from "./components/VerdictView";
import { buildScanBody } from "./lib/input";
import { type Route, routeFromHash, routeTitle, TABS, type Tab } from "./lib/route";

// Secondary views are split into their own chunks so the first load only ships Analyze.
const FeedView = lazy(() => import("./views/FeedView").then((m) => ({ default: m.FeedView })));
const VerdictsView = lazy(() =>
  import("./views/VerdictsView").then((m) => ({ default: m.VerdictsView })),
);
const CatalogView = lazy(() =>
  import("./views/CatalogView").then((m) => ({ default: m.CatalogView })),
);

export default function App() {
  const [tab, setTab] = useState<Route>(() => routeFromHash(window.location.hash));
  const [stack, setStack] = useState<Verdict[]>([]); // navigation trail into child verdicts
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [narrBusy, setNarrBusy] = useState(false);
  const [health, setHealth] = useState<"ok" | "down" | "unknown">("unknown");
  const [version, setVersion] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [key, setKey] = useState(getApiKey);
  const [notice, setNotice] = useState<string | null>(null);
  const clearNoticeLater = useTimeout();
  const lastBody = useRef<Record<string, unknown> | null>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    const onHash = () => setTab(routeFromHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    document.title = routeTitle(tab);
  }, [tab]);

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
    const k = key.trim();
    setApiKey(k);
    setShowSettings(false);
    setNotice(k ? "API key saved for this tab." : "API key cleared.");
    clearNoticeLater(() => setNotice(null), 3000);
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
      <button
        type="button"
        onClick={() => document.getElementById("main")?.focus()}
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-2 focus:z-10 focus:rounded focus:bg-accent focus:px-3 focus:py-1 focus:text-on-accent"
      >
        Skip to content
      </button>
      <header className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4 sm:py-5">
        <a
          href="#/analyze"
          className="flex min-w-0 items-center gap-3 rounded-lg"
          aria-label="UniPhish 2 SOC console, go to Analyze"
        >
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
          <div className="min-w-0">
            <p className="text-lg font-bold leading-tight tracking-tight text-ink">
              UniPhish <span className="text-accent">2</span>{" "}
              <span className="font-normal text-mute">SOC console</span>
            </p>
            <p className="hidden text-xs text-mute sm:block">
              Explainable phishing detection for humans and AI agents
            </p>
          </div>
        </a>
        <nav
          aria-label="Primary"
          className="order-3 grid w-full grid-cols-4 gap-1 rounded-xl border border-line bg-panel/70 p-1 md:order-none md:flex md:w-auto md:flex-1 md:border-0 md:bg-transparent md:p-0"
        >
          {TABS.map((t) => (
            <a
              key={t.id}
              href={`#/${t.id}`}
              aria-current={tab === t.id ? "page" : undefined}
              className={`flex items-center justify-center whitespace-nowrap rounded-lg px-2 py-2 text-sm font-medium md:px-3 md:py-1.5 ${tab === t.id ? "bg-panel2 text-accent shadow-sm" : "text-mute hover:bg-panel2/60 hover:text-ink"}`}
            >
              <span className="md:hidden">{t.short}</span>
              <span className="hidden md:inline">{t.label}</span>
            </a>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2 text-xs text-mute">
          <span
            className="flex items-center gap-1.5 whitespace-nowrap"
            role="status"
            title="API health"
          >
            <span
              className={`h-2 w-2 rounded-full ${health === "ok" ? "bg-ok" : health === "down" ? "bg-bad" : "bg-warn"}`}
              aria-hidden="true"
            />
            {health === "ok" ? "API online" : health === "down" ? "API unreachable" : "Checking…"}
            {version && ` · v${version}`}
          </span>
          <ThemeToggle />
          <button
            type="button"
            onClick={() => setShowSettings(!showSettings)}
            aria-expanded={showSettings}
            aria-controls="settings-panel"
            className="rounded-lg border border-line px-2.5 py-1.5 hover:border-accent/50 hover:text-ink"
          >
            Settings
          </button>
        </div>
      </header>

      {notice && (
        <p
          role="status"
          className="fade-in mb-4 rounded-xl border border-ok/40 bg-ok/10 px-4 py-2 text-sm text-ok"
        >
          {notice}
        </p>
      )}

      {showSettings && (
        <form
          id="settings-panel"
          aria-label="Settings"
          onSubmit={(e) => {
            e.preventDefault();
            saveKey();
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape") setShowSettings(false);
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
              className="rounded-lg border border-line bg-bg/70 px-3 py-1.5 font-mono text-sm text-ink focus:border-accent/60"
            />
          </label>
          <button
            type="submit"
            className="rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-on-accent hover:brightness-110"
          >
            Save
          </button>
          <button
            type="button"
            onClick={() => setShowSettings(false)}
            className="rounded-lg border border-line px-4 py-1.5 text-sm text-mute hover:text-ink"
          >
            Cancel
          </button>
          <p className="basis-full text-xs text-mute">
            Kept in this tab&apos;s session storage only and sent to this server as a request
            header. It is never embedded in the bundle.
          </p>
        </form>
      )}

      <main id="main" tabIndex={-1} className="flex-1 space-y-4 outline-none">
        <h1 className="sr-only">{TABS.find((t) => t.id === tab)?.label ?? "Page not found"}</h1>
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
        <Suspense fallback={<Spinner label="Loading view" />}>
          {tab === "feed" && <FeedView onOpenVerdict={(id) => void openStored(id)} />}
          {tab === "history" && <VerdictsView onOpenVerdict={(id) => void openStored(id)} />}
          {tab === "catalog" && <CatalogView />}
        </Suspense>
        {tab === "notfound" && <NotFound />}
      </main>

      <footer className="pt-10 text-center text-xs text-mute">
        UniPhish 2 · open-source defensive tooling · submitted content is analysed, never executed
      </footer>
    </div>
  );
}

function NotFound() {
  return (
    <section className="fade-in rounded-2xl border border-line bg-panel/80 px-6 py-14 text-center">
      <p className="font-mono text-5xl font-bold text-accent">404</p>
      <h2 className="mt-3 text-lg font-semibold">This page doesn&apos;t exist</h2>
      <p className="mx-auto mt-2 max-w-md text-sm text-mute">
        The console has four views: Analyze, Live feed, Verdicts &amp; stats and Catalog. The link
        you followed points to none of them.
      </p>
      <a
        href="#/analyze"
        className="mt-6 inline-flex rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-on-accent hover:brightness-110"
      >
        Back to Analyze
      </a>
    </section>
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
        <div key={h} className="fade-in rounded-2xl border border-line bg-panel/60 p-4">
          <h2 className="text-sm font-semibold text-accent">{h}</h2>
          <p className="mt-1 text-xs leading-5 text-mute">{p}</p>
        </div>
      ))}
    </section>
  );
}
