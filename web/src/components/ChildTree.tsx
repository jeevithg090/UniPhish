import { useState } from "react";
import type { Verdict } from "../api/types";
import { flattenVerdicts, LEVEL_STYLE, normLevel } from "../lib/risk";
import { Chip } from "./ui";

function Node({ v, depth, onOpen }: { v: Verdict; depth: number; onOpen: (v: Verdict) => void }) {
  const [open, setOpen] = useState(depth < 1);
  const lv = normLevel(v.level);
  const has = v.children.length > 0;
  const top = [...v.signals]
    .sort((a, b) => (b.contribution ?? b.weight) - (a.contribution ?? a.weight))
    .slice(0, 3);
  return (
    <li>
      <div
        className="flex flex-wrap items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-panel2"
        style={{ paddingLeft: `${depth * 18 + 8}px` }}
      >
        {has ? (
          <button
            type="button"
            onClick={() => setOpen(!open)}
            aria-expanded={open}
            aria-label={open ? "Collapse" : "Expand"}
            className="w-4 text-mute"
          >
            {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-4 text-center text-mute" aria-hidden="true">
            ·
          </span>
        )}
        <Chip className={LEVEL_STYLE[lv].chip}>{v.score}</Chip>
        <Chip className="border-line bg-panel2 text-mute">{v.kind}</Chip>
        {v.origin && <span className="text-xs text-mute">{v.origin}</span>}
        <button
          type="button"
          onClick={() => onOpen(v)}
          className="min-w-0 max-w-full flex-1 truncate text-left font-mono text-sm hover:text-accent"
          title={v.target}
        >
          {v.target || "(no label)"}
        </button>
        {top
          .filter((s) => (s.contribution ?? s.weight) > 0)
          .slice(0, 2)
          .map((s) => (
            <span key={s.id} className="hidden text-xs text-mute md:inline">
              {s.title}
            </span>
          ))}
      </div>
      {has && open && (
        <ul>
          {v.children.map((c, i) => (
            <Node key={`${c.id}${i}`} v={c} depth={depth + 1} onOpen={onOpen} />
          ))}
        </ul>
      )}
    </li>
  );
}

/** Expandable artifact tree: email -> links / attachments / QR codes, each with its own verdict. */
export function ChildTree({ verdict, onOpen }: { verdict: Verdict; onOpen: (v: Verdict) => void }) {
  const total = flattenVerdicts(verdict).length - 1;
  if (total === 0)
    return (
      <p className="text-sm text-mute">
        No child artifacts (links, attachments, QR codes or redirects) were extracted.
      </p>
    );
  return (
    <div>
      <p className="mb-2 text-xs text-mute">
        {total} child artifact{total === 1 ? "" : "s"}. Select one to inspect its own verdict.
      </p>
      {/* biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: WAI-ARIA tree pattern (ul/li with role tree/treeitem) */}
      <ul className="rounded-xl border border-line py-1" role="tree">
        <Node v={verdict} depth={0} onOpen={onOpen} />
      </ul>
    </div>
  );
}
