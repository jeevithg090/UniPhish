import { useMemo, useState } from "react";
import type { Verdict } from "../api/types";
import { defang } from "../lib/defang";
import { collectIndicators } from "../lib/risk";
import { Chip, CopyButton, Empty } from "./ui";

export function Indicators({ verdict }: { verdict: Verdict }) {
  const [defanged, setDefanged] = useState(true);
  const list = useMemo(() => collectIndicators(verdict), [verdict]);
  const shown = (type: string, value: string) => (defanged ? defang(value, type) : value);
  if (list.length === 0) return <Empty>No indicators were extracted.</Empty>;
  const all = list.map((i) => shown(i.type, i.value)).join("\n");
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <label className="flex cursor-pointer items-center gap-2 text-xs text-mute">
          <input
            type="checkbox"
            checked={defanged}
            onChange={(e) => setDefanged(e.target.checked)}
            className="accent-accent"
          />
          Defang (safe to paste into tickets and chat)
        </label>
        <CopyButton text={all} label={`Copy all (${list.length})`} />
      </div>
      <ul className="divide-y divide-line rounded-xl border border-line">
        {list.map((i) => (
          <li
            key={`${i.type}:${i.value}`}
            className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm"
          >
            <Chip className="w-20 justify-center border-line bg-panel2 font-mono text-mute">
              {i.type}
            </Chip>
            <code className="min-w-0 flex-1 break-all text-ink/90">{shown(i.type, i.value)}</code>
            {i.role && <Chip className="border-line text-mute">{i.role}</Chip>}
            {i.malicious && <Chip className="border-bad/40 bg-bad/10 text-bad">malicious</Chip>}
            <CopyButton text={shown(i.type, i.value)} />
          </li>
        ))}
      </ul>
    </div>
  );
}
