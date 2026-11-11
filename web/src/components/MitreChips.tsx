import type { MitreTechnique } from "../api/types";
import { Chip } from "./ui";

/** Only link out to the official MITRE sites; never to arbitrary server-supplied URLs. */
export function safeMitreUrl(u: string): string | null {
  try {
    const url = new URL(u);
    if (url.protocol !== "https:") return null;
    return url.hostname === "attack.mitre.org" || url.hostname === "atlas.mitre.org" ? url.toString() : null;
  } catch {
    return null;
  }
}

export function MitreChips({ techniques }: { techniques: MitreTechnique[] }) {
  if (!techniques.length) return <p className="text-sm text-mute">No ATT&amp;CK / ATLAS techniques mapped.</p>;
  return (
    <ul className="flex flex-wrap gap-2">
      {techniques.map((t) => {
        const href = safeMitreUrl(t.url);
        const cls = t.framework === "atlas" ? "border-accent/40 bg-accent/10 text-accent" : "border-info/40 bg-info/10 text-info";
        const body = (
          <>
            <b className="font-mono">{t.id}</b> {t.name}
            {t.tactic && <span className="opacity-70"> · {t.tactic}</span>}
          </>
        );
        return (
          <li key={t.id}>
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer" title={`${t.framework.toUpperCase()} ${t.id}`}>
                <Chip className={`${cls} hover:brightness-125`}>{body}</Chip>
              </a>
            ) : (
              <Chip className={cls}>{body}</Chip>
            )}
          </li>
        );
      })}
    </ul>
  );
}
