import { LEVEL_STYLE, ACTION_LABEL, normLevel } from "../lib/risk";

/** Semicircular 0-100 risk gauge with threshold ticks at 50 and 85. */
export function Gauge({ score, level, action }: { score: number; level: string; action?: string }) {
  const lv = normLevel(level);
  const st = LEVEL_STYLE[lv];
  const s = Math.max(0, Math.min(100, score));
  const R = 80;
  const cx = 100;
  const cy = 100;
  const pt = (v: number, r = R) => {
    const a = Math.PI * (1 - v / 100);
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)] as const;
  };
  const arc = (a: number, b: number) => {
    const [x1, y1] = pt(a);
    const [x2, y2] = pt(b);
    return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  };
  const tick = (v: number) => {
    const [x1, y1] = pt(v, R - 12);
    const [x2, y2] = pt(v, R + 8);
    return <line key={v} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--color-mute)" strokeWidth="1.5" />;
  };
  return (
    <figure className="m-0 flex flex-col items-center" aria-label={`Risk score ${s} out of 100, ${st.label}`}>
      <svg viewBox="0 0 200 120" className="w-full max-w-[280px]" role="img" aria-hidden="true">
        <path d={arc(0, 50)} stroke="var(--color-ok)" strokeOpacity=".22" strokeWidth="14" fill="none" />
        <path d={arc(50, 85)} stroke="var(--color-warn)" strokeOpacity=".22" strokeWidth="14" fill="none" />
        <path d={arc(85, 100)} stroke="var(--color-bad)" strokeOpacity=".22" strokeWidth="14" fill="none" />
        {s > 0 && <path d={arc(0, Math.max(s, 0.6))} stroke={st.color} strokeWidth="14" strokeLinecap="round" fill="none" style={{ transition: "all .6s ease" }} />}
        {tick(50)}
        {tick(85)}
        <text x={cx} y="88" textAnchor="middle" fontSize="38" fontWeight="700" fill="var(--color-ink)">{s}</text>
        <text x={cx} y="106" textAnchor="middle" fontSize="10" fill="var(--color-mute)" letterSpacing="1.5">RISK / 100</text>
      </svg>
      <figcaption className="-mt-1 flex flex-col items-center gap-1">
        <span className={`rounded-full border px-3 py-0.5 text-sm font-semibold ${st.chip}`}>{st.label}</span>
        {action && <span className="text-xs text-mute">Action: <b className="text-ink">{ACTION_LABEL[action] ?? action}</b></span>}
      </figcaption>
    </figure>
  );
}
