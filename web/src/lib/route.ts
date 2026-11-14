export type Tab = "analyze" | "feed" | "history" | "catalog";
export type Route = Tab | "notfound";

export const TABS: { id: Tab; label: string; short: string }[] = [
  { id: "analyze", label: "Analyze", short: "Analyze" },
  { id: "feed", label: "Live feed", short: "Feed" },
  { id: "history", label: "Verdicts & stats", short: "History" },
  { id: "catalog", label: "Catalog", short: "Catalog" },
];

/** Map `location.hash` to a view. An empty hash is the Analyze view; anything unknown is a 404. */
export function routeFromHash(hash: string): Route {
  const h = hash.replace(/^#\/?/, "").replace(/\/+$/, "");
  if (!h) return "analyze";
  return TABS.some((t) => t.id === h) ? (h as Tab) : "notfound";
}

/** Document title for a route. */
export function routeTitle(route: Route): string {
  const label = TABS.find((t) => t.id === route)?.label ?? "Page not found";
  return `${label} · UniPhish 2 SOC Console`;
}
