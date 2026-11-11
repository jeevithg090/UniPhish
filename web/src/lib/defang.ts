// Defang / refang indicator values so they can be pasted into tickets and chat
// without becoming clickable. Pure and unit tested.

const URLISH = new Set(["url", "domain", "email", "ipv4", "ipv6"]);

export function defang(value: string, type = "url"): string {
  if (!URLISH.has(type)) return value;
  let v = value;
  v = v.replace(/^http(s?):\/\//i, (_m, s: string) => `hxxp${s}://`);
  v = v.replace(/^ftp:\/\//i, "fxp://");
  v = v.replace(/@/g, "[@]");
  // Defang dots in the host portion; for URLs, only up to the first path/query char.
  const m = /^([a-z0-9+.-]+:\/\/)?([^/?#]*)(.*)$/i.exec(v);
  if (!m) return v.replace(/\./g, "[.]");
  const [, scheme = "", host, rest] = m;
  return `${scheme}${host.replace(/\./g, "[.]")}${rest}`;
}

export function refang(value: string): string {
  return value
    .replace(/^hxxp(s?):\/\//i, (_m, s: string) => `http${s}://`)
    .replace(/^fxp:\/\//i, "ftp://")
    .replace(/\[(\.|@|:)\]/g, "$1")
    .replace(/\(\.\)/g, ".");
}
