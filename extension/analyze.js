// On-device brand-impersonation + reasons (JS port of uniphish/brands.py +
// reasons.py) so the popup explains verdicts with no server. Kept compact.
(function (global) {
  // confusable -> ASCII prototype (subset of the Python builtin map)
  const REV = {};
  const MAP = {
    a: "аαɑӑ", c: "сϲⅽ", e: "еҽ℮", i: "іїⅰӏ", j: "ј", l: "ӏⅼḷɩ", o: "оοօⲟ",
    p: "рρⲣ", s: "ѕƽ", x: "хχⅹ", y: "уүỳ", b: "вЬ", h: "һհ", k: "кӄ", m: "мɱ",
    n: "ոɳ", t: "тτ", u: "սц", d: "ԁⅾ", g: "ɡԍ", w: "ѡԝ",
  };
  for (const k in MAP) for (const ch of MAP[k]) REV[ch] = k;
  const LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b" };
  const BRANDS = ["paypal", "apple", "icloud", "google", "gmail", "youtube", "amazon",
    "microsoft", "outlook", "office365", "facebook", "instagram", "whatsapp", "netflix",
    "spotify", "linkedin", "coinbase", "binance", "metamask", "wellsfargo", "chase",
    "hsbc", "santander", "revolut", "sbi", "hdfc", "icici", "paytm", "phonepe", "alibaba",
    "aliexpress", "wechat", "alipay", "kakao", "naver", "dhl", "fedex", "steam", "discord",
    "telegram", "yahoo", "dropbox", "adobe"];
  const SUS_TLD = new Set(["top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link",
    "live", "online", "site", "zip", "mov", "work", "rest"]);
  const SHORT = new Set(["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "t.me", "cutt.ly"]);

  const host = (u) => u.replace(/^[a-z]+:\/\//i, "").split("/")[0].split("?")[0].split(":")[0];
  const norm = (s) => [...s.toLowerCase()].map((c) => LEET[REV[c] || c] || REV[c] || c).join("");
  function lev(a, b) {
    const dp = [...Array(b.length + 1).keys()];
    for (let i = 1; i <= a.length; i++) {
      let prev = dp[0]; dp[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const t = dp[j];
        dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] !== b[j - 1] ? 1 : 0));
        prev = t;
      }
    }
    return dp[b.length];
  }

  function brand(url) {
    const h = host(url), labels = h.split(".");
    const sld = labels.length >= 2 ? labels[labels.length - 2] : h;
    const nsld = norm(sld), nonascii = [...sld].some((c) => c.charCodeAt(0) > 127);
    for (const br of BRANDS) if (norm(br) === nsld) {
      if (sld === br) return null;
      return { brand: br, type: nonascii ? "homoglyph" : "typo", confidence: 0.9 };
    }
    for (const br of BRANDS) { const nb = norm(br); if (nb.length >= 5 && sld !== br && lev(nsld, nb) === 1) return { brand: br, type: "typo", confidence: 0.7 }; }
    for (const lbl of labels.slice(0, -2)) for (const br of BRANDS) if (norm(lbl) === norm(br) && norm(sld) !== norm(br)) return { brand: br, type: "subdomain", confidence: 0.85 };
    return null;
  }

  function reasons(url) {
    const h = host(url), out = [], add = (t, s) => out.push({ text: t, severity: s });
    const b = brand(url);
    if (b) { const v = { homoglyph: "disguises itself as", typo: "is a lookalike of", subdomain: "hides the real domain behind" }[b.type]; add(`Domain ${v} “${b.brand}”.`, "high"); }
    for (const ch of h) if (ch.charCodeAt(0) > 127 && REV[ch]) { add(`Uses “${ch}”, which looks like “${REV[ch]}” but is a different letter.`, "high"); break; }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) add("Uses a raw IP address instead of a domain.", "high");
    if (h.includes("xn--")) add("Punycode/IDN domain — often used for lookalikes.", "high");
    const tld = h.split(".").pop();
    if (SUS_TLD.has(tld)) add(`Uses the “.${tld}” TLD, common in phishing.`, "medium");
    if (SHORT.has(h)) add("Shortened link — the real destination is hidden.", "medium");
    if (Math.max(h.split(".").length - 2, 0) >= 3) add("Unusually deep subdomain structure.", "medium");
    return { reasons: out, brand: b };
  }

  const api = { brand, reasons, host, norm };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishAnalyze = api;
})(typeof self !== "undefined" ? self : this);
