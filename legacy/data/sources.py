"""Real public URL feeds (best-effort, network required).

Blended with the synthetic multilingual data to (a) make the task realistic and
(b) supply diverse real benign domains so the benign class doesn't collapse under
deduplication. All feeds are open / no-auth. Every fetcher returns a DataFrame
(columns: url, label, script_family, technique, source) or None on any failure,
so the pipeline degrades gracefully to pure-synthetic when offline.

Sources:
  - OpenPhish community feed  (real phishing)         label=1
  - URLhaus online CSV        (real malicious URLs)   label=1
  - Cisco Umbrella top-1M     (real popular domains)  label=0
"""

from __future__ import annotations

import csv
import io
import zipfile
from typing import Callable, Optional

import pandas as pd

TIMEOUT = 60
COLS = ["url", "label", "script_family", "technique", "source"]


def _script_family(url: str) -> str:
    """Assign a script family by the dominant non-ASCII Unicode block in the URL."""
    counts = {"arabic": 0, "cjk": 0, "devanagari": 0, "hangul": 0, "other": 0}
    for ch in url:
        o = ord(ch)
        if o < 128:
            continue
        if 0x0600 <= o <= 0x06FF:
            counts["arabic"] += 1
        elif 0x0900 <= o <= 0x097F:
            counts["devanagari"] += 1
        elif 0xAC00 <= o <= 0xD7A3 or 0x1100 <= o <= 0x11FF:
            counts["hangul"] += 1
        elif 0x4E00 <= o <= 0x9FFF or 0x3000 <= o <= 0x30FF:
            counts["cjk"] += 1
        else:
            counts["other"] += 1
    return "latin_nonenglish" if sum(counts.values()) == 0 else max(counts, key=counts.get)


def _frame(urls, label, technique, source) -> pd.DataFrame:
    urls = [u for u in urls if isinstance(u, str) and u.startswith("http")]
    return pd.DataFrame({
        "url": urls,
        "label": label,
        "script_family": [_script_family(u) for u in urls],
        "technique": technique,
        "source": source,
    })[COLS]


def fetch_openphish(limit: int = 10000) -> Optional[pd.DataFrame]:
    try:
        import requests
        r = requests.get("https://openphish.com/feed.txt", timeout=TIMEOUT)
        r.raise_for_status()
        urls = [u.strip() for u in r.text.splitlines() if u.strip()]
        return _frame(urls[:limit], 1, "real_phish", "openphish")
    except Exception:
        return None


def fetch_urlhaus(limit: int = 10000) -> Optional[pd.DataFrame]:
    try:
        import requests
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_online/", timeout=TIMEOUT)
        r.raise_for_status()
        lines = [ln for ln in r.text.splitlines() if ln and not ln.startswith("#")]
        urls = [row[2] for row in csv.reader(lines) if len(row) >= 3]
        return _frame(urls[:limit], 1, "real_malicious", "urlhaus")
    except Exception:
        return None


def fetch_umbrella_benign(limit: int = 20000) -> Optional[pd.DataFrame]:
    try:
        import requests
        url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        text = zf.read(zf.namelist()[0]).decode("utf-8", errors="ignore")
        domains = [ln.split(",")[-1].strip() for ln in text.splitlines() if "," in ln]
        urls = [f"https://{d}/" for d in domains[:limit] if d]
        return _frame(urls, 0, "benign", "umbrella")
    except Exception:
        return None


def fetch_real(seed: int = 42, n_phish: int = 12000, n_benign: int = 12000) -> Optional[pd.DataFrame]:
    """Fetch and balance real phishing + benign feeds. None if all sources fail."""
    phish_frames = [f(n_phish) for f in (fetch_openphish, fetch_urlhaus)]
    phish = [df for df in phish_frames if df is not None and len(df)]
    benign = fetch_umbrella_benign(n_benign)

    frames = list(phish)
    if benign is not None and len(benign):
        frames.append(benign)
    if not frames:
        return None

    out = pd.concat(frames, ignore_index=True).drop_duplicates("url")
    ph = out[out.label == 1]
    be = out[out.label == 0]
    ph = ph.sample(min(len(ph), n_phish), random_state=seed) if len(ph) else ph
    be = be.sample(min(len(be), n_benign), random_state=seed) if len(be) else be
    result = pd.concat([ph, be], ignore_index=True)
    print(f"[sources] real feeds: {len(ph)} phishing + {len(be)} benign")
    return result
