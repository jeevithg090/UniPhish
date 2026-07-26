"""Real-time phishing threat-hunter on the Certificate Transparency firehose.

Every public TLS certificate is published to CT logs within seconds of issuance —
before the phishing site is live and long before blocklists list it. This streams
newly-issued domains (Certstream) through UniPhish + the technique classifier, and
emits STIX 2.1 IOCs (MITRE ATT&CK-mapped) for flagged domains into the TAXII feed.

    python -m scripts.ct_hunter --source certstream --threshold 75
    python -m scripts.ct_hunter --source sample        # offline demo, no network
"""

from __future__ import annotations

import argparse
import json
import time

from uniphish.brands import _host
from uniphish.infer import UniPhishScorer
from uniphish.ioc_store import append_objects
from uniphish.threatintel import detect, to_stix

CERTSTREAM_URL = "wss://certstream.calidog.io/"


def _process(scorer, domain, threshold, watchlist, stats):
    domain = domain.lstrip("*.").strip()
    if not domain or "." not in domain:
        return
    stats["seen"] += 1
    d = detect(scorer, f"https://{domain}/")
    flagged = d["risk"] >= threshold or (d["target_brand"] and d["risk"] >= 40)
    if watchlist and d["target_brand"] not in watchlist:
        flagged = False
    if not flagged:
        return
    append_objects(to_stix(d)["objects"])
    stats["alerts"] += 1
    tgt = f" -> impersonates {d['target_brand']}" if d["target_brand"] else ""
    tech = ",".join(d["techniques"]) or "-"
    print(f"🚨 risk={d['risk']:3d}  {domain}{tgt}  [{tech}]")


def run_sample(scorer, threshold, watchlist, limit):
    """Offline: synthesize a stream of newly-'issued' domains (lookalikes + benign)."""
    from data.synth import SynthConfig, synthesize
    rows = synthesize(SynthConfig(per_family=max(6, limit // 6)))
    domains = [_host(r["url"]) for r in rows][:limit]
    stats = {"seen": 0, "alerts": 0}
    print(f"[sample] streaming {len(domains)} freshly-'issued' domains\n")
    for dom in domains:
        _process(scorer, dom, threshold, watchlist, stats)
    print(f"\nprocessed {stats['seen']} domains, {stats['alerts']} IOCs emitted to the TAXII feed")


def run_certstream(scorer, threshold, watchlist, limit):
    import asyncio
    import websockets

    async def _run():
        stats = {"seen": 0, "alerts": 0}
        print(f"[certstream] connecting to {CERTSTREAM_URL} …")
        async with websockets.connect(CERTSTREAM_URL, ping_interval=20, max_size=None) as ws:
            async for msg in ws:
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                if data.get("message_type") != "certificate_update":
                    continue
                for dom in data["data"]["leaf_cert"].get("all_domains", []):
                    _process(scorer, dom, threshold, watchlist, stats)
                if limit and stats["seen"] >= limit:
                    break
        print(f"\nprocessed {stats['seen']} domains, {stats['alerts']} IOCs emitted")

    try:
        asyncio.run(_run())
    except Exception as e:
        print(f"[certstream] stream error ({e}); the public firehose can be flaky — "
              f"try again, or use --source sample for an offline demo.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["certstream", "sample"], default="sample")
    ap.add_argument("--threshold", type=int, default=75, help="risk (0-100) to alert on")
    ap.add_argument("--brands", default="", help="comma-separated brand watchlist (optional)")
    ap.add_argument("--limit", type=int, default=120, help="max domains to process")
    ap.add_argument("--model", default="artifacts/uniphish_adv.keras")
    args = ap.parse_args()

    scorer = UniPhishScorer(args.model)
    watchlist = set(b.strip() for b in args.brands.split(",") if b.strip())
    t0 = time.time()
    (run_certstream if args.source == "certstream" else run_sample)(
        scorer, args.threshold, watchlist, args.limit)
    print(f"elapsed {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
