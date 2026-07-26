"""UniPhish scan API (FastAPI) — the backend for the live demo.

Run:
    UNIPHISH_MODEL=artifacts/uniphish_adv.keras \
        uvicorn api.server:app --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health          -> {status, model, tflite}
    POST /scan            {url}        -> {url, prob, tier}
    POST /scan/batch      {urls: [...]}-> [{url, prob, tier}, ...]

Risk tiers use the paper's thresholds: block >= 0.9, warn >= 0.5, else safe.
"""

from __future__ import annotations

import os
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from uniphish import ioc_store
from uniphish.brands import _host
from uniphish.classify_attack import classify
from uniphish.enrich import decode_idn, domain_age_days, fused_risk, resolve_redirects
from uniphish.explain import saliency
from uniphish.infer import UniPhishScorer
from uniphish.reasons import analyze
from uniphish.threatintel import detect, to_stix

TAXII_MEDIA = "application/taxii+json;version=2.1"
COLLECTION_ID = "phishing-iocs"

MODEL_PATH = os.environ.get("UNIPHISH_MODEL", "artifacts/uniphish_adv.keras")

app = FastAPI(title="UniPhish", version="0.1.0",
              description="Unicode-native multilingual phishing URL detection")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_scorer: UniPhishScorer | None = None


def scorer() -> UniPhishScorer:
    global _scorer
    if _scorer is None:
        _scorer = UniPhishScorer(MODEL_PATH)
    return _scorer


class ScanRequest(BaseModel):
    url: str


class BatchRequest(BaseModel):
    urls: List[str]


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_PATH,
            "tflite": MODEL_PATH.endswith(".tflite"),
            "loaded": _scorer is not None}


@app.post("/scan")
def scan(req: ScanRequest):
    """Score a URL and enrich with brand-impersonation + plain-language reasons.

    Reasons/brand are pure string analysis (no extra model calls), so this stays cheap.
    """
    result = scorer().scan(req.url)
    result.update(analyze(req.url))     # adds {"reasons": [...], "brand": {...}|None}
    result["attack"] = classify(req.url)  # technique taxonomy + target brand
    return result


@app.post("/scan/batch")
def scan_batch(req: BatchRequest):
    return scorer().scan_batch(req.urls)


@app.post("/explain")
def explain(req: ScanRequest):
    """Full explanation: score + tier + brand + reasons + character-level saliency.

    Saliency uses occlusion (one forward pass per character), so this is heavier than
    /scan — intended for a single URL the user is inspecting.
    """
    s = scorer()
    result = s.scan(req.url)
    result.update(analyze(req.url))
    result["saliency"] = saliency(s, req.url)
    return result


@app.post("/enrich")
def enrich(req: ScanRequest):
    """Full hybrid analysis: ML score + IDN decode + redirect chain + domain age,
    fused into a single transparent risk score (0-100). Network calls are
    best-effort and SSRF-guarded; the endpoint never fails on them."""
    prob = scorer().scan(req.url)["prob"]
    idn = decode_idn(req.url)
    redirects = resolve_redirects(req.url)
    final = redirects["final_url"]
    age = domain_age_days(_host(final))
    risk = fused_risk(prob, final, young_domain_days=age)
    return {"url": req.url, "model_prob": prob, "idn": idn,
            "redirects": redirects, **risk}


# ---- Threat intelligence: STIX 2.1 + MITRE ATT&CK + TAXII 2.1 feed ---------- #
@app.post("/stix")
def stix(req: ScanRequest):
    """Return a STIX 2.1 bundle (Indicator + MITRE ATT&CK Attack-Patterns) for a URL."""
    return to_stix(detect(scorer(), req.url))


@app.get("/taxii2/")
def taxii_discovery():
    return {"title": "UniPhish TAXII Server",
            "description": "Phishing IOCs (STIX 2.1) with MITRE ATT&CK attribution",
            "default": "/taxii2/api/", "api_roots": ["/taxii2/api/"]}


@app.get("/taxii2/api/")
def taxii_root():
    return {"title": "UniPhish API root", "max_content_length": 10485760,
            "versions": [TAXII_MEDIA]}


@app.get("/taxii2/api/collections/")
def taxii_collections():
    return {"collections": [{
        "id": COLLECTION_ID, "title": "UniPhish phishing IOCs", "can_read": True,
        "can_write": False, "media_types": ["application/stix+json;version=2.1"]}]}


@app.get("/taxii2/api/collections/{collection_id}/objects/")
def taxii_objects(collection_id: str, limit: int = 1000, added_after: str = None):
    objs = ioc_store.read_objects(limit=limit, added_after=added_after) if collection_id == COLLECTION_ID else []
    return {"objects": objs, "more": False}
