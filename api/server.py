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

from uniphish.brands import _host
from uniphish.enrich import decode_idn, domain_age_days, fused_risk, resolve_redirects
from uniphish.explain import saliency
from uniphish.infer import UniPhishScorer
from uniphish.reasons import analyze

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
