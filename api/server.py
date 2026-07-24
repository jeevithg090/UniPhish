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

from uniphish.infer import UniPhishScorer

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
    return scorer().scan(req.url)


@app.post("/scan/batch")
def scan_batch(req: BatchRequest):
    return scorer().scan_batch(req.urls)
