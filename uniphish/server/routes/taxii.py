"""TAXII 2.1 read-only server exposing UniPhish's STIX indicators.

Implements the discovery, API-root, collections and objects resources from the OASIS
TAXII 2.1 spec, reading from the store's STIX objects (explicit objects plus indicators
synthesised from malicious IOCs). A single read-only collection, ``phishing-iocs``, is
served. Responses carry the ``application/taxii+json;version=2.1`` media type.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from uniphish.export.stix import STIX_MEDIA_TYPE, TAXII_MEDIA_TYPE
from uniphish.server.routes import get_store

router = APIRouter(tags=["taxii"])

COLLECTION_ID = "phishing-iocs"
_MAX_CONTENT_LENGTH = 10_485_760


def _taxii(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse(payload, media_type=TAXII_MEDIA_TYPE)


@router.get("/taxii2/")
def discovery(request: Request) -> JSONResponse:
    api_root = str(request.url_for("taxii_api_root"))
    return _taxii(
        {
            "title": "UniPhish TAXII Server",
            "description": "Phishing IOCs (STIX 2.1) with MITRE ATT&CK attribution.",
            "contact": "https://github.com/jeevithg090/UniPhish",
            "default": api_root,
            "api_roots": [api_root],
        }
    )


@router.get("/taxii2/api/", name="taxii_api_root")
def api_root() -> JSONResponse:
    return _taxii(
        {
            "title": "UniPhish API root",
            "description": "Read-only phishing threat-intel collections.",
            "versions": [TAXII_MEDIA_TYPE],
            "max_content_length": _MAX_CONTENT_LENGTH,
        }
    )


@router.get("/taxii2/api/collections/")
def collections() -> JSONResponse:
    return _taxii({"collections": [_collection_meta()]})


@router.get("/taxii2/api/collections/{collection_id}/")
def collection(collection_id: str) -> JSONResponse:
    if collection_id != COLLECTION_ID:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown collection.")
    return _taxii(_collection_meta())


@router.get("/taxii2/api/collections/{collection_id}/objects/")
def objects(
    collection_id: str,
    store=Depends(get_store),
    limit: int = Query(1000, ge=1, le=10000),
    added_after: str | None = Query(None),
) -> JSONResponse:
    """Return the collection's STIX objects as a TAXII envelope (oldest-first paging)."""
    if collection_id != COLLECTION_ID:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown collection.")
    try:
        objs = store.stix_objects(limit=limit, added_after=added_after)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Invalid 'added_after' timestamp."
        ) from exc
    envelope: dict[str, Any] = {"more": False, "objects": objs}
    return JSONResponse(envelope, media_type=STIX_MEDIA_TYPE)


def _collection_meta() -> dict[str, Any]:
    return {
        "id": COLLECTION_ID,
        "title": "UniPhish phishing IOCs",
        "description": "STIX 2.1 indicators for detected phishing infrastructure.",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_MEDIA_TYPE],
    }
