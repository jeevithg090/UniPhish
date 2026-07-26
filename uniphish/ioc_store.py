"""Append-only STIX object store backing the TAXII 2.1 feed.

The CT hunter appends STIX objects here; the TAXII endpoints read them. JSONL on
disk so the (long-running) hunter and the API server can be separate processes.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Dict, List

_PATH = os.environ.get("UNIPHISH_IOC_STORE", "data/iocs/objects.jsonl")
_LOCK = threading.Lock()


def append_objects(objects: List[Dict]) -> int:
    os.makedirs(os.path.dirname(_PATH) or ".", exist_ok=True)
    with _LOCK, open(_PATH, "a", encoding="utf-8") as fh:
        for o in objects:
            fh.write(json.dumps(o, ensure_ascii=False) + "\n")
    return len(objects)


def read_objects(limit: int = 1000, added_after: str | None = None) -> List[Dict]:
    if not os.path.exists(_PATH):
        return []
    out = []
    with open(_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if added_after and obj.get("created", "") <= added_after:
                continue
            out.append(obj)
    return out[-limit:]


def count() -> int:
    return len(read_objects(limit=10 ** 9))
