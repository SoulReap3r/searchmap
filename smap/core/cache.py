"""On-disk JSON cache with TTL. This is what makes the offline workflow real:
once a CPE's CVEs / an EPSS score / the KEV feed have been fetched, they are
served from here until they expire, and `--offline` serves them past expiry."""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

HOME = Path(os.environ.get("SPLOITMAP_HOME", Path.home() / ".local/share/sploitmap"))
CACHE_DIR = HOME / "cache"
FEED_DIR = HOME / "feeds"
for _d in (CACHE_DIR, FEED_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _key(namespace: str, ident: str) -> Path:
    h = hashlib.sha1(ident.encode("utf-8", "replace")).hexdigest()[:20]
    return CACHE_DIR / f"{namespace}_{h}.json"


def get(namespace: str, ident: str, ttl: int, *, offline: bool = False) -> Optional[Any]:
    p = _key(namespace, ident)
    if not p.exists():
        return None
    try:
        blob = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    age = time.time() - blob.get("_stored", 0)
    if not offline and age > ttl:
        return None
    return blob.get("data")


def put(namespace: str, ident: str, data: Any) -> None:
    p = _key(namespace, ident)
    try:
        p.write_text(json.dumps({"_stored": time.time(), "_id": ident, "data": data}))
    except OSError:
        pass


def feed_path(name: str) -> Path:
    return FEED_DIR / name


def stats() -> dict:
    files = list(CACHE_DIR.glob("*.json"))
    size = sum(f.stat().st_size for f in files) if files else 0
    feeds = {f.name: f.stat().st_mtime for f in FEED_DIR.glob("*")}
    return {"entries": len(files), "bytes": size, "dir": str(CACHE_DIR), "feeds": feeds}
