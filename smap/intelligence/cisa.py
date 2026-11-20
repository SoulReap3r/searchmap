"""CISA Known Exploited Vulnerabilities catalogue.

NVD already embeds KEV status inline (``cisaExploitAdd``), which is what the
applicability engine reads. This module maintains a downloadable copy of the
full catalogue for ``update-db``, offline cross-checking, and the ``cve``
lookup command (ransomware-campaign flag, required-action text)."""
from __future__ import annotations
import json
from typing import Optional

from ..core import cache, http

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEED_FILE = "cisa_kev.json"


def update() -> dict:
    dest = cache.feed_path(FEED_FILE)
    n = http.download(FEED_URL, dest)
    data = json.loads(dest.read_text())
    return {"bytes": n, "count": data.get("count"), "version": data.get("catalogVersion")}


def _load() -> dict:
    dest = cache.feed_path(FEED_FILE)
    if not dest.exists():
        return {}
    try:
        return json.loads(dest.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


_INDEX: Optional[dict] = None


def _index() -> dict:
    global _INDEX
    if _INDEX is None:
        data = _load()
        _INDEX = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    return _INDEX


def lookup(cve_id: str) -> Optional[dict]:
    return _index().get(cve_id)


def is_kev(cve_id: str) -> bool:
    return cve_id in _index()


def have_feed() -> bool:
    return cache.feed_path(FEED_FILE).exists()
