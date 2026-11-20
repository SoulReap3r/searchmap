"""Shared, rate-limited HTTP with a generic User-Agent.

PRIVACY: queries to NVD/EPSS/CISA/OSV carry only public product identifiers and
CVE ids — never the target IP, the operator's identity, or any scan artefact.
The User-Agent is a fixed generic string.
"""
from __future__ import annotations
import threading
import time
from typing import Optional

import requests

USER_AGENT = "sploitmap/3.0 (+vulnerability-research)"

_session: Optional[requests.Session] = None
_locks: dict[str, threading.Lock] = {}
_last: dict[str, float] = {}
_GLOBAL = threading.Lock()


def session() -> requests.Session:
    global _session
    if _session is None:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        _session = s
    return _session


def _throttle(host: str, min_interval: float) -> None:
    with _GLOBAL:
        lock = _locks.setdefault(host, threading.Lock())
    with lock:
        wait = min_interval - (time.time() - _last.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last[host] = time.time()


class HttpError(Exception):
    pass


def get_json(url: str, *, params: dict | None = None, headers: dict | None = None,
             min_interval: float = 0.0, timeout: int = 30, retries: int = 3) -> dict:
    host = requests.utils.urlparse(url).netloc
    last_exc: Exception | None = None
    for attempt in range(retries):
        if min_interval:
            _throttle(host, min_interval)
        try:
            r = session().get(url, params=params, headers=headers, timeout=timeout)
            if r.status_code == 429 or 500 <= r.status_code < 600:
                time.sleep(2 ** attempt + 1)
                last_exc = HttpError(f"{url} -> HTTP {r.status_code}")
                continue
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            last_exc = e
            time.sleep(1.5 * (attempt + 1))
    raise HttpError(f"GET {url} failed after {retries} tries: {last_exc}")


def post_json(url: str, *, json_body: dict, timeout: int = 30, retries: int = 2) -> dict:
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            r = session().post(url, json=json_body, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            last_exc = e
            time.sleep(1.0 * (attempt + 1))
    raise HttpError(f"POST {url} failed: {last_exc}")


def download(url: str, dest, *, timeout: int = 120) -> int:
    r = session().get(url, timeout=timeout, stream=True)
    r.raise_for_status()
    n = 0
    with open(dest, "wb") as fh:
        for chunk in r.iter_content(chunk_size=65536):
            fh.write(chunk)
            n += len(chunk)
    return n
