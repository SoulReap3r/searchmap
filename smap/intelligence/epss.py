"""FIRST EPSS — exploit-prediction scores (probability a CVE is exploited in the
wild in the next 30 days). Batched by CVE id, cached per-CVE for a day."""
from __future__ import annotations
from ..core import cache, http

API = "https://api.first.org/data/v1/epss"
TTL = 24 * 3600


def scores(cve_ids: list[str], *, offline: bool = False) -> dict[str, dict]:
    """Return {cve_id: {"epss": float, "percentile": float}} for as many as we
    can. Missing / offline ones are simply absent."""
    out: dict[str, dict] = {}
    need: list[str] = []
    for c in cve_ids:
        hit = cache.get("epss", c, TTL, offline=offline)
        if hit is not None:
            out[c] = hit
        else:
            need.append(c)
    if need and not offline:
        for i in range(0, len(need), 90):
            chunk = need[i:i + 90]
            try:
                data = http.get_json(API, params={"cve": ",".join(chunk)},
                                     min_interval=0.3, timeout=20)
            except http.HttpError:
                continue
            for row in data.get("data", []):
                rec = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
                out[row["cve"]] = rec
                cache.put("epss", row["cve"], rec)
    return out
