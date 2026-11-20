"""NIST NVD 2.0 API client — CVE discovery by CPE, and product->CPE resolution.

Rate limits: 5 requests / 30s anonymous, 50 / 30s with an API key in the
``NVD_API_KEY`` env var. We cache aggressively so a re-scan is instant and the
offline profile works. We do NOT trust NVD's CPE match blindly: this module
only *fetches*; ``correlation.applicability`` decides whether a CVE truly
applies to the detected version.
"""
from __future__ import annotations
import os
from typing import Optional

from ..core import cache, http
from ..core.cpe import CPE, alias_lookup, normalize_product

API_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_CPE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_TTL = 24 * 3600
CPE_TTL = 30 * 24 * 3600


def _headers() -> dict:
    k = os.environ.get("NVD_API_KEY")
    return {"apiKey": k} if k else {}


def _interval() -> float:
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.2


def resolve_cpe(product: str, version: str = "", *, offline: bool = False) -> Optional[CPE]:
    """Map a product string to a canonical CPE (part,vendor,product). Alias map
    first (no network), then the NVD CPE dictionary (cached). In offline mode
    only the alias map and existing cache are consulted."""
    hit = alias_lookup(product)
    if hit:
        part, vendor, prod = hit
        return CPE(part, vendor, prod, version or "*")

    norm = normalize_product(product)
    if not norm:
        return None
    cached = cache.get("cperesolve", norm, CPE_TTL, offline=offline)
    if cached is None:
        if offline:
            return None
        try:
            data = http.get_json(API_CPE, params={"keywordSearch": norm, "resultsPerPage": 20},
                                 headers=_headers(), min_interval=_interval(), timeout=30)
            cached = [p["cpe"]["cpeName"] for p in data.get("products", [])]
            cache.put("cperesolve", norm, cached)
        except http.HttpError:
            return None
    # pick the best application-part CPE whose product token overlaps the query
    toks = set(norm.split())
    best = None
    for name in cached:
        try:
            c = CPE.parse(name)
        except ValueError:
            continue
        if c.part != "a":
            continue
        prodtoks = set(c.product.replace("_", " ").split())
        score = len(toks & prodtoks)
        if best is None or score > best[0]:
            best = (score, c)
    if best and best[0] > 0:
        return best[1].with_version(version or "*")
    return None


def fetch_cves(cpe: CPE, *, offline: bool = False, ttl: int = CVE_TTL,
               max_pages: int = 4) -> list[dict]:
    """Return raw NVD CVE objects whose configurations reference this
    product+version (NVD's own version-aware match — we re-verify downstream)."""
    vmatch = cpe.to_string()
    cached = cache.get("nvdcve", vmatch, ttl, offline=offline)
    if cached is not None:
        return cached
    if offline:
        return []
    results: list[dict] = []
    start = 0
    per = 2000
    for _ in range(max_pages):
        try:
            data = http.get_json(API_CVE, headers=_headers(), min_interval=_interval(),
                                 timeout=40,
                                 params={"virtualMatchString": vmatch,
                                         "resultsPerPage": per, "startIndex": start})
        except http.HttpError:
            break
        vulns = data.get("vulnerabilities", [])
        results.extend(v["cve"] for v in vulns)
        total = data.get("totalResults", 0)
        start += per
        if start >= total or not vulns:
            break
    cache.put("nvdcve", vmatch, results)
    return results


def fetch_one(cve_id: str, *, offline: bool = False) -> Optional[dict]:
    cached = cache.get("nvdone", cve_id, CVE_TTL, offline=offline)
    if cached is not None:
        return cached
    if offline:
        return None
    try:
        data = http.get_json(API_CVE, params={"cveId": cve_id}, headers=_headers(),
                             min_interval=_interval(), timeout=30)
    except http.HttpError:
        return None
    vulns = data.get("vulnerabilities", [])
    obj = vulns[0]["cve"] if vulns else None
    if obj:
        cache.put("nvdone", cve_id, obj)
    return obj


# ---- parsing helpers (pure, unit-testable) ----

def description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def metric(cve: dict) -> dict:
    """Best available CVSS metric as {score, severity, vector, version}."""
    m = cve.get("metrics", {})
    for fam in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if fam in m and m[fam]:
            e = m[fam][0]
            d = e.get("cvssData", {})
            return {
                "score": d.get("baseScore"),
                "severity": d.get("baseSeverity") or e.get("baseSeverity", ""),
                "vector": d.get("vectorString", ""),
                "version": d.get("version", fam.replace("cvssMetric", "")),
            }
    return {"score": None, "severity": "", "vector": "", "version": ""}


def references(cve: dict) -> list[dict]:
    return [{"url": r.get("url", ""), "tags": r.get("tags", [])}
            for r in cve.get("references", [])]


def cwes(cve: dict) -> list[str]:
    out = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def kev_inline(cve: dict) -> tuple[bool, str]:
    """NVD embeds CISA KEV status directly."""
    if cve.get("cisaExploitAdd"):
        return True, cve.get("cisaExploitAdd", "")
    return False, ""


def iter_cpe_matches(cve: dict):
    """Yield (cpeMatch dict, node_operator) for every cpeMatch in the CVE's
    configurations, so applicability can reason about version ranges and AND
    conditions."""
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            op = node.get("operator", "OR")
            for m in node.get("cpeMatch", []):
                yield m, op, node
