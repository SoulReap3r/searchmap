"""Vulnerability-intelligence orchestrator.

product+version  ->  CPE  ->  NVD CVEs  ->  applicability/confidence
             ->  + EPSS  + KEV  + Exploit-DB/PoC references
All source-traceable, all cached.
"""
from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from ..core.cpe import CPE
from ..core.models import Confidence, CveFinding, ExploitRef, Service
from ..correlation.applicability import assess
from . import cisa, epss, exploitdb, nvd

MAX_EXPLOIT_LOOKUPS = 25


def discover_cves(product: str, version: str = "", *, offline: bool = False,
                  include_not_applicable: bool = False, resolved: Optional[CPE] = None,
                  with_exploits: bool = True) -> tuple[list[CveFinding], Optional[CPE]]:
    from ..core.versioning import looks_like_version
    match_version = version if (version and looks_like_version(version)) else ""
    cpe = resolved or nvd.resolve_cpe(product, match_version, offline=offline)
    if cpe is None:
        return [], None
    if match_version and not cpe.has_version:
        cpe = cpe.with_version(match_version)

    raw = nvd.fetch_cves(cpe, offline=offline)
    findings: list[CveFinding] = []
    for cve in raw:
        f = assess(cve, cpe)
        if f is None:
            continue
        if f.confidence == Confidence.NOT_APPLICABLE and not include_not_applicable:
            continue
        findings.append(f)

    # EPSS (one batched call) + KEV feed cross-check
    emap = epss.scores([f.cve_id for f in findings], offline=offline)
    for f in findings:
        if f.cve_id in emap:
            f.epss = emap[f.cve_id]["epss"]
            f.epss_percentile = emap[f.cve_id]["percentile"]
        if not f.kev and cisa.is_kev(f.cve_id):
            f.kev = True
            rec = cisa.lookup(f.cve_id) or {}
            f.kev_date = rec.get("dateAdded", "")

    findings.sort(key=lambda f: f.priority)

    # exploit correlation for the most promising findings only (bounded subprocess)
    if with_exploits and exploitdb.available():
        top = findings[:MAX_EXPLOIT_LOOKUPS]
        with ThreadPoolExecutor(max_workers=8) as pool:
            for f, refs in zip(top, pool.map(exploitdb.by_cve, [f.cve_id for f in top])):
                _attach_exploits(f, refs)
    # always fold NVD exploit-tagged references in (free, no subprocess)
    for f in findings:
        for r in f.references:
            if r.is_exploit and not any(e.url == r.url for e in f.exploits):
                f.exploits.append(ExploitRef(title="PoC / exploit reference", source="NVD-ref",
                                             url=r.url, cves=[f.cve_id]))
    return findings, cpe


def _attach_exploits(f: CveFinding, refs: list[ExploitRef]) -> None:
    seen = {(e.source, e.edb_id, e.url) for e in f.exploits}
    for r in refs:
        key = (r.source, r.edb_id, r.url)
        if key not in seen:
            f.exploits.append(r)
            seen.add(key)


def enrich_service(svc: Service, *, offline: bool = False,
                   include_not_applicable: bool = False) -> None:
    """Populate svc.findings (CVEs, ranked) and svc.exploits (product-level
    Exploit-DB hits that may predate CVE tagging, e.g. vsftpd backdoor)."""
    if not svc.product:
        return
    resolved = None
    if svc.resolved_cpe:
        try:
            resolved = CPE.parse(svc.resolved_cpe)
        except ValueError:
            resolved = None
    findings, cpe = discover_cves(svc.product, svc.version, offline=offline,
                                  include_not_applicable=include_not_applicable,
                                  resolved=resolved)
    svc.findings = findings
    if cpe:
        svc.resolved_cpe = cpe.to_string()
        svc.cpe_source = "alias/NVD"
    # product-level exploit sweep (not every exploit carries a CVE). Pin to the
    # version only when it's a real version; for a build number, search the
    # product name so build-adjacent exploits (e.g. 14700 RCE) still surface.
    # Sort code-exec / auth-bypass / metasploit first so the foothold is visible.
    if exploitdb.available():
        from ..core.versioning import looks_like_version
        q = svc.banner if (svc.version and looks_like_version(svc.version)) else svc.product
        hot = re.compile(r"(?i)remote code|\brce\b|code execution|auth\w*[\s-]*bypass|unauth")
        exs = exploitdb.by_query(q)
        exs.sort(key=lambda e: (0 if hot.search(e.title) else 1, 0 if e.is_metasploit else 1))
        svc.exploits = exs[:10]
