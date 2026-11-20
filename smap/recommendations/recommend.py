"""Turn a CveFinding into an inspectable, operator-driven recommendation.

Hard rule (from the brief): never fabricate a run command from a filename or
assume a PoC takes an IP as argv[1]. We recommend *inspecting* the exploit
(`searchsploit -x`), mirroring it (`-m`), and reading its documented usage
before anything is executed. The tool only ever suggests.
"""
from __future__ import annotations
from ..core.models import CveFinding, Recommendation, Service

_AV = {"N": "network-reachable (remote)", "A": "adjacent network", "L": "local access", "P": "physical"}
_PR = {"N": "no authentication", "L": "a low-privileged account", "H": "an administrative account"}


def _prerequisites(f: CveFinding) -> str:
    bits = []
    vec = f.cvss_vector or ""
    for token, table in (("AV:", _AV), ("PR:", _PR)):
        for code, text in table.items():
            if f"{token}{code}" in vec:
                bits.append(text)
                break
    if "UI:R" in vec:
        bits.append("user interaction")
    if f.kev:
        bits.append("actively exploited in the wild (CISA KEV)")
    return "; ".join(bits) if bits else "see CVSS vector / advisory"


def for_finding(f: CveFinding, svc: Service) -> Recommendation:
    title = f"{f.cve_id}: {f.description[:90]}" if f.description else f.cve_id
    rec = Recommendation(title=title)
    rec.rationale = (f"confidence {f.confidence.value}" +
                     (f", CVSS {f.cvss_score}" if f.cvss_score else "") +
                     (f", EPSS {f.epss:.0%}" if f.epss is not None else "") +
                     (", CISA KEV" if f.kev else ""))
    rec.prerequisites = _prerequisites(f)

    # research commands — all inspection, nothing executed
    rec.research.append(f"nvd: {f.nvd_url}")
    for r in f.references:
        tag = "/".join(r.tags) if r.tags else "ref"
        if any(t in r.tags for t in ("Patch", "Vendor Advisory", "Mitigation", "Exploit", "Third Party Advisory")):
            rec.research.append(f"{tag}: {r.url}")
    for e in f.exploits[:4]:
        if e.edb_id:
            rec.research.append(f"inspect PoC: searchsploit -x {e.edb_id}   # {e.title[:50]}")
            rec.research.append(f"copy PoC:    searchsploit -m {e.edb_id}")
        elif e.url:
            rec.research.append(f"PoC ({e.source}): {e.url}")

    # manual testing — operator reads usage first, then runs it themselves
    rec.manual_test = [
        "read the PoC header / usage before running it (do not assume argv order)",
        f"confirm the service really is {svc.product} {svc.version}".rstrip(),
        "reproduce the advisory's trigger condition manually (curl/nc) where possible",
    ]
    rec.validation = (
        "treat as present only if the detected version AND the vulnerable "
        "configuration both match the advisory, or the PoC's own non-destructive "
        "check succeeds. " +
        ("Beware distro backports: a patched build can keep the old version string."
         if f.confidence.value in ("CONFIRMED", "PROBABLE") else
         "Version is uncertain — re-fingerprint before spending time here.")
    )
    return rec


def for_service(svc: Service, *, top: int = 6) -> None:
    svc.recommendations = [for_finding(f, svc) for f in svc.findings[:top]]
