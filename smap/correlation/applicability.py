"""The confidence engine.

Given a raw NVD CVE and the detected (product, version), decide whether the CVE
*actually* applies, with evidence. This is the module that separates searchmap
from a keyword grep: it reads every ``cpeMatch`` for our product, checks the
detected version against the real version bounds, and refuses to call an
unbounded wildcard match a confirmed vulnerability.

Confidence:
  CONFIRMED  exact version pin == detected, or a fully-bounded range includes it
  PROBABLE   a single-bounded range includes it
  POSSIBLE   product matches but version is unbounded / unknown, or our product
             is only a secondary condition behind another vulnerable product
  UNKNOWN    no version to reason about and no bounds to lean on
  NOT_APPLICABLE  detected version is explicitly outside every range -> dropped
"""
from __future__ import annotations
from typing import Optional

from ..core.cpe import CPE
from ..core.models import Confidence, CveFinding, Reference
from ..core.versioning import eq, satisfies, has_any_bound, InvalidVersion, compare
from ..intelligence import nvd


def _bounds(m: dict) -> dict:
    return {
        "start_including": m.get("versionStartIncluding"),
        "start_excluding": m.get("versionStartExcluding"),
        "end_including": m.get("versionEndIncluding"),
        "end_excluding": m.get("versionEndExcluding"),
    }


def _range_text(crit: CPE, b: dict) -> str:
    if crit.has_version:
        return f"= {crit.version}"
    parts = []
    if b["start_including"]:
        parts.append(f">= {b['start_including']}")
    if b["start_excluding"]:
        parts.append(f"> {b['start_excluding']}")
    if b["end_including"]:
        parts.append(f"<= {b['end_including']}")
    if b["end_excluding"]:
        parts.append(f"< {b['end_excluding']}")
    return " and ".join(parts) if parts else "all versions (no bound)"


def assess(cve_raw: dict, detected: CPE, build_label: str = "") -> Optional[CveFinding]:
    """Return a CveFinding, or None if the CVE never references our product as a
    vulnerable component.

    ``build_label`` is the detected version when it's a build number that can't be
    compared to NVD's (marketing-version) ranges — used so the evidence says
    "detected build 14710, not comparable" rather than the false "version unknown"."""
    # honest phrase for the "can't compare" case
    unk = (f"detected build {build_label}, but NVD lists this product by marketing "
           f"version — build not directly comparable" if build_label else "target version unknown")
    version = detected.version if detected.has_version else None
    our: list[tuple[dict, CPE, str]] = []
    other_products: set[tuple[str, str]] = set()
    multi_condition = False

    for m, op, node in nvd.iter_cpe_matches(cve_raw):
        try:
            crit = CPE.parse(m["criteria"])
        except (ValueError, KeyError):
            continue
        if not m.get("vulnerable", False):
            continue
        if crit.same_product(detected):
            our.append((m, crit, op))
            if op == "AND" or len(node.get("cpeMatch", [])) > 1:
                multi_condition = True
        else:
            other_products.add((crit.vendor, crit.product))

    if not our:
        return None

    best_conf = Confidence.NOT_APPLICABLE
    evidence: list[str] = []
    affected: list[str] = []
    applicable_any = False

    for m, crit, op in our:
        b = _bounds(m)
        rng = _range_text(crit, b)
        affected.append(rng)

        if crit.has_version:                       # exact version pin
            if version is None:
                conf, ev = Confidence.POSSIBLE, f"CVE pins version {crit.version}; {unk}"
            elif eq(version, crit.version):
                conf, ev = Confidence.CONFIRMED, f"exact version match ({crit.version})"
            else:
                conf, ev = Confidence.NOT_APPLICABLE, f"affects only {crit.version}, target is {version}"
        elif has_any_bound(**b):                    # bounded range
            if version is None:
                conf, ev = Confidence.POSSIBLE, f"affects {rng}; {unk}"
            elif satisfies(version, **b):
                two_sided = (b["start_including"] or b["start_excluding"]) and \
                            (b["end_including"] or b["end_excluding"])
                conf = Confidence.CONFIRMED if two_sided else Confidence.PROBABLE
                ev = f"version {version} is within affected range {rng}"
            else:
                conf, ev = Confidence.NOT_APPLICABLE, f"version {version} is outside affected range {rng}"
        else:                                       # unbounded wildcard
            if other_products:
                conf = Confidence.POSSIBLE
                ex = sorted(other_products)[0]
                ev = (f"this product is listed with no version bound; the primary "
                      f"vulnerable component is {ex[0]}:{ex[1]} — likely not this service")
            elif version is None:
                conf, ev = Confidence.UNKNOWN, f"product matches, no version bound; {unk}"
            else:
                conf, ev = Confidence.POSSIBLE, ("NVD lists this product with no version bound "
                                                 "(nominally all versions) — verify against vendor advisory")

        if conf != Confidence.NOT_APPLICABLE:
            applicable_any = True
        if conf.rank < best_conf.rank:
            best_conf, evidence = conf, [ev]
        elif conf == best_conf and ev not in evidence:
            evidence.append(ev)

    if not applicable_any:
        best_conf = Confidence.NOT_APPLICABLE  # every match excluded the version

    f = CveFinding(cve_id=cve_raw.get("id", ""))
    f.description = nvd.description(cve_raw)
    met = nvd.metric(cve_raw)
    f.cvss_score, f.cvss_severity = met["score"], met["severity"]
    f.cvss_vector, f.cvss_version = met["vector"], met["version"]
    f.kev, f.kev_date = nvd.kev_inline(cve_raw)
    f.cwe = nvd.cwes(cve_raw)
    f.published = cve_raw.get("published", "")[:10]
    f.confidence = best_conf
    f.evidence = evidence
    f.affected = sorted(set(a for a in affected if a))
    f.references = [Reference(url=r["url"], tags=r["tags"], source="NVD")
                    for r in nvd.references(cve_raw)]

    # missing-evidence prompts (what the operator still has to confirm)
    if version is None:
        if build_label:
            f.missing_evidence.append(
                f"map build {build_label} to a marketing version to compare against NVD's range "
                f"(check the vendor advisory / changelog)")
        else:
            f.missing_evidence.append("exact service version (re-fingerprint or banner-grab)")
    if multi_condition:
        f.missing_evidence.append("additional config/platform condition in the NVD node (see configurations)")
    if best_conf in (Confidence.CONFIRMED, Confidence.PROBABLE):
        f.missing_evidence.append("vulnerable configuration actually enabled, and no backported vendor patch")
    return f
