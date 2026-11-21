"""Tolerant software-version comparison and range satisfaction.

Product versions in the wild are not all PEP 440 / SemVer: OpenSSH ``7.2p2``,
Webmin ``1.890``, ``2.4.49``, ``9.0.16``, ``5.0.0-beta3``. We need an ordering
that is *correct for the cases CVE version-range matching actually turns on*:

* numeric dotted components compared numerically (``1.890`` > ``1.9``, not lexical)
* a trailing patch letter is newer than the bare release (``7.2p2`` > ``7.2``)
* a recognised pre-release marker is older than the release
  (``2.4.49rc1`` < ``2.4.49``)

This is the single most load-bearing primitive in the tool: an off-by-one here
turns a patched box into a false "vulnerable". It is exercised hard by
``tests/test_versioning.py``.
"""
from __future__ import annotations
import re
from functools import cmp_to_key
from typing import Optional

# pre-release markers rank *below* the final release at the same position
_PRERELEASE = {
    "dev": -6, "snapshot": -6, "nightly": -6,
    "alpha": -5, "a": -5,
    "beta": -4, "b": -4,
    "rc": -3, "pre": -3, "preview": -3, "c": -3,
    "milestone": -2, "m": -2,
}
_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


class InvalidVersion(ValueError):
    pass


def _tokens(v: str) -> list[str]:
    v = str(v).strip().lower()
    v = re.sub(r"^[vr]", "", v)            # strip a leading v/r (v2.4, r12)
    return _TOKEN.findall(v)


def _key(v: str) -> list[tuple]:
    """Comparable key. Each token -> (rank, numeric, text).

    rank 0 = pre-release marker (sorts low), 1 = numeric, 2 = other alpha
    (treated as a patch suffix, sorts high)."""
    out: list[tuple] = []
    for t in _tokens(v):
        if t.isdigit():
            out.append((1, int(t), ""))
        elif t in _PRERELEASE:
            out.append((0, _PRERELEASE[t], t))
        else:
            out.append((2, 0, t))
    return out


def compare(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for a <, ==, > b. Raises InvalidVersion if a side has
    no numeric component at all (e.g. a pure word), which the caller treats as
    'version unknown'."""
    ka, kb = _key(a), _key(b)
    if not any(k[0] == 1 for k in ka) or not any(k[0] == 1 for k in kb):
        raise InvalidVersion(f"not a comparable version: {a!r} vs {b!r}")
    for i in range(max(len(ka), len(kb))):
        xa = ka[i] if i < len(ka) else None
        xb = kb[i] if i < len(kb) else None
        if xa is None:                      # a exhausted: b longer
            return -1 if kb[i][0] >= 1 else 1   # extra numeric/patch => b bigger
        if xb is None:
            return 1 if ka[i][0] >= 1 else -1
        if xa != xb:
            return -1 if xa < xb else 1
    return 0


def eq(a: str, b: str) -> bool:
    try:
        return compare(a, b) == 0
    except InvalidVersion:
        return str(a).strip().lower() == str(b).strip().lower()


def satisfies(version: str,
              start_including: Optional[str] = None,
              start_excluding: Optional[str] = None,
              end_including: Optional[str] = None,
              end_excluding: Optional[str] = None) -> bool:
    """True if *version* falls inside the (possibly open) range described by the
    NVD cpeMatch bound fields. Any bound that fails to parse is treated as absent
    rather than silently excluding — conservative for a recon tool."""
    def _cmp(a, b):
        try:
            return compare(a, b)
        except InvalidVersion:
            return None
    checks = [
        (start_including, lambda c: c is not None and c < 0),
        (start_excluding, lambda c: c is not None and c <= 0),
        (end_including,   lambda c: c is not None and c > 0),
        (end_excluding,   lambda c: c is not None and c >= 0),
    ]
    for bound, fails in checks:
        if bound in (None, "", "*", "-"):
            continue
        c = _cmp(version, bound)
        if fails(c):
            return False
    return True


def has_any_bound(start_including=None, start_excluding=None,
                  end_including=None, end_excluding=None) -> bool:
    return any(b not in (None, "", "*", "-")
               for b in (start_including, start_excluding, end_including, end_excluding))


def sort_versions(versions: list[str], reverse: bool = False) -> list[str]:
    return sorted(versions, key=cmp_to_key(compare), reverse=reverse)


def looks_like_version(v: str) -> bool:
    """Whether a string is a CPE-matchable version rather than a build number.
    '2.4.49' / '14.0' / '13' are versions; a bare '14710' is a build number and
    must NOT be matched against NVD version ranges (it would compare as > 14.0)."""
    v = (v or "").strip()
    if not v:
        return False
    if re.fullmatch(r"\d{4,}", v):     # bare build number
        return False
    return bool(re.search(r"\d+\.\d+", v)) or bool(re.fullmatch(r"\d{1,3}", v))
