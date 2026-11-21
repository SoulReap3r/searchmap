"""Version ordering + range satisfaction — the primitive every applicability
decision depends on. Cases are drawn from real OSCP-relevant software."""
import pytest
from smap.core.versioning import (compare, eq, satisfies, InvalidVersion, sort_versions,
                                  clean_version, looks_like_version)


@pytest.mark.parametrize("a,b,expected", [
    ("2.4.49", "2.4.50", -1),
    ("2.4.49", "2.4.49", 0),
    ("2.4.50", "2.4.49", 1),
    ("9.0.16", "9.0.30", -1),
    ("9.0.16", "9.0.9", 1),          # numeric, not lexical (16 > 9)
    ("1.890", "1.9", 1),             # Webmin: 1.890 > 1.9 numerically
    ("10.0", "9.9", 1),              # 10 > 9
    ("7.2p2", "7.2", 1),             # OpenSSH patch letter is newer
    ("7.2p2", "7.2p1", 1),
    ("7.2p1", "7.4p1", -1),
    ("2.4.49rc1", "2.4.49", -1),     # pre-release older than release
    ("2.4.49", "2.4.49beta", 1),
    ("5.0.0-beta3", "5.0.0", -1),
    ("5.0.0-beta3", "5.0.0-beta2", 1),
    ("1.0", "1.0.0", -1),            # strict: fewer components sorts lower
])
def test_compare(a, b, expected):
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


def test_uncomparable_raises():
    with pytest.raises(InvalidVersion):
        compare("unknown", "2.4.49")


def test_eq_fallback_on_unparseable():
    assert eq("latest", "latest")
    assert not eq("latest", "stable")


def test_sort():
    xs = ["2.4.49", "2.4.7", "2.4.50", "2.2.34", "2.4.49rc1"]
    assert sort_versions(xs) == ["2.2.34", "2.4.7", "2.4.49rc1", "2.4.49", "2.4.50"]


# ---- range satisfaction (mirrors NVD cpeMatch bound fields) ----

def test_range_both_bounds():
    # vulnerable: >= 2.4.0 and < 2.4.50  (Apache 2.4.49 path traversal window)
    assert satisfies("2.4.49", start_including="2.4.0", end_excluding="2.4.50")
    assert not satisfies("2.4.50", start_including="2.4.0", end_excluding="2.4.50")
    assert not satisfies("2.2.34", start_including="2.4.0", end_excluding="2.4.50")


def test_range_end_excluding_only():
    assert satisfies("7.6", end_excluding="7.7")       # OpenSSH user-enum < 7.7
    assert not satisfies("7.7", end_excluding="7.7")
    assert not satisfies("8.0", end_excluding="7.7")


def test_range_inclusive_bounds():
    assert satisfies("1.920", start_including="1.890", end_including="1.920")  # Webmin RCE window
    assert not satisfies("1.921", start_including="1.890", end_including="1.920")


def test_no_bounds_matches_anything():
    # unbounded wildcard: the caller must treat this as low-confidence, but the
    # range check itself is vacuously true
    assert satisfies("2.4.49")
    assert satisfies("0.0.1")


def test_bound_wildcards_ignored():
    assert satisfies("2.4.49", start_including="*", end_excluding="-")


def test_unparseable_bound_is_lenient():
    # a garbage bound should not silently drop a real finding
    assert satisfies("2.4.49", end_excluding="notaversion")


# ---- clean_version: nmap banners are noisy (regression: MariaDB got 0 CVEs) ----

@pytest.mark.parametrize("raw,expected", [
    ("10.3.24 or later", "10.3.24"),       # the bug: became a malformed CPE
    ("2.3.4 (Debian)", "2.3.4"),
    ("Apache/2.4.49", "2.4.49"),
    ("7.2p2", "7.2p2"),                    # keep patch suffix
    ("5.0.0-beta3", "5.0.0-beta3"),
    ("1.890", "1.890"),
    ("14710", ""),                         # bare build number is not a version
    ("", ""),
    ("unknown", ""),
])
def test_clean_version(raw, expected):
    assert clean_version(raw) == expected


def test_looks_like_version():
    assert looks_like_version("10.3.24")
    assert looks_like_version("14")        # major-only is a version
    assert not looks_like_version("14710") # bare build is not
    assert not looks_like_version("")
