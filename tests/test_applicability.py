"""Applicability engine against REAL NVD fixtures (tests/fixtures/nvd/).

This is the false-positive-resistance suite the whole tool stands or falls on.
No network: fixtures are frozen NVD records.
"""
import json
import pathlib
import pytest

from smap.core.cpe import CPE
from smap.core.models import Confidence
from smap.correlation.applicability import assess

FIX = pathlib.Path(__file__).parent / "fixtures" / "nvd"


def load(cve_id):
    return json.loads((FIX / f"{cve_id}.json").read_text())


def apache(v="*"):
    return CPE("a", "apache", "http_server", v)


def openssh(v="*"):
    return CPE("a", "openbsd", "openssh", v)


def webmin(v="*"):
    return CPE("a", "webmin", "webmin", v)


# ---- exact version pin (Apache 2.4.49 path traversal) ----

def test_exact_match_confirmed():
    f = assess(load("CVE-2021-41773"), apache("2.4.49"))
    assert f.confidence == Confidence.CONFIRMED
    assert "exact version match" in " ".join(f.evidence)
    assert f.cvss_score == 9.8
    assert f.kev is True            # in CISA KEV (inline cisaExploitAdd)


def test_exact_match_patched_version_rejected():
    f = assess(load("CVE-2021-41773"), apache("2.4.51"))
    assert f.confidence == Confidence.NOT_APPLICABLE


def test_exact_match_unknown_version_is_possible():
    f = assess(load("CVE-2021-41773"), apache("*"))
    assert f.confidence == Confidence.POSSIBLE


# ---- the classic false positive (CVE-2007-4723 is a Ragnarok bug) ----

def test_wildcard_nonvulnerable_product_is_dropped():
    # Apache appears only as a non-vulnerable platform condition -> not our CVE
    f = assess(load("CVE-2007-4723"), apache("2.4.49"))
    assert f is None


# ---- single-bounded range (OpenSSH <= 7.7 user enumeration) ----

def test_range_in_window_probable():
    f = assess(load("CVE-2018-15473"), openssh("7.2p2"))
    assert f.confidence == Confidence.PROBABLE
    assert "within affected range" in " ".join(f.evidence)


def test_range_above_window_rejected():
    f = assess(load("CVE-2018-15473"), openssh("8.0"))
    assert f.confidence == Confidence.NOT_APPLICABLE


def test_range_unknown_version_possible():
    f = assess(load("CVE-2018-15473"), openssh("*"))
    assert f.confidence == Confidence.POSSIBLE


# ---- Webmin <= 1.920 RCE (numeric-aware: 1.890 < 1.920 < 1.921) ----

def test_webmin_in_window():
    assert assess(load("CVE-2019-15107"), webmin("1.890")).confidence == Confidence.PROBABLE


def test_webmin_above_window_rejected():
    assert assess(load("CVE-2019-15107"), webmin("1.921")).confidence == Confidence.NOT_APPLICABLE


# ---- wrong product entirely ----

def test_unrelated_product_returns_none():
    assert assess(load("CVE-2021-41773"), CPE("a", "nginx", "nginx", "1.20")) is None


def test_missing_evidence_populated():
    f = assess(load("CVE-2021-41773"), apache("*"))
    assert any("version" in m for m in f.missing_evidence)
