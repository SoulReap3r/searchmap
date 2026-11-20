import json
from smap.core.models import (Confidence, CveFinding, ExploitRef, Host, Reference,
                              ScanResult, Service)
from smap.reporting import reports, serialize
from smap.recommendations import recommend
from smap.intelligence import exploitdb


def _sample() -> ScanResult:
    f = CveFinding(cve_id="CVE-2021-41773", description="Path traversal RCE",
                   cvss_score=9.8, cvss_severity="CRITICAL",
                   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                   epss=0.9999, kev=True, confidence=Confidence.CONFIRMED,
                   evidence=["exact version match (2.4.49)"], affected=["= 2.4.49"],
                   references=[Reference("https://nvd/x", ["Patch"], "NVD")],
                   exploits=[ExploitRef("Apache 2.4.49 Path Traversal", "Exploit-DB",
                                        "https://exploit-db.com/exploits/50383", "50383")])
    svc = Service(80, "tcp", "http", "Apache httpd", "2.4.49", host_ip="10.10.10.5",
                  resolved_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                  findings=[f])
    recommend.for_service(svc)
    return ScanResult(hosts=[Host("10.10.10.5", "t.local", services=[svc])],
                      profile="exam", tool_version="3.0.0", sources_used=["NVD"])


# ---- serialize round-trip (Confidence enum survives) ----

def test_json_roundtrip_preserves_enum():
    r = _sample()
    d = json.loads(serialize.to_json(r))
    assert d["hosts"][0]["services"][0]["findings"][0]["confidence"] == "CONFIRMED"
    rebuilt = serialize.from_dict(d)
    assert rebuilt.hosts[0].services[0].findings[0].confidence == Confidence.CONFIRMED
    assert rebuilt.hosts[0].services[0].findings[0].cvss_score == 9.8


# ---- report formats ----

def test_markdown_report_has_cve_and_cpe():
    md = reports.markdown_report(_sample())
    assert "CVE-2021-41773" in md and "cpe:2.3:a:apache:http_server" in md


def test_html_report_is_wellformed():
    h = reports.html_report(_sample())
    assert h.startswith("<!doctype html>") and h.rstrip().endswith("</html>")
    assert "CVE-2021-41773" in h and "KEV" in h


# ---- recommendations ----

def test_recommendation_prereqs_from_cvss_vector():
    r = _sample().hosts[0].services[0].recommendations[0]
    assert "network-reachable (remote)" in r.prerequisites
    assert "no authentication" in r.prerequisites
    assert "CISA KEV" in r.prerequisites


def test_recommendation_never_fabricates_run_command():
    r = _sample().hosts[0].services[0].recommendations[0]
    # research steps must only inspect/copy/point-to, never a synthesised run line
    for cmd in r.research:
        assert ("searchsploit -x" in cmd or "searchsploit -m" in cmd
                or cmd.startswith("nvd:") or "://" in cmd), cmd
    assert "read the PoC header" in r.manual_test[0]


# ---- exploitdb parsing (no subprocess) ----

def test_exploitdb_to_ref_extracts_cve_and_flags():
    e = {"Title": "Foo 1.0 - RCE (Metasploit)", "EDB-ID": "12345",
         "Path": "/x/12345.rb", "Codes": "CVE-2020-1234;OSVDB-1", "Verified": "1"}
    ref = exploitdb._to_ref(e)
    assert ref.edb_id == "12345" and ref.is_metasploit and ref.verified
    assert ref.cves == ["CVE-2020-1234"]
    assert ref.url == "https://www.exploit-db.com/exploits/12345"
