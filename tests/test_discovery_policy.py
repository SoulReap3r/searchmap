import pathlib
from smap.discovery import nmap
from smap.protocols import registry
from smap.policies.exam import Policy
from smap.core.models import Service

FIX = pathlib.Path(__file__).parent / "fixtures" / "scan.xml"


# ---- nmap XML ingestion ----

def test_ingest_parses_services():
    hosts = nmap.ingest(str(FIX))
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.10.10.5" and h.hostname == "target.local"
    ports = {s.port: s for s in h.services}
    assert set(ports) == {21, 22, 80, 445, 3389}
    assert ports[21].product == "vsftpd" and ports[21].version == "2.3.4"
    assert ports[22].nmap_cpes == ["cpe:/a:openbsd:openssh:7.2p2"]


def test_ingest_harvests_nse_cves():
    hosts = nmap.ingest(str(FIX))
    rdp = next(s for s in hosts[0].services if s.port == 3389)
    assert any("CVE-2099-0001" in n for n in rdp.notes)


def test_ingest_bad_path_is_empty():
    assert nmap.ingest("/nonexistent/scan.xml") == []


# ---- protocol key mapping (nmap aliases + ports) ----

def test_protocol_key_aliases():
    assert registry.protocol_key(Service(445, name="microsoft-ds")) == "smb"
    assert registry.protocol_key(Service(139, name="netbios-ssn")) == "smb"
    assert registry.protocol_key(Service(3389, name="ms-wbt-server")) == "rdp"
    assert registry.protocol_key(Service(1433, name="ms-sql-s")) == "mssql"
    assert registry.protocol_key(Service(389, name="ldap")) == "ldap"


def test_protocol_key_by_port_fallback():
    assert registry.protocol_key(Service(22, name="")) == "ssh"
    assert registry.protocol_key(Service(8080, name="http-proxy")) == "http"


def test_build_steps_gates_credentialed():
    svc = Service(445, name="microsoft-ds", host_ip="10.0.0.1")
    no_creds = registry.build_steps(svc, has_creds=False)
    with_creds = registry.build_steps(svc, has_creds=True)
    assert len(with_creds) > len(no_creds)
    assert all(not s.needs_creds for s in no_creds)
    # commands are templated with the real IP
    assert any("10.0.0.1" in s.command for s in no_creds)


# ---- exam / lab policy isolation ----

def test_exam_blocks_automated_scanners():
    p = Policy("exam")
    assert not p.allows("nuclei")
    assert not p.allows("nikto")
    assert not p.allows("cred_spray")
    assert not p.allows("exploit_exec")


def test_exam_allows_research_and_enum():
    p = Policy("exam")
    for cap in ("nvd_lookup", "epss", "kev", "searchsploit", "active_fingerprint", "nmap_service_scan"):
        assert p.allows(cap), cap


def test_nmap_cve_scripts_flagged_in_exam():
    d = Policy("exam").check("nmap_cve_scripts")
    assert d.allowed and d.flagged


def test_lab_enables_scanners_but_never_autoexploit():
    p = Policy("lab")
    assert p.allows("nuclei") and p.allows("nikto")
    assert not p.allows("exploit_exec")
