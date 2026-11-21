"""Service discovery: run nmap -sV, or ingest an existing -oX file.

XML is parsed with defusedxml (untrusted input: an nmap XML may come from
anywhere). CVE strings found in NSE script output (``--cve`` / vulners) are
harvested so they can be cross-referenced with the intelligence engine.
"""
from __future__ import annotations
import re
import shutil
import subprocess
from typing import Iterable

from defusedxml import ElementTree as ET

from ..core.models import Host, Service

TOP_PORTS = 1000
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def available() -> bool:
    return shutil.which("nmap") is not None


def run(targets: Iterable[str], xml_out: str, *, full: bool = False,
        cve: bool = False, timeout: int = 1800, extra: list[str] | None = None,
        ports: str | None = None) -> str:
    cmd = ["nmap", "--open", "-sV", "-T4", "-oX", xml_out]
    if ports:
        cmd += ["-p", ports]
    elif full:
        cmd += ["-p-"]
    else:
        cmd += ["--top-ports", str(TOP_PORTS)]
    if cve:
        scripts = "vuln,vulners"
        cmd += ["--script", scripts]
    cmd += (extra or [])
    cmd += list(targets)
    try:
        subprocess.run(cmd, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        pass
    return xml_out


def ingest(path: str) -> list[Host]:
    import sys
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        print(f"[!] scan file not found: {path}", file=sys.stderr)
        return []
    except ET.ParseError as e:
        print(f"[!] nmap XML at {path} is malformed ({e}).", file=sys.stderr)
        print("    Likely a concurrent scan writing the same file, or an interrupted scan. "
              "Re-run (each run now uses its own file), or pass a clean --xml.", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] could not read {path}: {e}", file=sys.stderr)
        return []
    hosts: list[Host] = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ip = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr", "")
                break
        if not ip:
            continue
        host = Host(ip=ip)
        hn = h.find("./hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name", "")
        osmatch = h.find("./os/osmatch")
        if osmatch is not None:
            host.os = osmatch.get("name", "")
        for p in h.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            s = p.find("service")
            svc = Service(
                port=int(p.get("portid", "0") or 0),
                proto=p.get("protocol", "tcp"),
                name=(s.get("name", "") if s is not None else ""),
                product=(s.get("product", "") if s is not None else ""),
                version=(s.get("version", "") if s is not None else ""),
                extrainfo=(s.get("extrainfo", "") if s is not None else ""),
                tunnel=(s.get("tunnel", "") if s is not None else ""),
                host_ip=ip,
            )
            if s is not None:
                for c in s.findall("cpe"):
                    if c.text:
                        svc.nmap_cpes.append(c.text)
            cves: set[str] = set()
            for scr in p.findall("script"):
                cves.update(CVE_RE.findall(scr.get("output", "") or ""))
            if cves:
                svc.notes.append("nmap NSE flagged: " + ", ".join(sorted(cves)))
            host.services.append(svc)
        hosts.append(host)
    return hosts
