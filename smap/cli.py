"""searchmap command-line interface.

    searchmap <target>                 scan (exam profile, default)
    searchmap <target> --cve           + nmap vuln NSE
    searchmap <target> --deep-enum     + credentialed enum suggestions
    searchmap <target> --profile lab   enable lab-only engines
    searchmap --xml scan.xml           ingest an existing nmap -oX
    searchmap cve CVE-2021-41773       look up one CVE
    searchmap research "Apache 2.4.49" ad-hoc product research
    searchmap doctor                   dependency / connectivity / policy check
    searchmap update-db                refresh CISA KEV feed + caches
    searchmap report scan.json --format html
"""
from __future__ import annotations
import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .core.models import Host, ScanResult, Service
from .policies.exam import Policy


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def split_host_port(target: str) -> tuple[str, str | None]:
    """Accept 'host:port' (e.g. 192.168.1.5:8443) and split it. Leaves CIDRs,
    bare hosts, and anything with multiple colons (IPv6) untouched."""
    if ":" in target and "/" not in target and target.count(":") == 1:
        host, _, port = target.rpartition(":")
        if host and port.isdigit() and 0 < int(port) <= 65535:
            return host, port
    return target, None


# ---------------------------------------------------------------- scan --------
def cmd_scan(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="searchmap", description="scan + map a target")
    p.add_argument("target", nargs="?", help="IP / host / CIDR, or a file of them")
    p.add_argument("--xml", metavar="FILE", help="ingest an existing nmap -oX file")
    p.add_argument("--full", action="store_true", help="scan all 65535 ports")
    p.add_argument("-p", "--ports", metavar="PORTS", help="scan only these ports (e.g. 8443 or 80,443)")
    p.add_argument("--cve", action="store_true", help="add nmap vuln/vulners NSE")
    p.add_argument("--deep-enum", action="store_true", help="include credentialed enum steps")
    p.add_argument("--no-fp", action="store_true", help="skip active web fingerprinting")
    p.add_argument("--profile", choices=["exam", "lab"], default="exam")
    p.add_argument("--offline", action="store_true", help="use only cached intel (no network)")
    p.add_argument("--all", dest="show_all", action="store_true", help="include NOT_APPLICABLE CVEs")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="deep results: show medium/low severity and low-confidence IDs too "
                        "(default hides them to cut exam noise)")
    p.add_argument("--format", choices=["terminal", "json", "markdown", "html"], default="terminal")
    p.add_argument("-o", "--output", metavar="FILE", help="write report to a file")
    p.add_argument("-w", "--workers", type=int, default=8)
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    if not a.target and not a.xml:
        p.error("a target or --xml is required")

    from .discovery import nmap
    from .fingerprint import web
    from .intelligence import engine
    from .recommendations import recommend
    from .reporting import reports, terminal

    policy = Policy(a.profile)
    result = ScanResult(profile=a.profile, started=_now(), tool_version=__version__)
    sources: list[str] = []

    # stage 1 — discovery
    if a.xml:
        print(f"[*] ingesting {a.xml}", file=sys.stderr)
        result.hosts = nmap.ingest(a.xml)
        sources.append("nmap-xml")
    else:
        ports = a.ports
        targets = [a.target]
        if os.path.isfile(a.target):
            targets = [l.strip() for l in open(a.target) if l.strip() and not l.startswith("#")]
        else:
            host, port = split_host_port(a.target)
            if port:
                targets = [host]
                ports = ports or port
                print(f"[i] target {a.target} -> host {host}, port {port}", file=sys.stderr)
        if not nmap.available():
            print("[!] nmap not found; use --xml to ingest a scan", file=sys.stderr)
            return 2
        use_cve = a.cve and policy.allows("nmap_cve_scripts")
        if a.cve and not use_cve:
            print("[!] --cve blocked by profile policy; skipping NSE", file=sys.stderr)
        elif use_cve and policy.check("nmap_cve_scripts").flagged:
            print("[!] nmap vuln NSE: permitted but intrusive — confirm it's exam-legal for you", file=sys.stderr)
        import tempfile
        fd, xml = tempfile.mkstemp(prefix="searchmap_", suffix=".xml")
        os.close(fd)   # unique per run: concurrent scans never clobber each other
        scope = f"port {ports}" if ports else ("all ports" if a.full else f"top {nmap.TOP_PORTS}")
        print(f"[*] nmap -sV{' + NSE vuln' if use_cve else ''} ({scope}) on {len(targets)} target(s)", file=sys.stderr)
        nmap.run(targets, xml, full=a.full, cve=use_cve, ports=ports)
        result.hosts = nmap.ingest(xml)
        print(f"[i] nmap XML: {xml}", file=sys.stderr)
        sources.append("nmap")

    services = result.all_services
    print(f"[*] {len(result.hosts)} host(s), {len(services)} open service(s)", file=sys.stderr)

    # stage 2 — active fingerprint
    if not a.no_fp and policy.allows("active_fingerprint"):
        webs = [s for s in services if web.is_web(s)]
        if webs:
            print(f"[*] fingerprinting {len(webs)} web service(s)", file=sys.stderr)
            with ThreadPoolExecutor(max_workers=a.workers) as pool:
                list(pool.map(web.fingerprint, webs))
            sources.append("active-fingerprint")

    # stage 3 — intelligence
    print(f"[*] correlating CVEs/exploits via NVD+EPSS+KEV+Exploit-DB"
          f"{' (offline cache)' if a.offline else ''}", file=sys.stderr)
    from .protocols import registry
    for svc in services:
        engine.enrich_service(svc, offline=a.offline, include_not_applicable=a.show_all)
        recommend.for_service(svc)
        svc.enum_steps = registry.build_steps(svc, has_creds=a.deep_enum,
                                              lab=(a.profile == "lab"))
    for src in ("NVD", "EPSS", "CISA-KEV", "Exploit-DB"):
        sources.append(src)
    result.sources_used = list(dict.fromkeys(sources))
    result.finished = _now()

    # stage 4 — report
    out = _render(result, policy, a, terminal, reports)
    if a.output and out is not None:
        open(a.output, "w").write(out)
        print(f"[+] report written to {a.output}", file=sys.stderr)
    return 0


def _render(result, policy, a, terminal, reports):
    if a.format == "terminal":
        terminal.render(result, policy, show_all=a.show_all, no_color=a.no_color,
                        verbose=a.verbose)
        return None
    out = {"json": reports.json_report, "markdown": reports.markdown_report,
           "html": reports.html_report}[a.format](result)
    if not a.output:
        print(out)
    return out


# ---------------------------------------------------------------- cve ---------
def cmd_cve(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="searchmap cve", description="look up a single CVE")
    p.add_argument("cve_id")
    p.add_argument("--offline", action="store_true")
    a = p.parse_args(argv)
    from .intelligence import nvd, epss, cisa, exploitdb
    cve = nvd.fetch_one(a.cve_id.upper(), offline=a.offline)
    if not cve:
        print(f"[!] {a.cve_id}: not found (or offline with no cache)")
        return 1
    met = nvd.metric(cve)
    kev, kdate = nvd.kev_inline(cve)
    if not kev and cisa.is_kev(a.cve_id.upper()):
        kev = True
    e = epss.scores([a.cve_id.upper()], offline=a.offline).get(a.cve_id.upper(), {})
    print(f"\n{a.cve_id.upper()}   {cve.get('published','')[:10]}")
    print("=" * 66)
    print(nvd.description(cve))
    print(f"\nCVSS: {met['score']} {met['severity']} ({met['version']})  {met['vector']}")
    if e:
        print(f"EPSS: {e['epss']:.1%} (percentile {e['percentile']:.1%})")
    print(f"CISA KEV: {'YES — actively exploited' + (' ('+kdate+')' if kdate else '') if kev else 'no'}")
    if nvd.cwes(cve):
        print(f"CWE: {', '.join(nvd.cwes(cve))}")
    print("\nAffected (configurations):")
    seen = set()
    for m, op, node in nvd.iter_cpe_matches(cve):
        if not m.get("vulnerable"):
            continue
        b = {k: v for k, v in m.items() if "version" in k}
        line = f"  {m['criteria']}  {b if b else ''}".rstrip()
        if line not in seen:
            seen.add(line)
            print(line)
    exs = exploitdb.by_cve(a.cve_id.upper())
    print(f"\nPublic exploits (Exploit-DB): {len(exs) or 'none found locally'}")
    for x in exs[:8]:
        print(f"  EDB-{x.edb_id}  {x.title}")
        print(f"    inspect: searchsploit -x {x.edb_id}   copy: searchsploit -m {x.edb_id}")
    exploit_refs = [r for r in nvd.references(cve) if any("exploit" in t.lower() for t in r["tags"])]
    if exploit_refs:
        print("PoC / exploit references (NVD):")
        for r in exploit_refs[:8]:
            print(f"  {r['url']}")
    print(f"\nNVD: https://nvd.nist.gov/vuln/detail/{a.cve_id.upper()}")
    return 0


# ------------------------------------------------------------- research -------
def cmd_research(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="searchmap research", description="ad-hoc product CVE research")
    p.add_argument("query", help='e.g. "Apache httpd 2.4.49" or "OpenSSH 7.2p2"')
    p.add_argument("--offline", action="store_true")
    p.add_argument("--all", dest="show_all", action="store_true")
    a = p.parse_args(argv)
    from .intelligence import engine, cisa
    import re
    m = re.search(r"\d[\w.]*$", a.query.strip())
    version = m.group(0) if m else ""
    product = a.query[:m.start()].strip() if m else a.query.strip()
    findings, cpe = engine.discover_cves(product, version, offline=a.offline,
                                         include_not_applicable=a.show_all)
    print(f"\nquery: product={product!r} version={version!r}")
    print(f"resolved CPE: {cpe.to_string() if cpe else 'UNRESOLVED (no CVE lookup possible)'}")
    if not cpe:
        print("  try a more specific product name, or `searchmap cve <id>` directly")
        return 1
    likely = [f for f in findings if f.confidence.value in ("CONFIRMED", "PROBABLE")]
    print(f"{len(likely)} likely applicable CVE(s):\n")
    for f in findings[:20]:
        kev = " KEV" if f.kev else ""
        exs = f" [{len(f.exploits)} exploit]" if f.exploits else ""
        print(f"  [{f.confidence.value:9}] {f.cve_id}  CVSS {f.cvss_score} "
              f"EPSS {f.epss or 0:.0%}{kev}{exs}")
        print(f"             {f.evidence[0] if f.evidence else ''}")
    return 0


# -------------------------------------------------------------- doctor --------
def cmd_doctor(argv: list[str]) -> int:
    from .doctor import run_doctor
    return run_doctor(argv)


# ------------------------------------------------------------ update-db -------
def cmd_update(argv: list[str]) -> int:
    from .intelligence import cisa
    from .core import cache
    print("[*] refreshing CISA KEV catalogue ...")
    try:
        info = cisa.update()
        print(f"[+] CISA KEV: {info['count']} entries (catalog {info['version']}, {info['bytes']} bytes)")
    except Exception as ex:
        print(f"[!] KEV update failed: {ex}")
    st = cache.stats()
    print(f"[*] intel cache: {st['entries']} entries, {st['bytes']//1024} KiB at {st['dir']}")
    print("[i] NVD/EPSS are queried on demand and cached per-item; searchsploit DB: run `searchsploit -u`")
    return 0


# -------------------------------------------------------------- report --------
def cmd_report(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="searchmap report", description="re-render a saved JSON scan")
    p.add_argument("input", help="a scan JSON produced by --format json")
    p.add_argument("--format", choices=["markdown", "html", "json"], default="html")
    p.add_argument("-o", "--output")
    a = p.parse_args(argv)
    import json
    from .reporting import reports, serialize
    result = serialize.from_dict(json.load(open(a.input)))
    out = {"markdown": reports.markdown_report, "html": reports.html_report,
           "json": reports.json_report}[a.format](result)
    if a.output:
        open(a.output, "w").write(out)
        print(f"[+] written to {a.output}")
    else:
        print(out)
    return 0


SUBCOMMANDS = {"cve": cmd_cve, "research": cmd_research, "doctor": cmd_doctor,
               "update-db": cmd_update, "report": cmd_report}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-V", "--version"):
        print(f"searchmap {__version__}")
        return 0
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv and argv[0] in SUBCOMMANDS:
        return SUBCOMMANDS[argv[0]](argv[1:])
    return cmd_scan(argv)


if __name__ == "__main__":
    sys.exit(main())
