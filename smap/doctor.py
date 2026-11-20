"""`sploitmap doctor` — dependencies, API connectivity, caches, policy."""
from __future__ import annotations
import shutil
import subprocess
import time

from rich.console import Console
from rich.table import Table

from .core import cache
from .policies.exam import Policy

CORE_TOOLS = ["nmap", "searchsploit"]
OPTIONAL_TOOLS = ["nxc", "netexec", "whatweb", "httpx", "nuclei", "feroxbuster", "ffuf",
                  "enum4linux-ng", "smbclient", "rpcclient", "ldapsearch", "nikto",
                  "evil-winrm", "hydra", "onesixtyone", "snmpwalk", "dig", "showmount",
                  "curl", "openssl", "impacket-mssqlclient"]
PY_LIBS = ["requests", "packaging", "rich", "jinja2", "yaml", "defusedxml"]


import re as _re
_ANSI = _re.compile(r"\x1b\[[0-9;]*m")
_BAD = _re.compile(r"(?i)illegal option|invalid option|^usage|unknown option|^options")


def _tool_version(name: str) -> str:
    for flag in ("--version", "-V", "version"):
        try:
            r = subprocess.run([name, flag], capture_output=True, text=True, timeout=5)
        except (subprocess.SubprocessError, OSError):
            continue
        for raw in (r.stdout + "\n" + r.stderr).splitlines():
            line = _ANSI.sub("", raw).strip()
            if line and not _BAD.search(line):
                return line[:40]
    return shutil.which(name) or ""


def _probe(url: str, params=None) -> tuple[bool, str]:
    from .core import http
    t = time.time()
    try:
        http.get_json(url, params=params, timeout=12)
        return True, f"{(time.time()-t)*1000:.0f} ms"
    except Exception as e:
        return False, str(e)[:40]


def run_doctor(argv: list[str]) -> int:
    c = Console()
    c.print(f"\n[bold white on blue] sploitmap doctor [/]\n")

    # dependencies
    t = Table(title="dependencies", show_lines=False, title_justify="left")
    t.add_column("component"); t.add_column("status"); t.add_column("detail")
    for name in CORE_TOOLS:
        path = shutil.which(name)
        t.add_row(name, "[green]OK[/]" if path else "[red]MISSING (required)[/]",
                  _tool_version(name) if path else "install it")
    for name in OPTIONAL_TOOLS:
        path = shutil.which(name)
        if path:
            t.add_row(name, "[green]OK[/]", _tool_version(name))
        else:
            t.add_row(name, "[yellow]absent[/]", "optional")
    for lib in PY_LIBS:
        try:
            __import__(lib)
            t.add_row(f"py:{lib}", "[green]OK[/]", "")
        except ImportError:
            t.add_row(f"py:{lib}", "[red]MISSING[/]", "pip install")
    c.print(t)

    # connectivity
    c.print("\n[bold]intelligence sources[/]")
    checks = [
        ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0", {"cveId": "CVE-2021-41773"}),
        ("EPSS", "https://api.first.org/data/v1/epss", {"cve": "CVE-2021-41773"}),
        ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", None),
    ]
    import os
    for name, url, params in checks:
        ok, detail = _probe(url, params)
        c.print(f"  {name:10} {'[green]reachable[/]' if ok else '[red]unreachable[/]'}  [dim]{detail}[/]")
    c.print(f"  {'NVD key':10} " + ("[green]set[/]" if os.environ.get("NVD_API_KEY")
            else "[yellow]not set[/] [dim](5 req/30s; set NVD_API_KEY for 50)[/]"))

    # caches / feeds
    from .intelligence import cisa
    st = cache.stats()
    c.print("\n[bold]caches[/]")
    c.print(f"  intel cache: {st['entries']} entries, {st['bytes']//1024} KiB  [dim]{st['dir']}[/]")
    c.print(f"  CISA KEV feed: " + ("[green]present[/]" if cisa.have_feed()
            else "[yellow]absent[/] [dim](run: sploitmap update-db)[/]"))

    # policy
    c.print("\n[bold]operating profiles[/]")
    for prof in ("exam", "lab"):
        pol = Policy(prof)
        c.print(f"  [cyan]{prof}[/]: {pol.enabled_summary()}")
    c.print(f"  [dim]basis: {Policy('exam').basis}[/]\n")
    return 0
