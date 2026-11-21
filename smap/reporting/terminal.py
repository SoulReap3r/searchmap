"""Rich terminal report — built for scanning by eye: aligned CVE tables, clear
section headers, and generous spacing instead of a wall of text."""
from __future__ import annotations
import re
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..core.cpe import CPE
from ..core.models import Confidence, ScanResult, Service
from ..policies.exam import Policy
from ..protocols import registry

_CONF_STYLE = {"CONFIRMED": "bold red", "PROBABLE": "dark_orange3", "POSSIBLE": "yellow",
               "UNKNOWN": "dim", "NOT_APPLICABLE": "dim"}
_SEV_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
_ID_STYLE = {"HIGH": "bold green", "MEDIUM": "green", "LOW": "yellow", "NONE": "dim"}


def _svc_rank(svc: Service) -> float:
    return max((f.actionability for f in svc.findings), default=0.0)


def _hi_sev(f) -> bool:
    """High/critical severity — the default 'signal' threshold (CVSS >= 7.0)."""
    return f.cvss_severity in ("CRITICAL", "HIGH") or (f.cvss_score or 0.0) >= 7.0


def render(result: ScanResult, policy: Policy, *, show_all: bool = False,
           max_cves: int = 8, no_color: bool = False, verbose: bool = False) -> None:
    c = Console(no_color=no_color, highlight=False)
    c.print()
    c.print(Text(" searchmap ", style="bold white on blue") +
            Text(f" v{result.tool_version}", style="bold") +
            Text("   discover · fingerprint · correlate · recommend", style="dim"))
    c.print(f"[bold]profile[/]  [cyan]{policy.profile.upper()}[/] — {policy.description}")
    c.print(f"[dim]engines  {policy.enabled_summary()}[/]")
    c.print(f"[dim]sources  {', '.join(result.sources_used) or '—'}[/]")

    for host in result.hosts:
        if not host.services:
            continue
        label = host.ip + (f"  {host.hostname}" if host.hostname else "") + (f"  ·  {host.os}" if host.os else "")
        c.print()
        c.rule(f"[bold bright_white]{label}[/]", style="blue")
        for svc in sorted(host.services, key=_svc_rank, reverse=True):
            _render_service(c, svc, policy, max_cves, verbose)

    _summary(c, result, verbose=verbose)


def _render_service(c: Console, svc: Service, policy: Policy, max_cves: int,
                    verbose: bool = False) -> None:
    idc = svc.confidence
    head = Text("\n▶ ", style="bold blue")
    head.append(f"{svc.port}/{svc.proto}", style="bold cyan")
    head.append("   ")
    head.append(f"{svc.product or svc.name} {svc.version}".strip(), style="bold bright_white")
    head.append(f"   ● {idc} id", style=_ID_STYLE.get(idc, "dim"))
    c.print(head)

    # identity block — condensed, aligned labels
    if svc.resolved_cpe:
        try:
            cc = CPE.parse(svc.resolved_cpe)
            cpe_short = f"{cc.vendor}:{cc.product}"
        except ValueError:
            cpe_short = svc.resolved_cpe
        c.print(f"    [dim]cpe       {cpe_short}  ·  {svc.cpe_source}[/]")
    seen = []
    for fp in svc.fingerprints:
        if fp.get("url"):
            seen.append(re.sub(r"^https?://[^/]+", "", fp["url"]) or "/")
        elif fp.get("cn"):
            seen.append(f"cert:{fp['cn']}")
    if seen:
        c.print(f"    [dim]seen      {' · '.join(dict.fromkeys(seen))}[/]")
    for n in svc.notes[:2]:
        c.print(f"    [dim]note      {n}[/]")

    applicable = [f for f in svc.findings if f.confidence != Confidence.NOT_APPLICABLE]
    # default view = high/critical only; -v reveals medium/low ("deep results")
    shown = applicable if verbose else [f for f in applicable if _hi_sev(f)]
    if applicable:
        _cve_table(c, svc, applicable, shown, max_cves, verbose)
    elif svc.product:
        c.print("    [dim]CVEs      none applicable for this exact version[/]")

    if svc.exploits:
        c.print("\n    [bold]public exploits[/] [dim](product-level)[/]")
        for e in svc.exploits[:4]:
            line = Text("      • ")
            line.append(f"EDB-{e.edb_id} ", style="green")
            line.append(f"{e.title[:58]}", style="default")
            line.append(f"   searchsploit -x {e.edb_id}", style="dim")
            c.print(line)

    steps = svc.enum_steps or registry.build_steps(svc, has_creds=False, lab=(policy.profile == "lab"))
    if steps:
        c.print(f"\n    [bold]enumeration[/] [dim]· {registry.protocol_key(svc) or 'generic'}[/]")
        for st in steps[:4]:
            c.print(f"      • [bright_white]{st.what}[/]")
            c.print(f"        [cyan]{st.command}[/]")
            if st.why:
                c.print(f"        [dim]↳ {st.why}  —  look for: {st.look_for}[/]")

    rec_by_cve = {r.title.split(":")[0]: r for r in svc.recommendations}
    start = shown if shown else applicable
    if start and svc.recommendations:
        c.print("\n    [bold]start here[/]")
        for f in start[:3]:
            r = rec_by_cve.get(f.cve_id)
            if r is None:
                continue
            head = Text("      ▸ ")
            head.append(f.cve_id, style="bold")
            head.append(f"  {f.confidence.value.lower()}", style=_CONF_STYLE[f.confidence.value])
            if f.cvss_score is not None:
                head.append(f" · CVSS {f.cvss_score}", style=_SEV_STYLE.get(f.cvss_severity, "white"))
            c.print(head)
            c.print(f"          [dim]prereq [/] {r.prerequisites}")
            ss = [f"searchsploit -x {e.edb_id}" for e in f.exploits if e.edb_id][:3]
            exp = " · ".join(ss) if ss else "no public exploit indexed — research / manual"
            c.print(f"          [dim]exploit[/] [green]{exp}[/]")
            c.print(f"          [dim]nvd    [/] {f.nvd_url}")   # full text; wraps cleanly


def _cve_table(c: Console, svc: Service, applicable: list, shown: list,
               max_cves: int, verbose: bool) -> None:
    likely = sum(1 for f in applicable if f.confidence in (Confidence.CONFIRMED, Confidence.PROBABLE))
    poss = len(applicable) - likely
    hidden = len(applicable) - len(shown)
    tail = f"  [dim]· {hidden} medium/low hidden (-v)[/]" if hidden and not verbose else ""
    c.print(f"\n    [bold]CVEs[/]  [green]{likely} likely[/] · [yellow]{poss} possible[/]{tail}")

    if not shown:
        c.print("    [dim]no high/critical-severity findings — use -v for medium/low[/]")
        return

    # if the version couldn't be matched (build number), say it ONCE, not per row
    note = next((f.evidence[0] for f in shown if f.evidence and "not directly comparable" in f.evidence[0]), "")
    if note:
        c.print(f"    [yellow]⚠ {note.split(';',1)[-1].strip()} — treat these as leads, verify per advisory[/]")

    t = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=False, show_edge=False, pad_edge=False)
    t.add_column("CVE", style="cyan", no_wrap=True)
    t.add_column("conf", no_wrap=True)
    t.add_column("CVSS", justify="right", no_wrap=True)
    t.add_column("EPSS", justify="right", no_wrap=True)
    t.add_column("KEV", justify="center", no_wrap=True)
    t.add_column("exp", justify="right", no_wrap=True)
    t.add_column("what it is", no_wrap=True, overflow="ellipsis", min_width=24, max_width=52)
    for f in shown[:max_cves]:
        cvss = Text(f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—",
                    style=_SEV_STYLE.get(f.cvss_severity, "white"))
        desc = " ".join((f.description or "").split())[:60]
        t.add_row(
            f.cve_id,
            Text(f.confidence.value.lower(), style=_CONF_STYLE[f.confidence.value]),
            cvss,
            f"{f.epss:.0%}" if f.epss is not None else "—",
            Text("KEV", style="bold red") if f.kev else "",
            Text(str(len(f.exploits)), style="green") if f.exploits else Text("0", style="dim"),
            desc,
        )
    c.print(t)
    if len(shown) > max_cves:
        c.print(f"    [dim]  … +{len(shown)-max_cves} more shown — see --format html / json for the full list[/]")

    # surface the single best exploit inline (the foothold)
    best = next((f for f in shown for e in f.exploits if e.edb_id), None)
    if best:
        e = next(e for e in best.exploits if e.edb_id)
        c.print(f"    [green]→ top exploit[/] EDB-{e.edb_id}  {e.title[:52]}  [dim]searchsploit -x {e.edb_id}[/]")


def _summary(c: Console, result: ScanResult, per_host: int = 10, verbose: bool = False) -> None:
    c.print()
    title = "ATTACK SURFACE — start here (ranked per host)"
    c.rule(f"[bold bright_white]{title}{'  [deep results]' if verbose else ''}[/]", style="red")
    if not verbose:
        c.print("  [dim]high-confidence IDs · high/critical severity only — add -v for the rest[/]")

    # one ranked block per host; hosts ordered by their best finding.
    # default view: only HIGH-id services and high/critical findings (cut exam noise)
    host_blocks = []
    for h in result.hosts:
        finds, port_of = [], {}
        for s in h.services:
            if not verbose and s.confidence != "HIGH":
                continue
            for f in s.findings:
                if f.confidence == Confidence.NOT_APPLICABLE:
                    continue
                if not verbose and not _hi_sev(f):
                    continue
                finds.append(f)
                port_of[id(f)] = s.port
        finds.sort(key=lambda f: f.priority)
        best = -finds[0].actionability if finds else 0.0
        host_blocks.append((best, h, finds, port_of))
    host_blocks.sort(key=lambda x: x[0])

    any_cve = any(finds for _, _, finds, _ in host_blocks)
    if not any_cve:
        leads = [f"{h.ip}:{s.port} ({s.product or s.name})"
                 for h in result.hosts for s in h.services if s.exploits or s.enum_steps]
        c.print("  [dim]no version-matched CVEs — work enumeration on:[/] " + ", ".join(leads[:10])
                if leads else "  [dim]no high-signal findings — work the enumeration steps above[/]")
        c.print()
        return

    for _, h, finds, port_of in host_blocks:
        if not finds:
            svcs = ", ".join(f"{s.port}/{s.name}" for s in h.services)
            c.print(f"\n  [bold cyan]{h.ip}[/]  [dim]— no version-matched CVEs; enumerate {svcs}[/]")
            continue
        top = finds[0]
        c.print(f"\n  [bold cyan]{h.ip}[/]  [dim]top: {top.cve_id} "
                f"CVSS {top.cvss_score} ({top.confidence.value.lower()})[/]")
        t = Table(box=box.SIMPLE_HEAD, padding=(0, 1), show_edge=False, pad_edge=False)
        t.add_column("#", justify="right", style="dim", no_wrap=True)
        t.add_column("port", style="cyan", no_wrap=True)
        t.add_column("CVE", style="bold", no_wrap=True)
        t.add_column("conf", no_wrap=True)
        t.add_column("CVSS", justify="right", no_wrap=True)
        t.add_column("EPSS", justify="right", no_wrap=True)
        t.add_column("KEV", justify="center", no_wrap=True)
        t.add_column("exp", justify="right", no_wrap=True)
        t.add_column("what it is", no_wrap=True, overflow="ellipsis", min_width=20, max_width=46)
        for i, f in enumerate(finds[:per_host], 1):
            t.add_row(
                str(i), str(port_of.get(id(f), "")), f.cve_id,
                Text(f.confidence.value.lower(), style=_CONF_STYLE[f.confidence.value]),
                Text(f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—",
                     style=_SEV_STYLE.get(f.cvss_severity, "white")),
                f"{f.epss:.0%}" if f.epss is not None else "—",
                Text("KEV", style="bold red") if f.kev else "",
                Text(str(len(f.exploits)), style="green") if f.exploits else Text("0", style="dim"),
                " ".join((f.description or "").split())[:60],
            )
        c.print(t)
        if len(finds) > per_host:
            c.print(f"    [dim]… +{len(finds)-per_host} more on this host[/]")
    c.print("\n  [dim]ranked by CVSS · exploit availability · KEV · EPSS (confirmed before possible)[/]\n")
