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


def render(result: ScanResult, policy: Policy, *, show_all: bool = False,
           max_cves: int = 8, no_color: bool = False) -> None:
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
            _render_service(c, svc, policy, max_cves)

    _summary(c, result)


def _render_service(c: Console, svc: Service, policy: Policy, max_cves: int) -> None:
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
    if applicable:
        _cve_table(c, svc, applicable, max_cves)
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

    if svc.recommendations:
        c.print("\n    [bold]start here[/]")
        for r in svc.recommendations[:2]:
            cve = r.title.split(":")[0]
            c.print(f"      [bold]▸ {cve}[/]  [dim]{r.rationale}  ·  prereq: {r.prerequisites}[/]")
            for cmd in r.research[:3]:
                c.print(f"          [green]$[/] [dim]{cmd}[/]")
            c.print(f"          [dim]✓ {r.validation}[/]")   # full text; wraps cleanly


def _cve_table(c: Console, svc: Service, applicable: list, max_cves: int) -> None:
    likely = sum(1 for f in applicable if f.confidence in (Confidence.CONFIRMED, Confidence.PROBABLE))
    poss = len(applicable) - likely
    c.print(f"\n    [bold]CVEs[/]  [green]{likely} likely[/] · [yellow]{poss} possible[/]")

    # if the version couldn't be matched (build number), say it ONCE, not per row
    note = next((f.evidence[0] for f in applicable if f.evidence and "not directly comparable" in f.evidence[0]), "")
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
    for f in applicable[:max_cves]:
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
    if len(applicable) > max_cves:
        c.print(f"    [dim]  … +{len(applicable)-max_cves} more — see --format html / json for the full list[/]")

    # surface the single best exploit inline (the foothold)
    best = next((f for f in applicable for e in f.exploits if e.edb_id), None)
    if best:
        e = next(e for e in best.exploits if e.edb_id)
        c.print(f"    [green]→ top exploit[/] EDB-{e.edb_id}  {e.title[:52]}  [dim]searchsploit -x {e.edb_id}[/]")


def _summary(c: Console, result: ScanResult) -> None:
    rows = []
    for h in result.hosts:
        for s in h.services:
            top = s.findings[0] if s.findings else None
            score = _svc_rank(s)
            if score <= 0 and not s.exploits:
                continue
            why = []
            if top and top.kev:
                why.append("KEV")
            if top and top.exploits:
                why.append("exploit")
            if top:
                why.append(top.confidence.value.lower())
            rows.append((score, h.ip, s, top, " · ".join(why) or "enumerate"))
    rows.sort(key=lambda r: -r[0])
    c.print()
    c.rule("[bold bright_white]ATTACK SURFACE — start here (ranked)[/]", style="red")
    if not rows:
        c.print("  [dim]no high-signal findings — work the enumeration steps above[/]\n")
        return
    t = Table(box=box.SIMPLE_HEAD, padding=(0, 2), show_edge=False, pad_edge=False)
    t.add_column("score", justify="right", style="bold red", no_wrap=True)
    t.add_column("target", style="cyan", no_wrap=True)
    t.add_column("service", style="bright_white")
    t.add_column("lead", overflow="ellipsis", max_width=40)
    for score, ip, s, top, why in rows[:12]:
        lead = (f"{top.cve_id} · " if top else "") + why
        t.add_row(f"{score:.0f}", f"{ip}:{s.port}", f"{s.product or s.name} {s.version}".strip(), lead)
    c.print(t)
    c.print()
