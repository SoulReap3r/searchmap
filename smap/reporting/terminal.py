"""Rich terminal report."""
from __future__ import annotations
from rich.console import Console
from rich.text import Text

from ..core.models import Confidence, ScanResult, Service
from ..policies.exam import Policy
from ..protocols import registry

_CONF_COLOR = {"CONFIRMED": "bold red", "PROBABLE": "red", "POSSIBLE": "yellow",
               "UNKNOWN": "dim", "NOT_APPLICABLE": "dim"}
_SEV_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def _svc_rank(svc: Service) -> float:
    return max((f.actionability for f in svc.findings), default=0.0)


def _epss(f) -> str:
    return f"EPSS {f.epss:5.1%}" if f.epss is not None else "EPSS   -- "


def render(result: ScanResult, policy: Policy, *, show_all: bool = False,
           max_cves: int = 8, no_color: bool = False) -> None:
    c = Console(no_color=no_color, highlight=False)
    c.print()
    c.print(Text("  SEARCHMAP ", style="bold white on blue") + Text(f" v{result.tool_version}  "))
    c.print(f"  PROFILE: [bold]{policy.profile.upper()}[/]   {policy.description}", style="cyan")
    c.print(f"  ENGINES: {policy.enabled_summary()}", style="dim")
    c.print(f"  SOURCES: {', '.join(result.sources_used) or '—'}", style="dim")
    c.print(f"  POLICY BASIS: {policy.basis}", style="dim")

    for host in result.hosts:
        if not host.services:
            continue
        c.rule(f"[bold]{host.ip}[/]" + (f"  {host.hostname}" if host.hostname else "") +
               (f"  [dim]{host.os}[/]" if host.os else ""))
        for svc in sorted(host.services, key=_svc_rank, reverse=True):
            _render_service(c, svc, policy)

    _summary(c, result)


def _render_service(c: Console, svc: Service, policy: Policy) -> None:
    conf = svc.confidence
    head = Text(f"\n  {svc.port}/{svc.proto}  ", style="bold cyan")
    head.append(f"{svc.product or svc.name} {svc.version}".strip(), style="bold")
    head.append(f"   [{conf} id]", style="green" if conf in ("HIGH", "MEDIUM") else "yellow")
    c.print(head)
    if svc.resolved_cpe:
        c.print(f"      cpe: {svc.resolved_cpe}  [dim]({svc.cpe_source})[/]", style="dim")
    for fp in svc.fingerprints:
        detail = " ".join(f"{k}={v}" for k, v in fp.items() if k not in ("source",))
        c.print(f"      fingerprint[{fp.get('source')}]: {detail[:90]}", style="dim")
    for n in svc.notes[:4]:
        c.print(f"      note: {n}", style="dim")

    applicable = [f for f in svc.findings if f.confidence != Confidence.NOT_APPLICABLE]
    if applicable:
        likely = [f for f in applicable if f.confidence in (Confidence.CONFIRMED, Confidence.PROBABLE)]
        poss = [f for f in applicable if f.confidence == Confidence.POSSIBLE]
        c.print(f"      [bold]CVE DISCOVERY[/]  ({len(likely)} likely, {len(poss)} possible)")
        for f in applicable[:8]:
            tag = Text("      ")
            tag.append(f"{f.cve_id} ", style="bold")
            tag.append(f"[{f.confidence.value}] ", style=_CONF_COLOR[f.confidence.value])
            if f.cvss_score is not None:
                tag.append(f"CVSS {f.cvss_score} ", style=_SEV_COLOR.get(f.cvss_severity, "white"))
            tag.append(_epss(f) + " ", style="white")
            if f.kev:
                tag.append("KEV ", style="bold red")
            if f.exploits:
                tag.append(f"[{len(f.exploits)} exploit]", style="green")
            c.print(tag)
            if f.description:
                c.print(f"          {f.description[:96]}", style="dim")
            if f.evidence:
                c.print(f"          evidence: {f.evidence[0]}", style="dim")
            ex = next((e for e in f.exploits if e.edb_id), None)
            if ex:
                c.print(f"          exploit: EDB-{ex.edb_id} {ex.title[:44]}  "
                        f"-> searchsploit -x {ex.edb_id}", style="green")
        if len(applicable) > 8:
            c.print(f"          [dim]… +{len(applicable)-8} more (see --format json / report)[/]")
    elif svc.product:
        c.print("      [dim]no applicable CVEs found for this exact version[/]")

    # product-level exploits without a CVE (e.g. vsftpd backdoor)
    if svc.exploits:
        c.print(f"      [bold]EXPLOIT-DB (product-level)[/]")
        for e in svc.exploits[:3]:
            c.print(f"          EDB-{e.edb_id} {e.title[:60]}  [dim]searchsploit -x {e.edb_id}[/]", style="green")

    steps = svc.enum_steps or registry.build_steps(svc, has_creds=False, lab=(policy.profile == "lab"))
    if steps:
        c.print(f"      [bold]ENUMERATION[/] ({registry.protocol_key(svc)})")
        for st in steps[:4]:
            c.print(f"          · {st.what}: [cyan]{st.command}[/]")
            if st.why:
                c.print(f"            [dim]why: {st.why} | look for: {st.look_for}[/]")

    if svc.recommendations:
        c.print("      [bold]RECOMMENDED NEXT ACTIONS[/]")
        for r in svc.recommendations[:3]:
            c.print(f"          ▸ {r.title[:92]}")
            c.print(f"            [dim]{r.rationale} | prereq: {r.prerequisites}[/]")
            for cmd in r.research[:3]:
                c.print(f"            [dim]$ {cmd}[/]")
            c.print(f"            [dim]validate: {r.validation[:120]}[/]")


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
            rows.append((score, h.ip, s, top, ", ".join(why)))
    rows.sort(key=lambda r: -r[0])
    c.rule("[bold]ATTACK SURFACE — start here (ranked)[/]")
    if not rows:
        c.print("  [dim]no high-signal findings — work the enumeration steps above[/]")
    for score, ip, s, top, why in rows[:12]:
        lead = f"{top.cve_id} " if top else ""
        c.print(f"  [red][{score:5.1f}][/] {ip}:{s.port}  [bold]{s.product or s.name} {s.version}[/]"
                f"  [dim]→ {lead}{why}[/]")
    c.print()
