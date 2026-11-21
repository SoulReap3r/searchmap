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


def _short_prereq(f) -> str:
    """What you need to fire it, from the CVSS vector. The auth requirement is
    the actionable part; 'local' is flagged because you can't hit it remotely."""
    v = f.cvss_vector or ""
    if "AV:L" in v or "AV:P" in v:
        base = "local (need shell)"
    elif "PR:N" in v:
        base = "unauth"                 # no creds needed — the good case
    elif "PR:L" in v:
        base = "needs creds (user)"
    elif "PR:H" in v:
        base = "needs creds (admin)"
    else:
        base = "—"
    if "UI:R" in v and base != "—":
        base += " + user-interaction"
    return base


def _exploit_cmd(f) -> str:
    ex = next((e for e in f.exploits if e.edb_id), None)
    return f"searchsploit -x {ex.edb_id}" if ex else "—"


def _fmt_cred(c: str) -> str:
    """'root:' (empty password) -> 'root:(blank)' for readability."""
    return c[:-1] + ":(blank)" if c.endswith(":") else c


def _need_col(f, svc) -> str:
    """Prereq + the default creds to try when the finding needs them."""
    base = _short_prereq(f)
    if "needs creds" in base and svc is not None and svc.default_creds:
        base += f"  → try {_fmt_cred(svc.default_creds[0])}"
    return base


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
        seen_enum: set[str] = set()   # dedupe identical enum (e.g. SMB on 139 & 445)
        for svc in sorted(host.services, key=_svc_rank, reverse=True):
            _render_service(c, svc, policy, max_cves, verbose, seen_enum)

    _summary(c, result, verbose=verbose)


def _render_service(c: Console, svc: Service, policy: Policy, max_cves: int,
                    verbose: bool = False, seen_enum: set | None = None) -> None:
    seen_enum = seen_enum if seen_enum is not None else set()
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
    if svc.default_creds:
        from ..intelligence import creds as _creds
        c.print(f"    [bold red]creds[/]     [red]try: {', '.join(_fmt_cred(x) for x in svc.default_creds[:6])}[/]"
                f"  [dim]· more: {_creds.lookup_cmd(svc.product)}[/]")
    if svc.creds_tested:
        c.print(f"    [bold green]VALID[/]     [green]{' · '.join(svc.creds_tested[:4])}[/]")

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

    # enumeration — show each protocol's steps once per host (SMB on 139 & 445 is identical)
    steps = svc.enum_steps or registry.build_steps(svc, has_creds=False, lab=(policy.profile == "lab"))
    if steps:
        key = registry.protocol_key(svc) or "generic"
        if key in seen_enum:
            c.print(f"\n    [dim]enumeration · {key} — same as above[/]")
        else:
            seen_enum.add(key)
            c.print(f"\n    [bold]enumeration[/] [dim]· {key}[/]")
            for st in steps[:4]:
                c.print(f"      • [bright_white]{st.what}[/]  [cyan]{st.command}[/]")
                if st.why:
                    c.print(f"        [dim]↳ {st.why}  —  look for: {st.look_for}[/]")
    # NB: the actionable "start here" (prereq / searchsploit / nvd) now lives once,
    # in the ATTACK SURFACE table at the end — no per-service duplicate.


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

    # full-width table; "what it is" fills the remaining space (KEV dropped to
    # give the description room)
    t = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=True, show_edge=False, pad_edge=False)
    t.add_column("CVE", style="cyan", no_wrap=True)
    t.add_column("conf", no_wrap=True)
    t.add_column("CVSS", justify="right", no_wrap=True)
    t.add_column("EPSS", justify="right", no_wrap=True)
    t.add_column("exp", justify="right", no_wrap=True)
    t.add_column("what it is", no_wrap=True, overflow="ellipsis", ratio=1)
    for f in shown[:max_cves]:
        cvss = Text(f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—",
                    style=_SEV_STYLE.get(f.cvss_severity, "white"))
        t.add_row(
            f.cve_id,
            Text(f.confidence.value.lower(), style=_CONF_STYLE[f.confidence.value]),
            cvss,
            f"{f.epss:.0%}" if f.epss is not None else "—",
            Text(str(len(f.exploits)), style="green") if f.exploits else Text("0", style="dim"),
            " ".join((f.description or "").split()),
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
        finds, port_of, svc_of = [], {}, {}
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
                svc_of[id(f)] = s
        finds.sort(key=lambda f: f.priority)
        best = -finds[0].actionability if finds else 0.0
        host_blocks.append((best, h, finds, port_of, svc_of))
    host_blocks.sort(key=lambda x: x[0])

    any_cve = any(finds for _, _, finds, _, _ in host_blocks)
    if not any_cve:
        leads = [f"{h.ip}:{s.port} ({s.product or s.name})"
                 for h in result.hosts for s in h.services if s.exploits or s.enum_steps]
        c.print("  [dim]no version-matched CVEs — work enumeration on:[/] " + ", ".join(leads[:10])
                if leads else "  [dim]no high-signal findings — work the enumeration steps above[/]")
        c.print()
        return

    for _, h, finds, port_of, svc_of in host_blocks:
        if not finds:
            svcs = ", ".join(f"{s.port}/{s.name}" for s in h.services)
            c.print(f"\n  [bold cyan]{h.ip}[/]  [dim]— no version-matched CVEs; enumerate {svcs}[/]")
            continue
        top = finds[0]
        c.print(f"\n  [bold cyan]{h.ip}[/]  [dim]top: {top.cve_id} "
                f"CVSS {top.cvss_score} ({top.confidence.value.lower()})[/]")
        # full-width action table: what to run + what you need (incl. default creds)
        t = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=True, show_edge=False, pad_edge=False)
        t.add_column("#", justify="right", style="dim", no_wrap=True)
        t.add_column("port", style="cyan", no_wrap=True)
        t.add_column("CVE", style="bold", no_wrap=True)
        t.add_column("conf", no_wrap=True)
        t.add_column("CVSS", justify="right", no_wrap=True)
        t.add_column("exploit", style="green", no_wrap=True)
        t.add_column("need", overflow="ellipsis", no_wrap=True, ratio=1)
        for i, f in enumerate(finds[:per_host], 1):
            t.add_row(
                str(i), str(port_of.get(id(f), "")), f.cve_id,
                Text(f.confidence.value.lower(), style=_CONF_STYLE[f.confidence.value]),
                Text(f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—",
                     style=_SEV_STYLE.get(f.cvss_severity, "white")),
                _exploit_cmd(f),
                _need_col(f, svc_of.get(id(f))),
            )
        c.print(t)
        if len(finds) > per_host:
            c.print(f"    [dim]… +{len(finds)-per_host} more on this host (-v / --format html)[/]")
    c.print("\n  [dim]ranked: confirmed first, then severity + a public exploit  ·  "
            "detail: searchmap cve <ID>  ·  nvd.nist.gov/vuln/detail/<ID>[/]\n")
