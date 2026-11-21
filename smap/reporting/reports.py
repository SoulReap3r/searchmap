"""JSON / Markdown / HTML reports off the same ScanResult."""
from __future__ import annotations
import html

from ..core.models import Confidence, ScanResult
from .serialize import to_json


def json_report(result: ScanResult) -> str:
    return to_json(result)


def _applicable(svc):
    return [f for f in svc.findings if f.confidence != Confidence.NOT_APPLICABLE]


def markdown_report(result: ScanResult) -> str:
    L = [f"# sploitmap report (v{result.tool_version})",
         "", f"- **Profile:** {result.profile}",
         f"- **Scanned:** {result.started} → {result.finished}",
         f"- **Sources:** {', '.join(result.sources_used) or '—'}", ""]
    for h in result.hosts:
        L.append(f"## {h.ip}" + (f" ({h.hostname})" if h.hostname else ""))
        if h.os:
            L.append(f"*OS:* {h.os}")
        for s in h.services:
            L.append(f"\n### {s.port}/{s.proto} — {s.product or s.name} {s.version}".rstrip())
            if s.resolved_cpe:
                L.append(f"`{s.resolved_cpe}`")
            apps = _applicable(s)
            if apps:
                L.append("\n| CVE | Confidence | CVSS | EPSS | KEV | Exploit | Evidence |")
                L.append("|---|---|---|---|---|---|---|")
                for f in apps[:25]:
                    L.append(f"| [{f.cve_id}]({f.nvd_url}) | {f.confidence.value} | "
                             f"{f.cvss_score or ''} {f.cvss_severity} | "
                             f"{f.epss:.0%} | {'yes' if f.kev else ''} | "
                             f"{'yes' if f.exploits else ''} | {(f.evidence[0] if f.evidence else '')} |")
            if s.exploits:
                L.append("\n*Exploit-DB (product-level):* " +
                         ", ".join(f"EDB-{e.edb_id}" for e in s.exploits[:6]))
            if s.enum_steps:
                L.append("\n**Enumeration**")
                for st in s.enum_steps[:6]:
                    L.append(f"- {st.what}: `{st.command}`" +
                             (f"  \n  _{st.why}_" if st.why else ""))
            for r in s.recommendations[:3]:
                L.append(f"\n**{r.title}**  ")
                L.append(f"*{r.rationale}* — prereq: {r.prerequisites}  ")
                for cmd in r.research[:4]:
                    L.append(f"    $ {cmd}")
                L.append(f"*validate:* {r.validation}")
    return "\n".join(L)


_HTML_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<title>sploitmap report</title><style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{color:#58a6ff} h2{border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:32px}
h3{color:#79c0ff;margin-top:22px}
code,.cpe{background:#161b22;padding:1px 5px;border-radius:4px;font-family:ui-monospace,monospace}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{border:1px solid #30363d;padding:5px 8px;text-align:left}
th{background:#161b22}
.CONFIRMED{color:#ff7b72;font-weight:700}.PROBABLE{color:#ffa657}.POSSIBLE{color:#d29922}
.kev{background:#da3633;color:#fff;border-radius:3px;padding:0 5px;font-size:11px}
.rec{background:#161b22;border-left:3px solid #58a6ff;padding:8px 12px;margin:8px 0;border-radius:4px}
.enum{margin:6px 0 10px 0}.enum li{margin:3px 0}
.meta{color:#8b949e}.cmd{color:#7ee787}.cmd code{color:#7ee787;background:#0d1117}
</style></head><body><div class="wrap">"""


def html_report(result: ScanResult) -> str:
    e = html.escape
    out = [_HTML_HEAD, f"<h1>sploitmap report</h1>",
           f"<p class=meta>Profile <b>{e(result.profile)}</b> · "
           f"{e(result.started)} → {e(result.finished)} · "
           f"sources: {e(', '.join(result.sources_used) or '—')}</p>"]
    for h in result.hosts:
        out.append(f"<h2>{e(h.ip)} <span class=meta>{e(h.hostname)} {e(h.os)}</span></h2>")
        for s in h.services:
            out.append(f"<h3>{s.port}/{e(s.proto)} — {e(s.product or s.name)} {e(s.version)}</h3>")
            if s.resolved_cpe:
                out.append(f"<p class=cpe>{e(s.resolved_cpe)}</p>")
            apps = _applicable(s)
            if apps:
                out.append("<table><tr><th>CVE</th><th>Confidence</th><th>CVSS</th>"
                           "<th>EPSS</th><th>KEV</th><th>Exploit</th><th>Evidence</th></tr>")
                for f in apps[:30]:
                    kev = "<span class=kev>KEV</span>" if f.kev else ""
                    out.append(
                        f"<tr><td><a href='{f.nvd_url}'>{f.cve_id}</a></td>"
                        f"<td class={f.confidence.value}>{f.confidence.value}</td>"
                        f"<td>{f.cvss_score or ''} {e(f.cvss_severity)}</td>"
                        f"<td>{f.epss:.0%}</td><td>{kev}</td>"
                        f"<td>{'yes' if f.exploits else ''}</td>"
                        f"<td>{e(f.evidence[0] if f.evidence else '')}</td></tr>")
                out.append("</table>")
            if s.exploits:
                eids = ", ".join(f"<a href='https://www.exploit-db.com/exploits/{e.edb_id}'>"
                                 f"EDB-{e.edb_id}</a>" for e in s.exploits[:8] if e.edb_id)
                out.append(f"<p class=meta>Exploit-DB (product-level): {eids}</p>")
            if s.enum_steps:
                out.append("<b>Enumeration</b><ul class=enum>")
                for st in s.enum_steps[:6]:
                    why = f" <span class=meta>— {e(st.why)}</span>" if st.why else ""
                    out.append(f"<li>{e(st.what)}: <code>{e(st.command)}</code>{why}</li>")
                out.append("</ul>")
            for r in s.recommendations[:3]:
                cmds = "".join(f"<div class=cmd>$ {e(c)}</div>" for c in r.research[:4])
                out.append(f"<div class=rec><b>{e(r.title)}</b><br><span class=meta>{e(r.rationale)} "
                           f"· prereq: {e(r.prerequisites)}</span>{cmds}"
                           f"<div class=meta>validate: {e(r.validation)}</div></div>")
    out.append("</div></body></html>")
    return "\n".join(out)
