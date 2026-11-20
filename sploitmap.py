#!/usr/bin/env python3
"""
sploitmap — nmap -sV  →  per-service exploit/CVE mapping, nxc-style.

Point it at a target (or an existing nmap -oX file). It fingerprints every
service, then for each product+version shows the known exploits (ExploitDB via
searchsploit, offline) and — with --cve — CVEs/CVSS (nmap vulners/vulscan).
Ranks services with real exploits first and hands you the copy/run commands.

Finds exploits; never runs them.  Requires: nmap, searchsploit.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys
from urllib.parse import quote_plus
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

VERSION = "1.0"

R = G = Y = B = C = BOLD = DIM = RST = ""
_CODES = {"R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[94m",
          "C":"\033[96m","BOLD":"\033[1m","DIM":"\033[2m","RST":"\033[0m"}
def colors(on):
    if on:
        for k,v in _CODES.items(): globals()[k]=v

NMAP_TOP = 1000
NMAP_TIMEOUT = 1800
SS_TIMEOUT = 25
# words that make a searchsploit title high-signal (likely RCE / usable)
HOT = re.compile(r"(?i)remote code|rce|command execution|backdoor|unauthenticated|"
                 r"metasploit|buffer overflow|deserial|arbitrary file (?:upload|write)|"
                 r"authentication bypass|auth bypass|path traversal|directory traversal")
# generic tokens that over-match searchsploit — stripped before searching, and
# a service with NOTHING but these left is skipped (no reliable product name)
STOP = {"microsoft","windows","httpd","server","service","services","linux","unix",
        "ssl","openssl","generic","http","https","over","rpc","msrpc","netbios",
        "netbios-ssn","ssn","kerberos","ldap","directory","active","terminal",
        "wsmans","kpasswd5","tcpwrapped","simple","dns","plus","api","httpapi",
        "microsoft-ds","standard","or","later","rpcbind","host","remote","daemon"}


WEB_PORTS = {80,443,8080,8443,8000,8008,8888,7001,9090,5000,3000,8081,10000}

@dataclass
class Svc:
    port: int
    proto: str
    name: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    exploits: list = field(default_factory=list)   # dicts: id,title,path, msf,hot
    cves: list = field(default_factory=list)        # (cve, cvss)
    web: list = field(default_factory=list)         # nuclei: (id, severity, detail)

    @property
    def is_web(self):
        n = self.name.lower()
        return (self.port in WEB_PORTS or "http" in n or "ssl" in n
                or n in ("wsmans","https-alt","https"))
    @property
    def url(self):
        tls = "https" if ("ssl" in self.name.lower() or "https" in self.name.lower()
                          or self.port in (443,8443,8080) or "wsman" in self.name.lower()) else "http"
        return f"{tls}://{self._ip}:{self.port}"
    _ip: str = ""

    @property
    def banner(self):
        return " ".join(x for x in (self.product, self.version) if x)
    @property
    def ver_clean(self):
        # just the numeric version (drop "or later", build strings, etc.)
        m = re.search(r"\d+(?:\.\d+)+", self.version)
        return m.group(0) if m else ""
    @property
    def prod_tokens(self):
        # real product-name tokens: not generic, not a bare number, len>=3
        return [t for t in self.product.split()
                if t.lower() not in STOP and not re.fullmatch(r"[\d.]+", t) and len(t) >= 3]
    @property
    def query(self):
        q = " ".join(self.prod_tokens).strip()
        return (q + " " + self.ver_clean).strip() if self.ver_clean else q
    @property
    def searchable(self):
        # reliable only with a real product name AND a version
        return bool(self.prod_tokens) and bool(self.ver_clean)


@dataclass
class Host:
    ip: str
    name: str = ""
    services: list = field(default_factory=list)


# ── nmap ────────────────────────────────────────────────────────────────
def run_nmap(targets, xml_path, full, cve):
    cmd = ["nmap", "--open", "-sV", "-T4", "-oX", xml_path]
    cmd += ["-p-"] if full else ["--top-ports", str(NMAP_TOP)]
    if cve:
        # vulners/vulscan = version/CPE -> CVE ; 'vuln' category = protocol checks
        # that catch versionless bugs (SMB MS17-010/EternalBlue, etc.)
        scripts = "vulners,vuln"
        if os.path.isdir("/usr/share/nmap/scripts/vulscan"):
            scripts += ",vulscan/vulscan.nse"
        cmd += ["--script", scripts]
    cmd += list(targets)
    say("*", f"stage 1 — nmap -sV{' + CVE scripts' if cve else ''} "
             f"({'all ports' if full else f'top {NMAP_TOP}'})")
    say(" ", f"{DIM}{' '.join(cmd)}{RST}\n")
    try:
        subprocess.run(cmd, timeout=NMAP_TIMEOUT)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        say("!", "nmap interrupted — parsing whatever XML exists")
    return xml_path


def parse_nmap(path):
    hosts = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as e:
        say("!", f"cannot parse nmap XML: {e}"); return hosts
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ip = next((a.get("addr") for a in h.findall("address")
                   if a.get("addrtype") in ("ipv4","ipv6")), "")
        if not ip: continue
        host = Host(ip=ip)
        hn = h.find("./hostnames/hostname")
        if hn is not None: host.name = hn.get("name","")
        for p in h.findall("./ports/port"):
            stt = p.find("state")
            if stt is None or stt.get("state") != "open": continue
            svc_el = p.find("service")
            svc = Svc(port=int(p.get("portid","0") or 0),
                      proto=p.get("protocol","tcp"),
                      name=(svc_el.get("name","") if svc_el is not None else ""),
                      product=(svc_el.get("product","") if svc_el is not None else ""),
                      version=(svc_el.get("version","") if svc_el is not None else ""))
            svc._ip = ip
            cpe = p.find("./service/cpe")
            if cpe is not None and cpe.text: svc.cpe = cpe.text
            # pull CVEs from vulners/vulscan script output on this port
            for scr in p.findall("script"):
                out = scr.get("output","") or ""
                for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)", out):
                    svc.cves.append((m.group(1), m.group(2)))
            host.services.append(svc)
        hosts.append(host)
    return hosts


# ── searchsploit ──────────────────────────────────────────────────────────
def searchsploit(query):
    if not query: return []
    try:
        out = subprocess.run(["searchsploit", "--json", query],
                             capture_output=True, text=True, timeout=SS_TIMEOUT).stdout
        data = json.loads(out or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []
    res = []
    for e in data.get("RESULTS_EXPLOIT", []):
        title = e.get("Title","")
        res.append({"id": e.get("EDB-ID",""), "title": title,
                    "path": e.get("Path",""),
                    "msf": "Metasploit" in title,
                    "hot": bool(HOT.search(title))})
    return res


# ── nuclei (core engine) ──────────────────────────────────────────────────
_SEV_RANK = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}
_NUC_LINE = re.compile(r"\[([a-z0-9][\w.-]*?)(?::[\w-]+)?\]\s+\[[\w-]+\]\s+\[(\w+)\]\s+(\S+)(?:\s+\[?\"?([^\"\]]+)\"?\]?)?")

def run_nuclei(svc, deep=False):
    """nuclei auto-references the service: fingerprints tech/versions + runs CVE
    templates. Recovered versions (e.g. Tomcat 9.0.16 under AppManager) are fed
    back into searchsploit — the bit raw nuclei doesn't do for you."""
    url = svc.url
    if deep:   # full automatic scan — fingerprints AND runs all matching CVE templates
        cmd = ["nuclei","-u",url,"-as","-silent","-nc"]
    else:      # fast: fingerprint tech + panels (recovers hidden versions) + exposures
        cmd = ["nuclei","-u",url,"-t","http/technologies/","-t","http/exposed-panels/",
               "-t","http/exposures/","-silent","-nc","-timeout","8","-rl","200"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=300 if deep else 120).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return
    recovered = []
    for ln in out.splitlines():
        ln = re.sub(r"\x1b\[[0-9;]*m","",ln).strip()
        m = _NUC_LINE.match(ln)
        if not m:
            continue
        tid, sev, matched, extra = m.group(1), m.group(2).lower(), m.group(3), (m.group(4) or "").strip()
        svc.web.append((tid, sev, extra))
        # a tech-detect template that extracted a version -> searchsploit it
        if extra and re.search(r"\d+\.\d+", extra) and ("detect" in tid or "version" in tid):
            prod = tid.replace("-detect","").replace("-version","").split(":")[0]
            recovered.append((prod, re.search(r"\d+(?:\.\d+)+", extra).group(0)))
    for prod, ver in recovered:
        for e in searchsploit(f"{prod} {ver}"):
            e["via"] = f"nuclei:{prod} {ver}"
            svc.exploits.append(e)
    # dedupe exploits after merging nuclei-recovered ones
    seen, uniq = set(), []
    for e in svc.exploits:
        if e["id"] in seen: continue
        seen.add(e["id"]); uniq.append(e)
    svc.exploits = uniq


def enrich(svc, loose=False):
    # Reliable matches need a VERSION — searching a bare generic product
    # ("RPC", "Terminal Services", "httpd") returns pure noise. So by default
    # only search version-pinned services; --loose allows product-only.
    if not svc.product:
        return
    if not loose and not svc.searchable:
        return
    if loose and not svc.prod_tokens:
        return
    res = searchsploit(svc.query)
    # dedupe by EDB-ID, keep order
    seen, uniq = set(), []
    for e in res:
        if e["id"] in seen: continue
        seen.add(e["id"]); uniq.append(e)
    svc.exploits = uniq


# ── output ─────────────────────────────────────────────────────────────
def research_links(svc):
    """Pre-filled CVE research URLs — YOU click and read them (exam-legal, unlike
    an automated scanner). Covers the versioned product and any nuclei-recovered
    tech (e.g. Tomcat under a web app)."""
    terms = {" ".join(svc.prod_tokens) + (" " + svc.ver_clean if svc.ver_clean else "")}
    for tid, sev, extra in svc.web:        # fold in nuclei-recovered versions
        if extra and re.search(r"\d+\.\d+", extra) and "detect" in tid:
            terms.add(f"{tid.split(':')[0].replace('-detect','')} {re.search(r'[\\d.]+', extra).group(0)}")
    out = []
    for t in sorted(x for x in terms if x.strip()):
        q = quote_plus(t)
        out.append((t, f"exploit-db.com/search?q={q}  ·  nvd.nist.gov/vuln/search/results?query={q}"))
    return out

def rank(svc):
    # services with hot/msf exploits float to the top
    hot = sum(1 for e in svc.exploits if e["hot"] or e["msf"])
    return (-hot, -len(svc.exploits), svc.port)

def print_host(host):
    print(f"\n{BOLD}{'═'*70}{RST}")
    print(f"{BOLD}  {host.ip}{RST}" + (f"  {DIM}{host.name}{RST}" if host.name else ""))
    print(f"{BOLD}{'═'*70}{RST}")
    for svc in sorted(host.services, key=rank):
        head = f"  {C}{svc.port}/{svc.proto}{RST}  {BOLD}{svc.banner or svc.name}{RST}"
        hot = [e for e in svc.exploits if e["hot"] or e["msf"]]
        if svc.exploits:
            tag = f"{R}{len(svc.exploits)} exploit(s){RST}" + (f"  {R}{BOLD}[{len(hot)} hot]{RST}" if hot else "")
            print(f"{head}   {tag}")
            for e in (hot or svc.exploits)[:6]:
                flag = f"{R}[MSF]{RST}" if e["msf"] else (f"{Y}[hot]{RST}" if e["hot"] else "")
                ext = e["path"].rsplit(".",1)[-1] if "." in e["path"] else ""
                print(f"        {G}{e['id']:>6}{RST}  {e['title'][:60]:<60} {DIM}({ext}){RST} {flag}")
            if len(svc.exploits) > 6:
                print(f"        {DIM}… {len(svc.exploits)-6} more — searchsploit {svc.query}{RST}")
            best = (hot or svc.exploits)[0]["id"]
            print(f"        {DIM}→ copy: searchsploit -m {best}   view: searchsploit -x {best}{RST}")
        elif svc.cves:
            print(f"{head}   {Y}{len(svc.cves)} CVE(s), no ExploitDB match{RST}")
        elif svc.product and not svc.searchable:
            why = "no version" if svc.prod_tokens else "generic/unnamed service"
            print(f"{head}   {DIM}{why} — skipped (--loose to try){RST}")
        else:
            print(f"{head}   {DIM}no known exploit{RST}")
        # show top CVEs by CVSS when we have them
        if svc.cves:
            top = sorted(set(svc.cves), key=lambda c: float(c[1]), reverse=True)[:4]
            print("        " + DIM + "CVE: " + ", ".join(f"{c}({v})" for c,v in top) + RST)
        # nuclei findings (fingerprints + CVEs it ran live)
        if svc.web:
            scol = {"critical":R,"high":R,"medium":Y,"low":Y,"info":DIM}
            for tid, sev, extra in sorted(svc.web, key=lambda x: _SEV_RANK.get(x[1],9))[:8]:
                c = scol.get(sev, DIM)
                det = f"  {DIM}{extra[:40]}{RST}" if extra else ""
                print(f"        {c}nuclei {sev:<8}{RST} {tid}{det}")
        # exam-legal CVE research links (you do the research — always allowed)
        if svc.prod_tokens:
            for label, url in research_links(svc):
                print(f"        {B}research{RST} {DIM}{label}:{RST} {url}")


def summary(hosts):
    hot = [(h,s) for h in hosts for s in h.services
           if any(e["hot"] or e["msf"] for e in s.exploits)]
    print(f"\n{BOLD}{'═'*70}{RST}\n{BOLD}  SUMMARY — start here{RST}\n{BOLD}{'═'*70}{RST}")
    if not hot:
        print(f"  {DIM}no high-signal exploits matched — check CVEs / manual research{RST}")
    for h, s in sorted(hot, key=lambda x: rank(x[1])):
        e = next(e for e in s.exploits if e["hot"] or e["msf"])
        print(f"  {R}[!]{RST} {h.ip}:{s.port}  {s.banner}  →  {G}EDB {e['id']}{RST}  {e['title'][:50]}")
    print()


def say(mk, msg):
    col = {"*":C,"!":Y,"+":G," ":""}.get(mk,"")
    print(f"{col}[{mk}]{RST} {msg}" if mk.strip() else f"    {msg}", flush=True)


def main():
    p = argparse.ArgumentParser(prog="sploitmap",
        description=f"sploitmap {VERSION} — nmap -sV → per-service exploit/CVE mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  sploitmap 10.10.10.5\n  sploitmap 10.10.10.5 --cve --full\n"
               "  sploitmap targets.txt\n  sploitmap --xml existing.xml")
    p.add_argument("target", help="IP, hostname, CIDR, or file of targets")
    p.add_argument("--xml", metavar="FILE", help="ingest an existing nmap -oX file (skip scanning)")
    p.add_argument("--full", action="store_true", help="nmap -p- (all ports) instead of top 1000")
    p.add_argument("--cve", action="store_true", help="add nmap vulners/vulscan CVE scripts (vulners needs internet)")
    p.add_argument("--loose", action="store_true", help="also search product-only (no version) — noisier, more false positives")
    p.add_argument("--nuclei", action="store_true",
                   help="LABS ONLY — run nuclei on web services (fingerprint + CVEs). "
                        "nuclei is an automated scanner/exploiter: NOT exam-legal. Off by default.")
    p.add_argument("--deep", action="store_true", help="with --nuclei: full automatic scan (-as), slower")
    p.add_argument("-w","--workers", type=int, default=8, help="parallel searchsploit lookups (default 8)")
    p.add_argument("--nmap-xml-out", metavar="FILE", help="where to write nmap XML")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args()
    colors(not a.no_color and sys.stdout.isatty())

    for b in ("nmap","searchsploit"):
        if not shutil.which(b) and not (a.xml and b=="nmap"):
            print(f"{R}error:{RST} {b} not on PATH", file=sys.stderr); return 1

    print(f"\n{BOLD}  sploitmap {VERSION}{RST}  {DIM}nmap -sV → exploits/CVEs — finds, never runs{RST}\n")

    if a.xml:
        say("*", f"stage 1 — ingesting {a.xml}")
        hosts = parse_nmap(a.xml)
    else:
        targets = [a.target]
        if os.path.isfile(a.target):
            targets = [l.strip() for l in open(a.target) if l.strip() and not l.startswith("#")]
        xmlp = a.nmap_xml_out or "sploitmap_scan.xml"
        run_nmap(targets, xmlp, a.full, a.cve)
        hosts = parse_nmap(xmlp)

    nsvc = sum(len(h.services) for h in hosts)
    say("*", f"stage 2 — searchsploit on {nsvc} service(s) across {len(hosts)} host(s)")
    allsvc = [s for h in hosts for s in h.services]
    with ThreadPoolExecutor(max_workers=max(1,a.workers)) as pool:
        futs = [pool.submit(enrich, s, a.loose) for s in allsvc]
        for _ in as_completed(futs): pass

    # stage 3 — nuclei (LABS ONLY, opt-in) auto-references every web service
    web = [s for s in allsvc if s.is_web]
    if web and a.nuclei and shutil.which("nuclei"):
        say("!", f"{Y}LAB MODE — nuclei is NOT exam-legal (automated scanner/exploiter){RST}")
        say("*", f"stage 3 — nuclei {'(deep -as)' if a.deep else '(fast)'} on "
                 f"{len(web)} web service(s) — fingerprints + CVEs, no prior knowledge")
        wk = max(1, min(a.workers, 4))   # nuclei is heavy; cap parallelism
        with ThreadPoolExecutor(max_workers=wk) as pool:
            for _ in as_completed([pool.submit(run_nuclei, s, a.deep) for s in web]):
                pass

    for h in hosts:
        if h.services: print_host(h)
    if hosts: summary(hosts)
    return 0


if __name__ == "__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(130)
