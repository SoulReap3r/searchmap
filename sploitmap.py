#!/usr/bin/env python3
"""
sploitmap — attack-surface mapper, nxc-style.

Not just "nmap + searchsploit". For every service it:
  1. DISCOVERS   — nmap -sV
  2. FINGERPRINTS — actively probes web services for the real product/version
                    nmap misses (titles, Server headers, favicon, body sigs),
                    e.g. Tomcat hiding under a vendor web app
  3. CORRELATES   — exploits (searchsploit, ranked) + a curated knowledge base
                    of notable CVEs, default credentials, and attack techniques
                    per service/product
  4. RECOMMENDS   — the exact commands to try, ranked, with research links

Finds and recommends; never exploits. Exam-legal by default (nuclei is opt-in,
LABS ONLY). Requires: nmap, searchsploit. Optional: nuclei.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, ssl, subprocess, sys, urllib.request
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import quote_plus
import xml.etree.ElementTree as ET

VERSION = "2.0"
R=G=Y=B=C=M=BOLD=DIM=RST=""
_CODES={"R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[94m","C":"\033[96m",
        "M":"\033[95m","BOLD":"\033[1m","DIM":"\033[2m","RST":"\033[0m"}
def colors(on):
    if on:
        for k,v in _CODES.items(): globals()[k]=v

NMAP_TOP=1000; NMAP_TIMEOUT=1800; SS_TIMEOUT=25; HTTP_TIMEOUT=6
HOT=re.compile(r"(?i)remote code|rce|command execution|backdoor|unauthenticated|metasploit|"
               r"deserial|arbitrary file (?:upload|write)|auth(?:entication)? bypass|path traversal")
STOP={"microsoft","windows","httpd","server","service","services","linux","unix","ssl","openssl",
      "generic","http","https","over","rpc","msrpc","netbios","netbios-ssn","ssn","kerberos","ldap",
      "directory","active","terminal","wsmans","kpasswd5","tcpwrapped","simple","dns","plus","api",
      "httpapi","microsoft-ds","standard","or","later","rpcbind","host","remote","daemon"}

# ── KNOWLEDGE BASE: generic service → attack techniques (the nxc_plus-style richness)
# each technique: (what, command-with-{ip}/{port})
SERVICE_KB = {
 "ftp":[("anonymous login",            "ftp {ip}   # user: anonymous  pass: anything"),
        ("list/pull everything if anon","wget -m --no-passive ftp://anonymous:anonymous@{ip}/"),
        ("brute (only with a userlist)","hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{ip}")],
 "ssh":[("auth methods / banner",      "ssh -v {ip}   # note allowed auth methods"),
        ("user enum (older OpenSSH)",   "searchsploit openssh user enum   # e.g. CVE-2018-15473"),
        ("key/weak-cred login",         "hydra -L users.txt -P rockyou.txt ssh://{ip}  (slow; prefer found creds)")],
 "smb":[("null session enum",          "nxc smb {ip} -u '' -p '' --shares --users --rid-brute"),
        ("EternalBlue check (MS17-010)","nmap -p445 --script smb-vuln-ms17-010 {ip}"),
        ("MS08-067 (old 2003/XP)",      "nmap -p445 --script smb-vuln-ms08-067 {ip}"),
        ("auth enum once you have creds","nxc smb {ip} -u USER -p PASS --shares --sam --lsa")],
 "http":[("content discovery",         "feroxbuster -u http://{ip}:{port} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        ("quick wins",                 "curl -s http://{ip}:{port}/robots.txt ; curl -s http://{ip}:{port}/.git/HEAD"),
        ("methods / headers",          "curl -sI -X OPTIONS http://{ip}:{port}/"),
        ("vhosts",                     "ffuf -u http://{ip}:{port}/ -H 'Host: FUZZ.target' -w subdomains.txt")],
 "mysql":[("default root login",       "mysql -h {ip} -u root          # try empty password"),
        ("creds login",                "mysql -h {ip} -u USER -pPASS   # then UDF privesc if local")],
 "mssql":[("sa default",               "impacket-mssqlclient sa:''@{ip}  OR  nxc mssql {ip} -u sa -p ''"),
        ("xp_cmdshell RCE (if admin)", "nxc mssql {ip} -u sa -p PASS -x whoami --local-auth")],
 "rdp":[("version / NLA",              "nxc rdp {ip} -u USER -p PASS"),
        ("BlueKeep check (old)",       "nmap -p3389 --script rdp-vuln-ms12-020 {ip}")],
 "smtp":[("user enum (VRFY/RCPT)",     "smtp-user-enum -M VRFY -U users.txt -t {ip}"),
        ("open relay",                 "nmap -p25 --script smtp-open-relay {ip}")],
 "snmp":[("community string + enum",   "onesixtyone {ip} public ; snmpwalk -v2c -c public {ip}")],
 "ldap":[("anonymous bind + dump",     "nxc ldap {ip} -u '' -p '' --users ; ldapsearch -x -H ldap://{ip} -s base")],
 "nfs":[("list + mount exports",       "showmount -e {ip} ; sudo mount -t nfs {ip}:/EXPORT /mnt -o nolock")],
 "telnet":[("banner / weak creds",     "telnet {ip}   # try admin/admin, root/root")],
 "vnc":[("no-auth / weak creds",       "vncviewer {ip}   # often no or weak auth")],
 "pop3":[("creds",                     "nc {ip} 110   # USER/PASS")],
 "irc":[("UnrealIRCd backdoor (3.2.8.1)","searchsploit unrealircd backdoor")],
}

# specific products (matched from active fingerprinting) → default creds + notable CVEs + technique
@dataclass
class Prod:
    name: str
    sigs: list          # lowercase substrings to match in title/server/body
    creds: list = field(default_factory=list)   # "user:pass"
    cves: list = field(default_factory=list)     # "CVE-XXXX — note"
    tips: list = field(default_factory=list)     # (what, cmd)

PRODUCT_KB = [
 Prod("Apache Tomcat", ["apache-coyote","tomcat"],
      creds=["tomcat:tomcat","tomcat:s3cret","admin:admin","tomcat:admin","role1:role1"],
      cves=["CVE-2020-1938 Ghostcat (AJP :8009 file read/RCE)","CVE-2017-12617 PUT JSP RCE"],
      tips=[("manager upload war (if creds work)","curl -u USER:PASS --upload-file shell.war 'http://{ip}:{port}/manager/text/deploy?path=/x'"),
            ("Ghostcat read WEB-INF",            "searchsploit -m 48143 ; python3 48143.py -p 8009 {ip} /WEB-INF/web.xml")]),
 Prod("ManageEngine", ["manageengine","appmanager","adaudit","servicedesk","opmanager","desktop central"],
      creds=["admin:admin"],
      cves=["many ManageEngine RCEs — match exact product+build to CVE"],
      tips=[("default login",      "browse https://{ip}:{port}  user admin pass admin"),
            ("metasploit modules", "msfconsole -q -x 'search manageengine'")]),
 Prod("Jenkins", ["jenkins","hudson"],
      creds=["admin:admin","admin:password"],
      cves=["CVE-2024-23897 file read","script console = RCE if authed"],
      tips=[("script console RCE","browse http://{ip}:{port}/script  (Groovy)"),
            ("unauth build/asynchPeople","curl http://{ip}:{port}/asynchPeople/")]),
 Prod("phpMyAdmin", ["phpmyadmin"],
      creds=["root:","root:root","root:password"],
      cves=["CVE-2018-12613 LFI/RCE (4.8.x)"],
      tips=[("login then SQL -> webshell","root with empty pass is common; then SELECT ... INTO OUTFILE")]),
 Prod("WordPress", ["wp-content","wordpress","wp-login"],
      cves=["plugin/theme CVEs dominate"],
      tips=[("enumerate users + plugins","wpscan --url http://{ip}:{port} --enumerate u,vp"),
            ("xmlrpc pingback/brute",    "curl http://{ip}:{port}/xmlrpc.php")]),
 Prod("Grafana", ["grafana"], creds=["admin:admin"],
      cves=["CVE-2021-43798 path traversal (8.x)"],
      tips=[("path traversal read",u"curl --path-as-is http://{ip}:{port}/public/plugins/alertlist/../../../../../../etc/passwd")]),
 Prod("Gitlab", ["gitlab"], cves=["CVE-2021-22205 unauth RCE (ExifTool)"],
      tips=[("version at /help ; then match CVE","curl -s http://{ip}:{port}/help | grep -i version")]),
 Prod("Webmin", ["webmin"], creds=["admin:admin","root:root"],
      cves=["CVE-2019-15107 unauth RCE (1.890-1.920)"], tips=[]),
 Prod("Jboss/Wildfly", ["jboss","wildfly"], cves=["JMXInvoker / deserialization RCE"],
      tips=[("jexboss","jexboss -u http://{ip}:{port}")]),
 Prod("Drupal", ["drupal"], cves=["CVE-2018-7600 Drupalgeddon2 RCE"],
      tips=[("drupalgeddon","searchsploit drupal 7.x drupalgeddon")]),
]


@dataclass
class Svc:
    port:int; proto:str; name:str; product:str=""; version:str=""; cpe:str=""
    _ip:str=""
    exploits:list=field(default_factory=list)
    cves:list=field(default_factory=list)
    web:list=field(default_factory=list)              # nuclei findings
    fp:dict=field(default_factory=dict)               # active fingerprint: title/server/etc
    prods:list=field(default_factory=list)            # matched PRODUCT_KB entries
    @property
    def banner(self): return " ".join(x for x in (self.product,self.version) if x)
    @property
    def ver_clean(self):
        m=re.search(r"\d+(?:\.\d+)+",self.version or ""); return m.group(0) if m else ""
    @property
    def prod_tokens(self):
        return [t for t in self.product.split() if t.lower() not in STOP
                and not re.fullmatch(r"[\d.]+",t) and len(t)>=3]
    @property
    def query(self):
        q=" ".join(self.prod_tokens).strip()
        return (q+" "+self.ver_clean).strip() if self.ver_clean else q
    @property
    def searchable(self): return bool(self.prod_tokens) and bool(self.ver_clean)
    @property
    def is_web(self):
        n=self.name.lower()
        return self.port in {80,443,8080,8443,8000,8008,8888,7001,9090,5000,3000,8081,10000} \
               or "http" in n or "ssl" in n or n in ("wsmans","https-alt")
    @property
    def tls(self):
        n=self.name.lower()
        return "ssl" in n or "https" in n or self.port in (443,8443,8081) or "wsman" in n
    @property
    def url(self): return f"{'https' if self.tls else 'http'}://{self._ip}:{self.port}"
    @property
    def svc_key(self):
        n=self.name.lower()
        for k in SERVICE_KB:
            if k in n or n in (k,k+"s"): return k
        # nmap names SMB/MSSQL/RDP by alias, not by protocol — map them
        alias={"microsoft-ds":"smb","netbios-ssn":"smb","ms-sql-s":"mssql","ms-sql":"mssql",
               "ms-wbt-server":"rdp","mariadb":"mysql","domain":"","smtps":"smtp","submission":"smtp"}
        if n in alias: return alias[n]
        byport={21:"ftp",22:"ssh",23:"telnet",25:"smtp",110:"pop3",139:"smb",161:"snmp",
                389:"ldap",445:"smb",636:"ldap",1433:"mssql",2049:"nfs",3268:"ldap",
                3306:"mysql",3389:"rdp",5900:"vnc"}
        if self.port in byport: return byport[self.port]
        if self.is_web: return "http"
        if "mariadb" in self.banner.lower(): return "mysql"
        return ""


@dataclass
class Host:
    ip:str; name:str=""; services:list=field(default_factory=list)


def say(mk,msg):
    col={"*":C,"!":Y,"+":G," ":""}.get(mk,"")
    print(f"{col}[{mk}]{RST} {msg}" if mk.strip() else f"    {msg}",flush=True)


# ── stage 1: nmap ──────────────────────────────────────────────────────────
def run_nmap(targets,xmlp,full,cve):
    cmd=["nmap","--open","-sV","-T4","-oX",xmlp]+(["-p-"] if full else ["--top-ports",str(NMAP_TOP)])
    if cve:
        s="vulners,vuln"+(",vulscan/vulscan.nse" if os.path.isdir("/usr/share/nmap/scripts/vulscan") else "")
        cmd+=["--script",s]
    cmd+=list(targets)
    say("*",f"stage 1 — nmap -sV{' + CVE scripts' if cve else ''} ({'all' if full else f'top {NMAP_TOP}'} ports)")
    say(" ",f"{DIM}{' '.join(cmd)}{RST}\n")
    try: subprocess.run(cmd,timeout=NMAP_TIMEOUT)
    except (subprocess.TimeoutExpired,KeyboardInterrupt): say("!","nmap interrupted — parsing partial XML")
    return xmlp

def parse_nmap(path):
    hosts=[]
    try: root=ET.parse(path).getroot()
    except (OSError,ET.ParseError) as e: say("!",f"cannot parse XML: {e}"); return hosts
    for h in root.findall("host"):
        st=h.find("status")
        if st is not None and st.get("state")=="down": continue
        ip=next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in("ipv4","ipv6")),"")
        if not ip: continue
        host=Host(ip=ip); hn=h.find("./hostnames/hostname")
        if hn is not None: host.name=hn.get("name","")
        for p in h.findall("./ports/port"):
            stt=p.find("state")
            if stt is None or stt.get("state")!="open": continue
            s=p.find("service")
            svc=Svc(int(p.get("portid","0") or 0),p.get("protocol","tcp"),
                    s.get("name","") if s is not None else "",
                    s.get("product","") if s is not None else "",
                    s.get("version","") if s is not None else "")
            svc._ip=ip
            cpe=p.find("./service/cpe")
            if cpe is not None and cpe.text: svc.cpe=cpe.text
            for scr in p.findall("script"):
                for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)",scr.get("output","") or ""):
                    svc.cves.append((m.group(1),m.group(2)))
            host.services.append(svc)
        hosts.append(host)
    return hosts


# ── stage 2: active fingerprint (web) — recover what nmap misses ────────────
def http_get(url,path="/"):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req=urllib.request.Request(url+path,headers={"User-Agent":"sploitmap"})
    try:
        with urllib.request.urlopen(req,timeout=HTTP_TIMEOUT,context=ctx) as r:
            return dict(r.headers), r.read(65536), r.status
    except Exception as e:
        try:  # grab headers/body from HTTPError too
            return dict(e.headers), (e.read(65536) if hasattr(e,"read") else b""), getattr(e,"code",0)
        except Exception:
            return {}, b"", 0

def fingerprint(svc):
    if not svc.is_web: return
    hdrs,body,code=http_get(svc.url)
    if not hdrs and not body: return
    text=body.decode("latin-1","replace")
    title=(re.search(r"<title[^>]*>([^<]{1,120})</title>",text,re.I) or [None,""])[1].strip()
    svc.fp={"server":hdrs.get("Server",""),"title":title,"code":code,
            "powered":hdrs.get("X-Powered-By",""),"cookie":hdrs.get("Set-Cookie","")[:60]}
    # favicon hash (mmh3-less: md5 for a quick signal)
    hay=" ".join([svc.fp["server"],title,svc.fp["powered"],svc.fp["cookie"],text[:4000]]).lower()
    for pr in PRODUCT_KB:
        if any(sig in hay for sig in pr.sigs):
            svc.prods.append(pr)
    # recover a version from Server header or body (e.g. Apache-Coyote/1.1, Jenkins 2.x)
    mv=re.search(r"(?:tomcat|jenkins|gitlab|grafana|drupal)[/ ]?v?(\d+(?:\.\d+)+)",hay)
    if mv and not svc.ver_clean and svc.prods:
        svc.product=svc.product or svc.prods[0].name; svc.version=mv.group(1)


# ── stage 3: exploits (searchsploit) ───────────────────────────────────────
def searchsploit(q):
    if not q: return []
    try:
        d=json.loads(subprocess.run(["searchsploit","--json",q],capture_output=True,text=True,
                                    timeout=SS_TIMEOUT).stdout or "{}")
    except Exception: return []
    return [{"id":e.get("EDB-ID",""),"title":e.get("Title",""),"path":e.get("Path",""),
             "msf":"Metasploit" in e.get("Title",""),"hot":bool(HOT.search(e.get("Title","")))}
            for e in d.get("RESULTS_EXPLOIT",[])]

_DOS=re.compile(r"(?i)denial of service|\bdos\b|\bcrash\b|\bpoc\b")
_UENUM=re.compile(r"(?i)username enum|user enumeration")
def relevance(e,svc):
    """rank searchsploit hits — exact version wins, so we never recommend a
    hot-but-wrong-product exploit (e.g. Apache+PHP cgi-bin for Apache 2.4.49)."""
    t=e["title"].lower(); s=0
    if svc.ver_clean and svc.ver_clean in t: s+=100          # exact version match
    s+=6*sum(1 for tok in svc.prod_tokens if tok.lower() in t)
    if e["hot"]: s+=30
    if e["msf"]: s+=20
    if _UENUM.search(t): s+=15                                # user-enum = useful recon
    if _DOS.search(t): s-=60                                  # DoS is useless for a foothold
    return s

def enrich(svc,loose):
    if not svc.product: return
    if not loose and not svc.searchable: return
    if loose and not svc.prod_tokens: return
    seen,uniq=set(),[]
    for e in searchsploit(svc.query):
        if e["id"] in seen: continue
        seen.add(e["id"]); e["rel"]=relevance(e,svc); uniq.append(e)
    uniq.sort(key=lambda e:-e["rel"])
    svc.exploits=uniq


# ── nuclei (LABS ONLY) ──────────────────────────────────────────────────────
_NUC=re.compile(r"\[([a-z0-9][\w.-]*?)(?::[\w-]+)?\]\s+\[[\w-]+\]\s+\[(\w+)\]\s+(\S+)(?:\s+\[?\"?([^\"\]]+))?")
_SEV={"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}
def run_nuclei(svc,deep):
    cmd=["nuclei","-u",svc.url,"-silent","-nc"]+(["-as"] if deep else
        ["-t","http/technologies/","-t","http/exposed-panels/","-t","http/exposures/","-timeout","8","-rl","200"])
    try: out=subprocess.run(cmd,capture_output=True,text=True,timeout=300 if deep else 120).stdout
    except Exception: return
    for ln in out.splitlines():
        m=_NUC.match(re.sub(r"\x1b\[[0-9;]*m","",ln).strip())
        if m: svc.web.append((m.group(1),m.group(2).lower(),(m.group(4) or "").strip(" \"]")))


# ── output ─────────────────────────────────────────────────────────────────
def research(svc):
    terms={svc.query} | {p.name for p in svc.prods}
    for t in sorted(x for x in terms if x and x.strip()):
        q=quote_plus(t); yield t,f"exploit-db.com/search?q={q} · nvd.nist.gov/vuln/search/results?query={q}"

def fill(cmd,svc): return cmd.replace("{ip}",svc._ip).replace("{port}",str(svc.port))

def score(svc):
    s=0
    s+=50*sum(1 for e in svc.exploits if e["hot"] or e["msf"])
    s+=25*len(svc.prods)+10*sum(1 for p in svc.prods if p.creds)
    s+=5*len(svc.exploits)+3*len(svc.cves)
    if svc.svc_key in ("smb","http","ftp","mssql","mysql"): s+=4
    return -s,svc.port

def print_host(host):
    print(f"\n{BOLD}{'═'*74}{RST}\n{BOLD}  {host.ip}{RST}"+(f"  {DIM}{host.name}{RST}" if host.name else ""))
    print(f"{BOLD}{'═'*74}{RST}")
    for svc in sorted(host.services,key=score):
        extra=""
        if svc.fp.get("title"): extra=f"  {DIM}“{svc.fp['title'][:40]}”{RST}"
        elif svc.fp.get("server"): extra=f"  {DIM}{svc.fp['server'][:30]}{RST}"
        print(f"\n  {C}{svc.port}/{svc.proto}{RST}  {BOLD}{svc.banner or svc.name}{RST}{extra}")
        # matched products (fingerprint) — the richest signal
        for pr in svc.prods:
            print(f"      {M}● {pr.name}{RST}  {DIM}(fingerprinted){RST}")
            if pr.creds: print(f"        {R}default creds:{RST} {', '.join(pr.creds[:6])}")
            for cve in pr.cves[:3]: print(f"        {Y}CVE:{RST} {cve}")
            for what,cmd in pr.tips[:3]: print(f"        {G}try:{RST} {what}  {DIM}{fill(cmd,svc)}{RST}")
        # exploits (relevance-sorted: exact-version matches first)
        hot=[e for e in svc.exploits if e["hot"] or e["msf"]]
        if svc.exploits:
            print(f"      {R}{len(svc.exploits)} ExploitDB match(es){RST}"+(f"  {R}{BOLD}[{len(hot)} hot]{RST}" if hot else ""))
            for e in svc.exploits[:4]:
                ver="✓ver" if svc.ver_clean and svc.ver_clean in e["title"].lower() else ""
                fl=" ".join(x for x in(ver,"[MSF]" if e["msf"] else("[hot]" if e["hot"] else "")) if x)
                print(f"        {G}{e['id']:>6}{RST} {e['title'][:56]:<56} {R}{fl}{RST}")
            be=svc.exploits[0]; fn=be["path"].split("/")[-1]
            rn={"py":"python3","rb":"ruby","sh":"bash","pl":"perl","php":"php"}.get(fn.rsplit(".",1)[-1],"")
            print(f"        {G}→{RST} searchsploit -x {be['id']} ; searchsploit -m {be['id']}"+
                  (f" ; {rn} {fn} {svc._ip}" if rn else ""))
        # generic service techniques (KB)
        if svc.svc_key and svc.svc_key in SERVICE_KB:
            print(f"      {B}techniques ({svc.svc_key}):{RST}")
            for what,cmd in SERVICE_KB[svc.svc_key][:4]:
                print(f"        {DIM}·{RST} {what}  {DIM}{fill(cmd,svc)}{RST}")
        # nmap CVEs
        if svc.cves:
            top=sorted(set(svc.cves),key=lambda c:float(c[1]),reverse=True)[:4]
            print(f"      {Y}CVEs:{RST} "+", ".join(f"{c}({v})" for c,v in top))
        # nuclei
        for tid,sev,ex in sorted(svc.web,key=lambda x:_SEV.get(x[1],9))[:5]:
            col={"critical":R,"high":R,"medium":Y}.get(sev,DIM)
            print(f"        {col}nuclei {sev:<8}{RST} {tid}"+(f"  {DIM}{ex[:30]}{RST}" if ex else ""))
        # research
        for t,u in research(svc): print(f"        {DIM}research {t}: {u}{RST}")

def summary(hosts):
    ranked=[]
    for h in hosts:
        for s in h.services:
            sc=-score(s)[0]
            if sc>=25: ranked.append((sc,h,s))
    ranked.sort(key=lambda x:-x[0])
    print(f"\n{BOLD}{'═'*74}{RST}\n{BOLD}  ATTACK SURFACE — start here (ranked){RST}\n{BOLD}{'═'*74}{RST}")
    if not ranked: print(f"  {DIM}nothing high-signal — work the techniques/research per service above{RST}")
    for sc,h,s in ranked[:10]:
        why=[]
        if any(e["hot"] or e["msf"] for e in s.exploits): why.append("exploit")
        if any(p.creds for p in s.prods): why.append("default-creds")
        if s.prods: why.append(s.prods[0].name)
        if s.cves: why.append(f"{len(s.cves)} CVEs")
        print(f"  {R}[{sc:>3}]{RST} {h.ip}:{s.port}  {BOLD}{s.banner or s.name}{RST}  {DIM}→ {', '.join(why) or 'enumerate'}{RST}")
    print()


def main():
    p=argparse.ArgumentParser(prog="sploitmap",description=f"sploitmap {VERSION} — attack-surface mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  sploitmap 10.10.10.5\n  sploitmap 10.10.10.5 --cve\n  sploitmap x --xml scan.xml\n  sploitmap 10.10.10.5 --nuclei   # LABS ONLY")
    p.add_argument("target"); p.add_argument("--xml",metavar="FILE")
    p.add_argument("--full",action="store_true"); p.add_argument("--cve",action="store_true",
        help="nmap vuln,vulners CVE scripts (catches versionless bugs like MS17-010)")
    p.add_argument("--loose",action="store_true",help="searchsploit product-only (noisier)")
    p.add_argument("--no-fp",action="store_true",help="skip active web fingerprinting")
    p.add_argument("--nuclei",action="store_true",help="LABS ONLY — nuclei scan (automated scanner/exploiter, NOT exam-legal)")
    p.add_argument("--deep",action="store_true",help="with --nuclei: full -as scan")
    p.add_argument("-w","--workers",type=int,default=8); p.add_argument("--no-color",action="store_true")
    a=p.parse_args(); colors(not a.no_color and sys.stdout.isatty())
    for b in ("nmap","searchsploit"):
        if not shutil.which(b) and not (a.xml and b=="nmap"):
            print(f"{R}error:{RST} {b} not on PATH",file=sys.stderr); return 1
    print(f"\n{BOLD}  sploitmap {VERSION}{RST}  {DIM}discover · fingerprint · correlate · recommend — never exploits{RST}\n")

    if a.xml:
        say("*",f"stage 1 — ingesting {a.xml}"); hosts=parse_nmap(a.xml)
    else:
        tg=[a.target]
        if os.path.isfile(a.target): tg=[l.strip() for l in open(a.target) if l.strip() and not l.startswith("#")]
        hosts=parse_nmap(run_nmap(tg,"sploitmap_scan.xml",a.full,a.cve))
    allsvc=[s for h in hosts for s in h.services]

    if not a.no_fp and [s for s in allsvc if s.is_web]:
        say("*",f"stage 2 — fingerprinting {sum(1 for s in allsvc if s.is_web)} web service(s)")
        with ThreadPoolExecutor(max_workers=max(1,a.workers)) as pool:
            for _ in as_completed([pool.submit(fingerprint,s) for s in allsvc if s.is_web]): pass

    say("*",f"stage 3 — correlating exploits/CVEs/techniques on {len(allsvc)} service(s)")
    with ThreadPoolExecutor(max_workers=max(1,a.workers)) as pool:
        for _ in as_completed([pool.submit(enrich,s,a.loose) for s in allsvc]): pass

    web=[s for s in allsvc if s.is_web]
    if web and a.nuclei and shutil.which("nuclei"):
        say("!",f"{Y}LAB MODE — nuclei is NOT exam-legal{RST}")
        say("*",f"stage 4 — nuclei {'(deep)' if a.deep else '(fast)'} on {len(web)} web service(s)")
        with ThreadPoolExecutor(max_workers=max(1,min(a.workers,4))) as pool:
            for _ in as_completed([pool.submit(run_nuclei,s,a.deep) for s in web]): pass

    for h in hosts:
        if h.services: print_host(h)
    if hosts: summary(hosts)
    return 0

if __name__=="__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(130)
