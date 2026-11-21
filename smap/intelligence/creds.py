"""Default-credential lookup, keyed to the product searchmap fingerprints.

Exam-safe: this only *prints* the known defaults to try (a curated table, like
the DefaultCreds cheat-sheet). Actually testing them is the opt-in, lab-only
`--creds-test` path (see `test_login`), which wraps `changeme`.
"""
from __future__ import annotations
import shutil
import subprocess

# normalized product substring  ->  ["user:pass", ...] most-likely first
BUILTIN: dict[str, list[str]] = {
    "manageengine applications manager": ["admin:admin"],
    "manageengine":            ["admin:admin"],
    "apache tomcat":           ["tomcat:tomcat", "admin:admin", "tomcat:s3cret", "role1:role1", "manager:manager"],
    "tomcat":                  ["tomcat:tomcat", "admin:admin", "tomcat:s3cret"],
    "jenkins":                 ["admin:admin", "admin:password"],
    "gitlab":                  ["root:5iveL!fe", "root:password"],
    "grafana":                 ["admin:admin"],
    "phpmyadmin":              ["root:", "root:root", "root:password"],
    "webmin":                  ["admin:admin", "root:root"],
    "jboss":                   ["admin:admin", "admin:"],
    "wildfly":                 ["admin:admin"],
    "weblogic":                ["weblogic:weblogic1", "weblogic:welcome1", "system:password"],
    "zabbix":                  ["Admin:zabbix"],
    "kibana":                  ["elastic:changeme"],
    "elasticsearch":           ["elastic:changeme"],
    "rabbitmq":                ["guest:guest"],
    "splunk":                  ["admin:changeme"],
    "nagios":                  ["nagiosadmin:nagiosadmin", "nagiosadmin:PASSW0RD"],
    "cacti":                   ["admin:admin"],
    "pfsense":                 ["admin:pfsense"],
    "openmediavault":          ["admin:openmediavault"],
    "drupal":                  ["admin:admin"],
    "joomla":                  ["admin:admin"],
    "wordpress":               ["admin:admin", "admin:password"],
    "iis":                     [],
    "mysql":                   ["root:", "root:root"],
    "mariadb":                 ["root:", "root:root"],
    "postgresql":              ["postgres:postgres", "postgres:"],
    "sql server":              ["sa:", "sa:sa"],
    "mongodb":                 ["admin:"],
    "redis":                   [],
    "vnc":                     [],
    "oracle":                  ["system:manager", "sys:change_on_install", "scott:tiger"],
    "apache activemq":         ["admin:admin"],
    "apache airflow":          ["airflow:airflow"],
    "portainer":               [],
    "grafana oss":             ["admin:admin"],
    "sonarqube":               ["admin:admin"],
    "jupyter":                 [],
    "cisco":                   ["cisco:cisco", "admin:admin"],
    "printer":                 ["admin:admin", "admin:"],
}


def defaults_for(product: str) -> list[str]:
    """Known default user:pass pairs for a fingerprinted product. Longest
    (most specific) matching key wins, merged with shorter ones."""
    p = (product or "").lower()
    if not p:
        return []
    out: list[str] = []
    for key in sorted(BUILTIN, key=len, reverse=True):
        if key in p:
            for c in BUILTIN[key]:
                if c not in out:
                    out.append(c)
    return out


def creds_cli_available() -> bool:
    return shutil.which("creds") is not None


def lookup_cmd(product: str) -> str:
    """The exam-legal command to look up *more* defaults for this product."""
    return f"creds search {product.split()[0].lower()}" if product else "creds search <product>"


def test_login(url: str, timeout: int = 120) -> list[str]:
    """LAB ONLY — wrap `changeme` to actively test defaults against a web login.
    Returns any credentials it reports as valid."""
    if not shutil.which("changeme"):
        return []
    try:
        out = subprocess.run(["changeme", "--timeout", "8", url],
                             capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.SubprocessError, OSError):
        return []
    hits = []
    for ln in out.splitlines():
        s = ln.strip()
        if "valid cred" in s.lower() or ("found" in s.lower() and ":" in s):
            hits.append(s)
    return hits
