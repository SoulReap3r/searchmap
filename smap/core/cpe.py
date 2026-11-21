"""CPE 2.3 parsing/building + product-name -> CPE resolution.

A CPE 2.3 formatted string has 13 colon-separated fields::

    cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other

We mostly care about (part, vendor, product, version). ``ALIASES`` maps the
messy product strings nmap/fingerprinting produce to the canonical
``(part, vendor, product)`` NVD uses; anything not in the map is resolved live
via the NVD CPE dictionary (see ``intelligence.nvd.resolve_cpe``) and cached.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

ANY = "*"


@dataclass(frozen=True)
class CPE:
    part: str = ANY
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    lang: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    @classmethod
    def parse(cls, s: str) -> "CPE":
        if not s or not s.startswith("cpe:2.3:"):
            # tolerate legacy cpe:/a:vendor:product:version
            if s and s.startswith("cpe:/"):
                return cls._parse_uri(s)
            raise ValueError(f"not a CPE 2.3 string: {s!r}")
        # split but respect backslash-escaped colons
        parts = re.split(r"(?<!\\):", s)[2:]
        parts += [ANY] * (11 - len(parts))
        f = [p.replace("\\:", ":") for p in parts[:11]]
        return cls(*f)

    @classmethod
    def _parse_uri(cls, s: str) -> "CPE":
        body = s[len("cpe:/"):]
        bits = body.split(":")
        bits += [ANY] * (5 - len(bits))
        part, vendor, product, version, update = bits[:5]
        return cls(part or ANY, vendor or ANY, product or ANY,
                   version or ANY, update or ANY)

    def to_string(self) -> str:
        fields = [self.part, self.vendor, self.product, self.version, self.update,
                  self.edition, self.lang, self.sw_edition, self.target_sw,
                  self.target_hw, self.other]
        return "cpe:2.3:" + ":".join(f or ANY for f in fields)

    @property
    def vp(self) -> tuple[str, str, str]:
        """(part, vendor, product) — identity ignoring version."""
        return (self.part, self.vendor, self.product)

    def same_product(self, other: "CPE") -> bool:
        return self.vendor == other.vendor and self.product == other.product and (
            self.part == other.part or ANY in (self.part, other.part))

    def with_version(self, version: str) -> "CPE":
        return CPE(self.part, self.vendor, self.product, version)

    @property
    def has_version(self) -> bool:
        return self.version not in (ANY, "-", "")

    def __str__(self) -> str:
        return self.to_string()


# canonical (part, vendor, product) for the products that actually show up on
# OSCP-style boxes. Keys are matched against a normalised product string.
ALIASES: dict[str, tuple[str, str, str]] = {
    "apache http server": ("a", "apache", "http_server"),
    "apache httpd":        ("a", "apache", "http_server"),
    "apache":              ("a", "apache", "http_server"),
    "httpd":               ("a", "apache", "http_server"),
    "apache tomcat":       ("a", "apache", "tomcat"),
    "tomcat":              ("a", "apache", "tomcat"),
    "coyote":              ("a", "apache", "tomcat"),
    "nginx":               ("a", "f5", "nginx"),
    "microsoft iis":       ("a", "microsoft", "internet_information_services"),
    "iis":                 ("a", "microsoft", "internet_information_services"),
    "internet information services": ("a", "microsoft", "internet_information_services"),
    "openssh":             ("a", "openbsd", "openssh"),
    "openssl":             ("a", "openssl", "openssl"),
    "vsftpd":              ("a", "vsftpd_project", "vsftpd"),
    "proftpd":             ("a", "proftpd", "proftpd"),
    "pure-ftpd":           ("a", "pureftpd", "pure-ftpd"),
    "filezilla server":    ("a", "filezilla-project", "filezilla_server"),
    "mysql":               ("a", "oracle", "mysql"),
    "mariadb":             ("a", "mariadb", "mariadb"),
    "microsoft sql server":("a", "microsoft", "sql_server"),
    "postgresql":          ("a", "postgresql", "postgresql"),
    "samba":               ("a", "samba", "samba"),
    "php":                 ("a", "php", "php"),
    "wordpress":           ("a", "wordpress", "wordpress"),
    "drupal":              ("a", "drupal", "drupal"),
    "joomla":              ("a", "joomla", "joomla\\!"),
    "jenkins":             ("a", "jenkins", "jenkins"),
    "gitlab":              ("a", "gitlab", "gitlab"),
    "grafana":             ("a", "grafana", "grafana"),
    "webmin":              ("a", "webmin", "webmin"),
    "exim":                ("a", "exim", "exim"),
    "postfix":             ("a", "postfix", "postfix"),
    "sendmail":            ("a", "sendmail", "sendmail"),
    "bind":                ("a", "isc", "bind"),
    "squid":               ("a", "squid-cache", "squid"),
    "jetty":               ("a", "eclipse", "jetty"),
    "jboss":               ("a", "redhat", "jboss_application_server"),
    "wildfly":             ("a", "redhat", "wildfly"),
    "elasticsearch":       ("a", "elastic", "elasticsearch"),
    "openssh_server":      ("a", "openbsd", "openssh"),
    "dropbear":            ("a", "dropbear_ssh_project", "dropbear_ssh"),
    "lighttpd":            ("a", "lighttpd", "lighttpd"),
    "phpmyadmin":          ("a", "phpmyadmin", "phpmyadmin"),
    "manageengine applications manager": ("a", "zohocorp", "manageengine_applications_manager"),
    "applications manager": ("a", "zohocorp", "manageengine_applications_manager"),
    "manageengine opmanager": ("a", "zohocorp", "manageengine_opmanager"),
    "manageengine servicedesk plus": ("a", "zohocorp", "manageengine_servicedesk_plus"),
}

_NOISE = re.compile(r"\b(server|service|daemon|httpd|project|software|inc|the|open|source)\b")


def normalize_product(product: str) -> str:
    p = (product or "").strip().lower()
    p = re.sub(r"[^a-z0-9. ]+", " ", p)
    p = re.sub(r"\s+", " ", p).strip()
    return p


def alias_lookup(product: str) -> Optional[tuple[str, str, str]]:
    """Try to map a product string to (part, vendor, product) without a network
    call. Exact match first, then a longest-token-substring match."""
    p = normalize_product(product)
    if not p:
        return None
    if p in ALIASES:
        return ALIASES[p]
    # try progressively trimming trailing version-ish tokens
    toks = p.split()
    for n in range(len(toks), 0, -1):
        cand = " ".join(toks[:n])
        if cand in ALIASES:
            return ALIASES[cand]
    # single distinctive token
    stripped = _NOISE.sub(" ", p).split()
    for t in stripped:
        if t in ALIASES:
            return ALIASES[t]
    return None
