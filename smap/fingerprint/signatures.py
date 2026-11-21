"""Product signatures for active fingerprinting.

Each entry maps evidence (Server header tokens, title/body substrings) to a
product name that ``core.cpe`` can resolve, plus a regex to pull a version out
of the evidence. Product names here must be ones ``cpe.alias_lookup`` knows, so
a fingerprint flows straight into CVE discovery.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class Signature:
    product: str                      # resolvable product name
    server_tokens: list[str] = field(default_factory=list)  # match in Server header
    body_tokens: list[str] = field(default_factory=list)    # match in title/body/cookies
    version_re: list[str] = field(default_factory=list)      # pull version from evidence
    probe_paths: list[str] = field(default_factory=list)     # extra URLs to GET when the
                                                             # version isn't on "/" (login pages etc.)
    note: str = ""


SIGNATURES: list[Signature] = [
    Signature("Apache httpd", ["apache/"], ["apache/"],
              [r"apache/(\d+\.\d+\.\d+)"]),
    Signature("nginx", ["nginx"], ["nginx"], [r"nginx/(\d+\.\d+(?:\.\d+)?)"]),
    Signature("Microsoft IIS", ["microsoft-iis", "iis/"], [],
              [r"iis/(\d+\.\d+)"]),
    Signature("Apache Tomcat", ["apache-coyote", "tomcat"], ["apache tomcat", "tomcat/"],
              [r"tomcat/(\d+\.\d+\.\d+)", r"tomcat/(\d+\.\d+)"]),
    Signature("Jetty", ["jetty"], ["jetty"], [r"jetty[/(]+(\d+\.\d+\.\d+)"]),
    Signature("lighttpd", ["lighttpd"], [], [r"lighttpd/(\d+\.\d+\.\d+)"]),
    Signature("Jenkins", ["jenkins", "jetty"], ["jenkins", "x-jenkins"],
              [r"jenkins[^0-9]{0,8}(\d+\.\d+(?:\.\d+)?)"]),
    Signature("GitLab", ["gitlab"], ["gitlab", "gon.gitlab"],
              [r"gitlab[^0-9]{0,8}(\d+\.\d+\.\d+)"]),
    Signature("Grafana", ["grafana"], ["grafana"], [r"grafana[^0-9]{0,8}(\d+\.\d+\.\d+)"]),
    Signature("phpMyAdmin", [], ["phpmyadmin"], [r"phpmyadmin\D{0,8}(\d+\.\d+\.\d+)"]),
    Signature("WordPress", [], ["wp-content", "wordpress", "wp-login"],
              [r"wordpress\D{0,6}(\d+\.\d+(?:\.\d+)?)", r'content="WordPress (\d+\.\d+(?:\.\d+)?)']),
    Signature("Drupal", ["drupal"], ["drupal", "x-generator: drupal"],
              [r"drupal[ /]?(\d+)"]),
    Signature("Webmin", [], ["webmin"], [r"webmin[^0-9]{0,6}(\d+\.\d+)"]),
    Signature("PHP", ["php/"], [], [r"php/(\d+\.\d+\.\d+)"]),
    # ManageEngine Applications Manager hides its version on "/"; the build
    # number leaks on the login page (/index.do -> "Applications Manager (Build No:14710)").
    Signature("ManageEngine Applications Manager", [],
              ["applications manager", "appmanager", "jsessionid_apm"],
              [r"applications manager\s*\(build\s*no\.?\s*:?\s*(\d+)\)",
               r"build\s*no\.?\s*:?\s*(\d+)"],
              probe_paths=["/index.do", "/webclient/common/jsp/home.jsp"],
              note="ManageEngine Applications Manager — build number maps to known RCEs (EDB)"),
    Signature("ManageEngine", [], ["manageengine", "servicedesk", "opmanager", "adaudit"],
              [r"build\s*no\.?\s*:?\s*(\d+)"], probe_paths=["/index.do"],
              note="ManageEngine console — match exact product+build to CVE/exploit"),
]

# Server-header product parsers (authoritative when present)
_SERVER_PARSERS = [
    (re.compile(r"apache/(\d+\.\d+\.\d+)", re.I), "Apache httpd"),
    (re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.I), "nginx"),
    (re.compile(r"microsoft-iis/(\d+\.\d+)", re.I), "Microsoft IIS"),
    (re.compile(r"jetty[/(]+(\d+\.\d+\.\d+)", re.I), "Jetty"),
    (re.compile(r"lighttpd/(\d+\.\d+\.\d+)", re.I), "lighttpd"),
    (re.compile(r"openssh[_/](\d+\.\d+[p0-9]*)", re.I), "OpenSSH"),
]


def parse_server_header(server: str) -> tuple[str, str] | None:
    for rx, product in _SERVER_PARSERS:
        m = rx.search(server or "")
        if m:
            return product, m.group(1)
    return None
