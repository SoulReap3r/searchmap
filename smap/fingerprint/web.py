"""Active fingerprinting of web services.

Recovers the real product + version that nmap's banner misses (the Tomcat under
a ManageEngine console). Evidence is recorded on the Service so the report can
show *why* a product was claimed, and conflicting signals are preserved rather
than silently overwritten.
"""
from __future__ import annotations
import re
import socket
import ssl
import urllib.request

from ..core.models import Service
from . import signatures

TIMEOUT = 6
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 7001, 9090, 5000, 3000, 8081, 10000}


def is_web(svc: Service) -> bool:
    n = svc.name.lower()
    return (svc.port in WEB_PORTS or "http" in n or svc.tunnel == "ssl"
            or n in ("https-alt", "wsmans", "sun-answerbook"))


def is_tls(svc: Service) -> bool:
    n = svc.name.lower()
    return svc.tunnel == "ssl" or "https" in n or "ssl" in n or svc.port in (443, 8443, 8081)


def _url(svc: Service) -> str:
    scheme = "https" if is_tls(svc) else "http"
    return f"{scheme}://{svc.host_ip}:{svc.port}"


def _http_get(url: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "sploitmap"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return dict(r.headers), r.read(65536), r.status
    except urllib.error.HTTPError as e:
        try:
            return dict(e.headers), (e.read(65536) if hasattr(e, "read") else b""), e.code
        except Exception:
            return {}, b"", getattr(e, "code", 0)
    except Exception:
        return {}, b"", 0


def _tls_cert_cn(host: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
    except Exception:
        return ""
    if not der:
        return ""
    # cheap CN extraction from the DER without a crypto dep: find the CN OID
    # (55 04 03) and read the following printable string
    m = re.search(rb"\x55\x04\x03.(.)([ -~]{1,64})", der)
    if m:
        try:
            ln = m.group(1)[0]
            return m.group(2)[:ln].decode("latin-1", "replace")
        except Exception:
            return ""
    return ""


GENERIC_PRODUCTS = {"", "appmanager", "httpd", "http", "https-alt", "ssl/https-alt", "unknown"}


def _extract_version(sig, hay: str) -> str:
    for rx in sig.version_re:
        m = re.search(rx, hay, re.I)
        if m:
            return m.group(1)
    return ""


def fingerprint(svc: Service) -> None:
    if not is_web(svc):
        return
    base = _url(svc)
    hdrs, body, code = _http_get(base + "/")
    if not hdrs and not body and code == 0:
        return
    text = body.decode("latin-1", "replace")
    title_m = re.search(r"<title[^>]*>([^<]{1,160})</title>", text, re.I)
    title = title_m.group(1).strip() if title_m else ""
    server = hdrs.get("Server", "")
    powered = hdrs.get("X-Powered-By", "")
    cookie = hdrs.get("Set-Cookie", "")
    svc.fingerprints.append({k: v for k, v in {
        "source": "http", "url": base + "/", "status": code, "server": server,
        "title": title, "x-powered-by": powered}.items() if v})

    if is_tls(svc):
        cn = _tls_cert_cn(svc.host_ip, svc.port)
        if cn:
            svc.fingerprints.append({"source": "tls-cert", "cn": cn})

    hay = " ".join([server, title, powered, cookie, text[:8000]]).lower()

    # which signatures match on the landing page?
    matched_sigs = [s for s in signatures.SIGNATURES
                    if any(t in server.lower() for t in s.server_tokens)
                    or any(t in hay for t in s.body_tokens)]

    # DEEP PROBE: many apps (ManageEngine, CMS login pages) hide their version
    # on "/" but leak it on a login/version page. Fetch those and fold them in.
    probe_paths: list[str] = []
    for s in matched_sigs:
        for p in s.probe_paths:
            if p not in probe_paths:
                probe_paths.append(p)
    for p in probe_paths[:4]:
        ph, pb, pc = _http_get(base + p)
        if pb:
            hay += " " + pb.decode("latin-1", "replace").lower()
            svc.fingerprints.append({"source": "probe", "url": base + p, "status": pc})

    parsed = signatures.parse_server_header(server)
    matched = [(s.product, _extract_version(s, hay)) for s in matched_sigs]
    for s in matched_sigs:
        if s.note and s.note not in svc.notes:
            svc.notes.append(s.note)

    chosen = parsed or next((m for m in matched if m[1]), None) or (matched[0] if matched else None)
    if chosen:
        prod, ver = chosen
        generic = (svc.product or "").lower() in GENERIC_PRODUCTS
        if generic or (not svc.product):
            svc.product = prod or svc.product
            if ver:
                svc.version = ver
            svc.cpe_source = "active-fingerprint"
        elif prod.lower() not in svc.product.lower() and svc.product.lower() not in prod.lower():
            svc.notes.append(f"fingerprint also suggests {prod} {ver}".rstrip() +
                             f" (nmap said {svc.product} {svc.version})".rstrip())
        elif not svc.version and ver:
            svc.version = ver
        if ver and re.fullmatch(r"\d{4,6}", ver):
            svc.notes.append(f"Build No: {ver} — map this build to the product's known exploits")

    extra = [p for p, _ in matched if p and p.lower() not in (svc.product or "").lower()]
    for p in dict.fromkeys(extra):
        svc.notes.append(f"also fingerprinted: {p}")
