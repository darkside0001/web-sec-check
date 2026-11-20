"""Network side: TLS handshakes and HTTP requests. Only the Python standard
library is used. Every request is a normal GET, the same as a browser visit."""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import tempfile
import warnings
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .checks import (check_certificate, check_cipher, check_headers, check_http_redirect,
                     check_protocols)
from .model import Finding

UA = f"web-sec-check/{__version__} (+https://github.com/darkside0001/web-sec-check)"

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    _TLS10, _TLS11 = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1

PROTOCOLS = {
    "TLSv1": _TLS10,
    "TLSv1.1": _TLS11,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


@dataclass
class Target:
    host: str
    port: int = 443
    path: str = "/"

    @classmethod
    def parse(cls, value: str) -> "Target":
        if "://" not in value:
            value = "https://" + value
        u = urlsplit(value)
        if u.scheme != "https":
            raise ValueError("only https:// targets are supported (the HTTP redirect is checked automatically)")
        if not u.hostname:
            raise ValueError(f"no host in {value!r}")
        return cls(u.hostname, u.port or 443, (u.path or "/") + (f"?{u.query}" if u.query else ""))


@dataclass
class ScanResult:
    target: Target
    findings: list[Finding] = field(default_factory=list)
    status: int | None = None
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None


def _decode_der(der: bytes) -> dict:
    """Decode a certificate we could not verify, so expiry etc. can still be
    shown. Uses CPython's internal decoder; returns {} if unavailable."""
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if not decoder or not der:
        return {}
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        return decoder(path)
    except Exception:
        return {}
    finally:
        os.unlink(path)


def tls_handshake(t: Target, timeout: float, ca_file: str | None = None):
    """Returns (cert dict, verify error or None, cipher, version)."""
    ctx = ssl.create_default_context(cafile=ca_file)
    try:
        with socket.create_connection((t.host, t.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=t.host) as tls:
                return tls.getpeercert(), None, tls.cipher(), tls.version()
    except ssl.SSLCertVerificationError as e:
        err = e.verify_message or str(e)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((t.host, t.port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=t.host) as tls:
            return _decode_der(tls.getpeercert(binary_form=True)), err, tls.cipher(), tls.version()


def _legacy_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
    """A client context that offers exactly one TLS version, or None if the
    local OpenSSL build refuses to offer it (common for TLS 1.0/1.1)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():  # TLS 1.0/1.1 are deprecated: that is what we test for
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        if version < ssl.TLSVersion.TLSv1_2:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return ctx


def probe_protocol(t: Target, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """True if the server completes a handshake with exactly this version,
    False if it refuses, None if this machine cannot test it."""
    ctx = _legacy_context(version)
    if ctx is None:
        return None
    try:
        with socket.create_connection((t.host, t.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=t.host) as tls:
                return tls.version() is not None
    except ssl.SSLError as e:
        if "no protocols available" in str(e).lower():
            return None
        return False
    except OSError:
        return False


def fetch_https(t: Target, timeout: float, verify: bool, ca_file: str | None = None, max_redirects: int = 5):
    """GET the page, following redirects on the same host. Returns
    (status, headers dict, list of Set-Cookie values, final URL)."""
    if verify:
        ctx = ssl.create_default_context(cafile=ca_file)
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    path, cookies = t.path, []
    for _ in range(max_redirects + 1):
        conn = http.client.HTTPSConnection(t.host, t.port, timeout=timeout, context=ctx)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
            resp = conn.getresponse()
            headers = {k: v for k, v in resp.getheaders()}
            cookies.extend(resp.msg.get_all("Set-Cookie") or [])
            resp.read(65536)
        finally:
            conn.close()
        url = f"https://{t.host}{'' if t.port == 443 else f':{t.port}'}{path}"
        loc = headers.get("Location") or headers.get("location")
        if resp.status in (301, 302, 303, 307, 308) and loc:
            nxt = urlsplit(urljoin(url, loc))
            if nxt.scheme == "https" and nxt.hostname == t.host and (nxt.port or 443) == t.port:
                path = (nxt.path or "/") + (f"?{nxt.query}" if nxt.query else "")
                continue
        return resp.status, headers, cookies, url
    return resp.status, headers, cookies, url


def fetch_http_redirect(t: Target, timeout: float, port: int = 80):
    conn = http.client.HTTPConnection(t.host, port, timeout=timeout)
    try:
        conn.request("GET", t.path, headers={"User-Agent": UA})
        resp = conn.getresponse()
        loc = resp.getheader("Location")
        resp.read(1024)
        return resp.status, loc, None
    except (OSError, http.client.HTTPException) as e:
        return None, None, f"{type(e).__name__}: {e}"
    finally:
        conn.close()


def scan(t: Target, timeout: float = 8.0, check_http: bool = True, http_port: int = 80,
         ca_file: str | None = None) -> ScanResult:
    res = ScanResult(t)
    try:
        cert, verr, cipher, version = tls_handshake(t, timeout, ca_file)
    except (OSError, ssl.SSLError) as e:
        res.error = f"TLS connection to {t.host}:{t.port} failed: {e}"
        return res

    protocols = {name: probe_protocol(t, v, timeout) for name, v in PROTOCOLS.items()}
    if version in protocols and protocols[version] is None:
        protocols[version] = True
    res.findings += check_protocols(protocols)
    res.findings += check_cipher(cipher)
    res.findings += check_certificate(cert, verr)

    try:
        status, headers, cookies, url = fetch_https(t, timeout, verify=verr is None, ca_file=ca_file)
        res.status, res.headers, res.final_url = status, headers, url
        res.findings += check_headers(headers, cookies)
    except (OSError, http.client.HTTPException) as e:
        res.findings.append(Finding("HTTP-FETCH", "Headers", "INFO", "info", "Could not fetch the page", str(e)))

    if check_http:
        s, loc, err = fetch_http_redirect(t, timeout, http_port)
        res.findings.append(check_http_redirect(s, loc, err))
    return res
