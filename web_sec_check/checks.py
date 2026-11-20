"""Pure checks: they take data collected by the scanner and return Findings.

Keeping them free of network code makes every rule unit-testable.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .model import Finding

HSTS_MIN = 15552000  # 180 days, the minimum for the HSTS preload list


def _h(headers: dict[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


# ------------------------------------------------------------- TLS ---

def check_protocols(protocols: dict[str, bool | None]) -> list[Finding]:
    """protocols maps 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3' to True
    (accepted), False (refused) or None (could not be tested locally)."""
    out = []
    legacy = [p for p in ("TLSv1", "TLSv1.1") if protocols.get(p)]
    untested = [p for p in ("TLSv1", "TLSv1.1") if protocols.get(p) is None]
    if legacy:
        out.append(Finding("TLS-LEGACY", "TLS", "FAIL", "high", "Legacy TLS versions accepted",
                           ", ".join(legacy),
                           "Disable TLS 1.0 and 1.1. Nginx: ssl_protocols TLSv1.2 TLSv1.3;"))
    elif untested:
        out.append(Finding("TLS-LEGACY", "TLS", "INFO", "info", "Legacy TLS versions not tested",
                           f"local OpenSSL cannot offer {', '.join(untested)}"))
    else:
        out.append(Finding("TLS-LEGACY", "TLS", "PASS", "high", "TLS 1.0 and 1.1 refused"))

    if protocols.get("TLSv1.3"):
        out.append(Finding("TLS-13", "TLS", "PASS", "low", "TLS 1.3 supported"))
    elif protocols.get("TLSv1.3") is False:
        out.append(Finding("TLS-13", "TLS", "WARN", "low", "TLS 1.3 not supported", "",
                           "Enable TLS 1.3 (OpenSSL 1.1.1+). It is faster and drops weak ciphers."))
    if protocols.get("TLSv1.2") is False and not protocols.get("TLSv1.3"):
        out.append(Finding("TLS-MODERN", "TLS", "FAIL", "high", "No modern TLS version accepted"))
    return out


WEAK_CIPHER = re.compile(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", re.I)


def check_cipher(cipher: tuple[str, str, int] | None) -> list[Finding]:
    if not cipher:
        return []
    name, version, bits = cipher
    if WEAK_CIPHER.search(name) or (bits and bits < 128):
        return [Finding("TLS-CIPHER", "TLS", "FAIL", "high", "Weak cipher negotiated",
                        f"{name} ({bits} bit)", "Use only AEAD ciphers (AES-GCM, CHACHA20-POLY1305).")]
    fs = version == "TLSv1.3" or "ECDHE" in name or "DHE" in name
    if not fs:
        return [Finding("TLS-CIPHER", "TLS", "WARN", "medium", "Cipher without forward secrecy",
                        f"{name}", "Prefer ECDHE key exchange.")]
    return [Finding("TLS-CIPHER", "TLS", "PASS", "medium", "Strong cipher negotiated", f"{name} ({version}, {bits} bit)")]


# ----------------------------------------------------- Certificate ---

def parse_cert_time(value: str) -> datetime:
    # format used by ssl.getpeercert(): 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _name(rdns) -> dict[str, str]:
    out = {}
    for rdn in rdns or ():
        for k, v in rdn:
            out[k] = v
    return out


def check_certificate(cert: dict | None, verify_error: str | None,
                      now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    out = []
    if verify_error:
        out.append(Finding("CERT-VALID", "Certificate", "FAIL", "high", "Certificate is not trusted",
                           verify_error, "Use a certificate from a public CA (Let's Encrypt is free) "
                           "and serve the full chain."))
    else:
        out.append(Finding("CERT-VALID", "Certificate", "PASS", "high",
                           "Certificate chain and hostname valid"))
    if not cert:
        return out

    subject = _name(cert.get("subject"))
    issuer = _name(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    out.append(Finding("CERT-INFO", "Certificate", "INFO", "info", "Certificate details",
                       f"subject CN={subject.get('commonName', '-')}, issuer={issuer.get('organizationName', issuer.get('commonName', '-'))}, "
                       f"SAN={', '.join(sans[:5]) or '-'}"))

    if "notAfter" in cert:
        expires = parse_cert_time(cert["notAfter"])
        days = (expires - now).days
        when = f"expires {expires:%Y-%m-%d} ({days} days)"
        if days < 0:
            out.append(Finding("CERT-EXPIRY", "Certificate", "FAIL", "high", "Certificate expired", when,
                               "Renew the certificate now and automate renewal (certbot, Caddy)."))
        elif days < 14:
            out.append(Finding("CERT-EXPIRY", "Certificate", "WARN", "high", "Certificate expires soon", when,
                               "Renew it. Check that automatic renewal works."))
        elif days < 30:
            out.append(Finding("CERT-EXPIRY", "Certificate", "WARN", "low", "Certificate expires within 30 days", when,
                               "Make sure automatic renewal is running."))
        else:
            out.append(Finding("CERT-EXPIRY", "Certificate", "PASS", "high", "Certificate not near expiry", when))
    return out


# --------------------------------------------------------- Headers ---

def check_hsts(headers: dict[str, str]) -> Finding:
    v = _h(headers, "Strict-Transport-Security")
    fix = "Strict-Transport-Security: max-age=31536000; includeSubDomains"
    if not v:
        return Finding("HDR-HSTS", "Headers", "FAIL", "high", "HSTS header missing", "", fix)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < HSTS_MIN:
        return Finding("HDR-HSTS", "Headers", "WARN", "high", "HSTS max-age too short",
                       f"max-age={age} (minimum {HSTS_MIN})", fix)
    if "includesubdomains" not in v.lower():
        return Finding("HDR-HSTS", "Headers", "WARN", "low", "HSTS without includeSubDomains", v, fix)
    return Finding("HDR-HSTS", "Headers", "PASS", "high", "HSTS enabled", v)


def check_csp(headers: dict[str, str]) -> Finding:
    v = _h(headers, "Content-Security-Policy")
    if not v:
        ro = _h(headers, "Content-Security-Policy-Report-Only")
        return Finding("HDR-CSP", "Headers", "WARN" if ro else "FAIL", "medium",
                       "CSP only in report-only mode" if ro else "Content-Security-Policy missing", ro or "",
                       "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                       "base-uri 'self'; frame-ancestors 'self'")
    problems = []
    low = v.lower()
    if "'unsafe-inline'" in low and "nonce-" not in low and "strict-dynamic" not in low:
        problems.append("'unsafe-inline'")
    if "'unsafe-eval'" in low:
        problems.append("'unsafe-eval'")
    if re.search(r"(default|script)-src[^;]*\s\*(\s|;|$)", low):
        problems.append("wildcard script source")
    if problems:
        return Finding("HDR-CSP", "Headers", "WARN", "medium", "CSP allows unsafe sources",
                       ", ".join(problems), "Replace inline scripts with nonces or hashes.")
    return Finding("HDR-CSP", "Headers", "PASS", "medium", "Content-Security-Policy set", v[:120])


def check_simple_headers(headers: dict[str, str]) -> list[Finding]:
    out = []
    v = _h(headers, "X-Content-Type-Options")
    if v and v.strip().lower() == "nosniff":
        out.append(Finding("HDR-XCTO", "Headers", "PASS", "medium", "X-Content-Type-Options: nosniff"))
    else:
        out.append(Finding("HDR-XCTO", "Headers", "FAIL", "medium", "X-Content-Type-Options missing", v or "",
                           "X-Content-Type-Options: nosniff"))

    xfo = _h(headers, "X-Frame-Options")
    csp = (_h(headers, "Content-Security-Policy") or "").lower()
    if "frame-ancestors" in csp:
        out.append(Finding("HDR-FRAME", "Headers", "PASS", "medium", "Clickjacking protection (CSP frame-ancestors)"))
    elif xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        out.append(Finding("HDR-FRAME", "Headers", "PASS", "medium", "Clickjacking protection (X-Frame-Options)", xfo))
    else:
        out.append(Finding("HDR-FRAME", "Headers", "FAIL", "medium", "No clickjacking protection", xfo or "",
                           "X-Frame-Options: DENY or CSP frame-ancestors 'self'"))

    rp = _h(headers, "Referrer-Policy")
    if rp and rp.strip().lower() not in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(Finding("HDR-REF", "Headers", "PASS", "low", "Referrer-Policy set", rp))
    else:
        out.append(Finding("HDR-REF", "Headers", "WARN", "low", "Referrer-Policy missing or weak", rp or "",
                           "Referrer-Policy: strict-origin-when-cross-origin"))

    pp = _h(headers, "Permissions-Policy")
    out.append(Finding("HDR-PERM", "Headers", "PASS" if pp else "WARN", "low",
                       "Permissions-Policy set" if pp else "Permissions-Policy missing", (pp or "")[:80],
                       "" if pp else "Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    return out


def check_disclosure(headers: dict[str, str]) -> list[Finding]:
    out = []
    server = _h(headers, "Server")
    if server and re.search(r"\d", server):
        out.append(Finding("INFO-SERVER", "Disclosure", "WARN", "low", "Server version disclosed", server,
                           "Hide the version: nginx 'server_tokens off;', Apache 'ServerTokens Prod'."))
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        v = _h(headers, name)
        if v:
            out.append(Finding(f"INFO-{name.upper()}", "Disclosure", "WARN", "low", f"{name} header disclosed", v,
                               f"Remove the {name} header."))
    if not out:
        out.append(Finding("INFO-SERVER", "Disclosure", "PASS", "low", "No software versions disclosed", server or ""))
    return out


# --------------------------------------------------------- Cookies ---

def check_cookies(set_cookies: list[str]) -> list[Finding]:
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
                 for a in raw.split(";")[1:]}
        missing = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        same = attrs.get("samesite", "").lower()
        if not same:
            missing.append("SameSite")
        elif same == "none" and "secure" not in attrs:
            missing.append("Secure (required with SameSite=None)")
        if missing:
            sev = "medium" if re.search(r"sess|auth|token|sid|jwt|login", name, re.I) else "low"
            out.append(Finding(f"COOKIE-{name}", "Cookies", "WARN", sev, f"Cookie '{name}' missing flags",
                               ", ".join(missing), f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax"))
        else:
            out.append(Finding(f"COOKIE-{name}", "Cookies", "PASS", "low", f"Cookie '{name}' has secure flags"))
    return out


# -------------------------------------------------------- Redirect ---

def check_http_redirect(status: int | None, location: str | None, error: str | None) -> Finding:
    if error:
        return Finding("REDIR-HTTPS", "Redirect", "INFO", "info", "Plain HTTP (port 80) not reachable", error)
    if status in (301, 302, 307, 308) and (location or "").lower().startswith("https://"):
        st = "PASS" if status in (301, 308) else "WARN"
        return Finding("REDIR-HTTPS", "Redirect", st, "medium",
                       "HTTP redirects to HTTPS" + ("" if st == "PASS" else " (temporary redirect)"),
                       f"{status} -> {location}", "" if st == "PASS" else "Use a permanent 301/308 redirect.")
    return Finding("REDIR-HTTPS", "Redirect", "FAIL", "medium", "HTTP does not redirect to HTTPS",
                   f"status {status}" + (f", Location: {location}" if location else ""),
                   "Redirect all http:// requests to https:// with 301.")


def check_headers(headers: dict[str, str], set_cookies: list[str]) -> list[Finding]:
    return ([check_hsts(headers), check_csp(headers)] + check_simple_headers(headers)
            + check_disclosure(headers) + check_cookies(set_cookies))
