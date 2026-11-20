from datetime import datetime, timezone

from web_sec_check.checks import (check_certificate, check_cipher, check_cookies, check_csp,
                                  check_disclosure, check_hsts, check_http_redirect,
                                  check_protocols, check_simple_headers)
from web_sec_check.model import Finding, grade, score

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def st(f):
    return f.status


def test_hsts():
    assert st(check_hsts({})) == "FAIL"
    assert st(check_hsts({"Strict-Transport-Security": "max-age=300"})) == "WARN"
    assert st(check_hsts({"strict-transport-security": "max-age=31536000"})) == "WARN"
    assert st(check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})) == "PASS"


def test_csp():
    assert st(check_csp({})) == "FAIL"
    assert st(check_csp({"Content-Security-Policy-Report-Only": "default-src 'self'"})) == "WARN"
    assert st(check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"})) == "WARN"
    assert st(check_csp({"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'"})) == "PASS"
    assert st(check_csp({"Content-Security-Policy": "default-src *"})) == "WARN"
    assert st(check_csp({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})) == "PASS"


def test_simple_headers_missing_and_present():
    missing = {f.id: f.status for f in check_simple_headers({})}
    assert missing == {"HDR-XCTO": "FAIL", "HDR-FRAME": "FAIL", "HDR-REF": "WARN", "HDR-PERM": "WARN"}
    good = {f.id: f.status for f in check_simple_headers({
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"})}
    assert set(good.values()) == {"PASS"}


def test_frame_ancestors_counts_as_clickjacking_protection():
    f = {x.id: x for x in check_simple_headers({"Content-Security-Policy": "frame-ancestors 'self'"})}
    assert f["HDR-FRAME"].status == "PASS"


def test_disclosure():
    ids = {f.id: f.status for f in check_disclosure({"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"})}
    assert ids == {"INFO-SERVER": "WARN", "INFO-X-POWERED-BY": "WARN"}
    assert check_disclosure({"Server": "nginx"})[0].status == "PASS"


def test_cookies():
    f = check_cookies(["PHPSESSID=abc; path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"])
    assert f[0].status == "WARN" and f[0].severity == "medium"
    assert "Secure" in f[0].detail and "HttpOnly" in f[0].detail and "SameSite" in f[0].detail
    assert f[1].status == "PASS"
    none_without_secure = check_cookies(["a=1; HttpOnly; SameSite=None"])[0]
    assert "required with SameSite=None" in none_without_secure.detail


def test_protocols():
    bad = {f.id: f.status for f in check_protocols({"TLSv1": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": False})}
    assert bad == {"TLS-LEGACY": "FAIL", "TLS-13": "WARN"}
    good = {f.id: f.status for f in check_protocols({"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True})}
    assert good == {"TLS-LEGACY": "PASS", "TLS-13": "PASS"}
    untested = {f.id: f.status for f in check_protocols({"TLSv1": None, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True})}
    assert untested["TLS-LEGACY"] == "INFO"


def test_cipher():
    assert check_cipher(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))[0].status == "PASS"
    assert check_cipher(("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))[0].status == "PASS"
    assert check_cipher(("AES128-SHA", "TLSv1.2", 128))[0].status == "WARN"
    assert check_cipher(("DES-CBC3-SHA", "TLSv1", 112))[0].status == "FAIL"


def cert(not_after):
    return {"subject": ((("commonName", "example.com"),),), "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"),), "notAfter": not_after}


def test_certificate_expiry():
    def exp(na):
        return {f.id: f for f in check_certificate(cert(na), None, NOW)}["CERT-EXPIRY"]
    assert exp("Nov 10 00:00:00 2026 GMT").status == "FAIL"
    assert exp("Nov 25 00:00:00 2026 GMT").status == "WARN" and exp("Nov 25 00:00:00 2026 GMT").severity == "high"
    assert exp("Dec 10 00:00:00 2026 GMT").severity == "low"
    assert exp("Feb 20 00:00:00 2027 GMT").status == "PASS"


def test_untrusted_certificate():
    f = check_certificate({}, "self-signed certificate", NOW)
    assert f[0].id == "CERT-VALID" and f[0].status == "FAIL"


def test_http_redirect():
    assert check_http_redirect(301, "https://example.com/", None).status == "PASS"
    assert check_http_redirect(302, "https://example.com/", None).status == "WARN"
    assert check_http_redirect(200, None, None).status == "FAIL"
    assert check_http_redirect(None, None, "ConnectionRefusedError").status == "INFO"


def test_grade():
    ok = [Finding("X", "Headers", "PASS", "high", "")]
    assert grade(ok) == "A+" and score(ok) == 100
    assert grade(ok + [Finding("CERT-VALID", "Certificate", "FAIL", "high", "")]) == "F"
    assert grade(ok + [Finding("TLS-LEGACY", "TLS", "FAIL", "high", "")]) == "B"
    many = [Finding(f"H{i}", "Headers", "FAIL", "medium", "") for i in range(5)]
    assert score(many) == 70 and grade(many) == "B"
