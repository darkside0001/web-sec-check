"""End-to-end scan against a local HTTPS server with a throwaway CA."""

import http.server
import shutil
import ssl
import subprocess
import threading

import pytest

from web_sec_check.cli import main
from web_sec_check.model import grade
from web_sec_check.scanner import Target, scan

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def make_pki(d):
    def run(*a):
        subprocess.run(a, check=True, capture_output=True, cwd=d)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "2", "-subj", "/CN=Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost")
    (d / "ext.cnf").write_text(
        "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
    run("openssl", "x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "srv.pem", "-days", "60", "-extfile", "ext.cnf")
    return d / "ca.pem", d / "srv.pem", d / "srv.key"


def serve(certfile, keyfile, headers, cookies=()):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            for c in cookies:
                self.send_header("Set-Cookie", c)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("localhost", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_pki(tmp_path_factory.mktemp("pki"))


def test_well_configured_site(pki):
    ca, crt, key = pki
    srv = serve(str(crt), str(key), GOOD_HEADERS, ["sid=1; Secure; HttpOnly; SameSite=Strict"])
    try:
        res = scan(Target("localhost", srv.server_port), timeout=5, check_http=False, ca_file=str(ca))
    finally:
        srv.shutdown()
    by = {f.id: f.status for f in res.findings}
    assert res.error is None and res.status == 200
    assert by["CERT-VALID"] == "PASS" and by["HDR-HSTS"] == "PASS" and by["HDR-CSP"] == "PASS"
    assert by["COOKIE-sid"] == "PASS" and by["TLS-13"] == "PASS"
    assert grade(res.findings) in ("A+", "A")


def test_untrusted_cert_and_missing_headers(pki, capsys):
    ca, crt, key = pki
    srv = serve(str(crt), str(key), {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4"}, ["PHPSESSID=x"])
    try:
        code = main([f"https://localhost:{srv.server_port}/", "--no-http", "--fail-under", "B", "--timeout", "5"])
    finally:
        srv.shutdown()
    out = capsys.readouterr().out
    assert code == 1
    assert "Grade: F" in out
    assert "Certificate is not trusted" in out
    assert "HSTS header missing" in out and "Server version disclosed" in out
    assert "expires" in out  # cert details still shown without verification


def test_connection_refused():
    res = scan(Target("localhost", 1), timeout=2, check_http=False)
    assert res.error and "failed" in res.error
