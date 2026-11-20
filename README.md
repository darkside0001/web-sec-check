# web-sec-check

![tests](https://github.com/darkside0001/web-sec-check/actions/workflows/tests.yml/badge.svg)

A command line tool that grades the HTTPS setup of a web site from **A+ to F**:
TLS versions, cipher, certificate, security headers, cookie flags, version
leaks and the HTTP to HTTPS redirect. Each problem comes with the line of
config that fixes it.

I use it after deploying a site behind Nginx or Caddy, and in CI to stop a
release that drops a security header. Python standard library only.

```
$ web-sec-check https://localhost:8443/        # local test server with a bad config
web-sec-check  https://localhost:8443/
Grade: F   Score: 56/100   HTTP status: 200

== Certificate ==
[FAIL] Certificate is not trusted: unable to get local issuer certificate
       fix: Use a certificate from a public CA (Let's Encrypt is free) and serve the full chain.
[PASS] Certificate not near expiry: expires 2027-01-19 (59 days)

== Headers ==
[WARN] HSTS max-age too short: max-age=3600 (minimum 15552000)
       fix: Strict-Transport-Security: max-age=31536000; includeSubDomains
[WARN] CSP allows unsafe sources: 'unsafe-inline', 'unsafe-eval'
       fix: Replace inline scripts with nonces or hashes.
[FAIL] X-Content-Type-Options missing
       fix: X-Content-Type-Options: nosniff
...
== Cookies ==
[WARN] Cookie 'PHPSESSID' missing flags: Secure, HttpOnly, SameSite
       fix: Set-Cookie: PHPSESSID=...; Secure; HttpOnly; SameSite=Lax
```

Full example reports for a badly and a well configured server (both are the
local test servers from `tests/`): [bad](examples/bad-site.txt),
[good](examples/good-site.txt), [Markdown](examples/report.md), [JSON](examples/report.json).

## What it checks

| Area | Check | Severity |
|------|-------|----------|
| TLS | TLS 1.0 / 1.1 accepted (tested with a real handshake for each version) | high |
| TLS | TLS 1.3 supported | low |
| TLS | negotiated cipher: weak (RC4, 3DES, NULL, EXPORT) or without forward secrecy | high / medium |
| Certificate | chain trusted and hostname matches | high |
| Certificate | expired, expires in < 14 days, < 30 days | high / low |
| Headers | `Strict-Transport-Security` present, `max-age` >= 180 days, `includeSubDomains` | high |
| Headers | `Content-Security-Policy` present, no `unsafe-inline` / `unsafe-eval` / `*` scripts | medium |
| Headers | `X-Content-Type-Options: nosniff` | medium |
| Headers | clickjacking: `X-Frame-Options` or CSP `frame-ancestors` | medium |
| Headers | `Referrer-Policy`, `Permissions-Policy` | low |
| Disclosure | version in `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` | low |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` (higher severity for session cookies) | medium / low |
| Redirect | `http://` answers with a permanent redirect to `https://` | medium |

### Grading

The score starts at 100. A failed check costs 15 / 6 / 2 points (high / medium
/ low), a warning costs half. Then:

- 95+ is **A+**, 85+ **A**, 70+ **B**, 55+ **C**, 40+ **D**, below that **F**
- an untrusted or expired certificate is always **F** (browsers block the page)
- accepting TLS 1.0 or 1.1 caps the grade at **B**, the same rule SSL Labs uses

## Install

```bash
git clone https://github.com/darkside0001/web-sec-check.git
cd web-sec-check
pip install .
# or without installing:
python3 -m web_sec_check example.com
```

Requires Python 3.9+.

## Usage

```bash
web-sec-check example.com
web-sec-check https://example.com:8443/login
web-sec-check -i sites.txt -f markdown -o report.md     # many sites, one report
web-sec-check example.com -f json | jq '.[0].findings[] | select(.status=="FAIL")'
web-sec-check intranet.local --ca-file corp-ca.pem      # internal PKI
web-sec-check example.com --fail-under A                # exit 1 below A, for CI
```

### In a GitHub Actions pipeline

```yaml
- run: pip install git+https://github.com/darkside0001/web-sec-check.git
- run: web-sec-check ${{ vars.SITE_URL }} --fail-under A
```

Exit codes: `0` ok, `1` a site graded below `--fail-under`, `2` a site could
not be reached.

## How it works

- `scanner.py` does the network part: one verified TLS handshake, one
  handshake per TLS version with the client pinned to that version, a `GET` of
  the page (following redirects on the same host) and a `GET` on port 80.
- If the certificate does not verify, the tool connects again without
  verification so it can still show expiry and subject.
- `checks.py` holds every rule as a pure function of headers and certificate
  data, so each rule is unit tested without a network.
- If the local OpenSSL cannot offer TLS 1.0/1.1 (many modern distros), those
  versions are reported as "not tested" instead of guessing.

## Tests

```bash
pip install -e .[dev]
pytest -q
# 15 passed
```

The end-to-end tests create a throwaway CA with `openssl`, start local HTTPS
servers with good and bad headers, and scan them.

## Scope

The tool sends the same requests as a browser visit, but only scan sites you
own or have permission to test. It does not replace a full TLS scanner such as
testssl.sh: it checks the settings that are most often wrong on small
deployments.

## License

MIT
