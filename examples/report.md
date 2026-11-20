# Web security check

| Site | Grade | Score | Fails | Warnings |
|---|---|---|---|---|
| localhost:8443 | **F** | 56 | 3 | 7 |
| localhost:9443 | **A+** | 99 | 0 | 1 |

## localhost

| Status | Check | Detail | Fix |
|---|---|---|---|
| FAIL | Certificate is not trusted | unable to get local issuer certificate | Use a certificate from a public CA (Let's Encrypt is free) and serve the full chain. |
| FAIL | X-Content-Type-Options missing |  | X-Content-Type-Options: nosniff |
| FAIL | No clickjacking protection |  | X-Frame-Options: DENY or CSP frame-ancestors 'self' |
| WARN | HSTS max-age too short | max-age=3600 (minimum 15552000) | Strict-Transport-Security: max-age=31536000; includeSubDomains |
| WARN | CSP allows unsafe sources | 'unsafe-inline', 'unsafe-eval' | Replace inline scripts with nonces or hashes. |
| WARN | Referrer-Policy missing or weak |  | Referrer-Policy: strict-origin-when-cross-origin |
| WARN | Permissions-Policy missing |  | Permissions-Policy: camera=(), microphone=(), geolocation=() |
| WARN | Server version disclosed | nginx/1.18.0 (Ubuntu) | Hide the version: nginx 'server_tokens off;', Apache 'ServerTokens Prod'. |
| WARN | X-Powered-By header disclosed | PHP/7.4.3 | Remove the X-Powered-By header. |
| WARN | Cookie 'PHPSESSID' missing flags | Secure, HttpOnly, SameSite | Set-Cookie: PHPSESSID=...; Secure; HttpOnly; SameSite=Lax |
| PASS | TLS 1.0 and 1.1 refused |  |  |
| PASS | TLS 1.3 supported |  |  |
| PASS | Strong cipher negotiated | TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bit) |  |
| PASS | Certificate not near expiry | expires 2027-01-19 (59 days) |  |
| INFO | Certificate details | subject CN=localhost, issuer=Test CA, SAN=localhost |  |

## localhost

| Status | Check | Detail | Fix |
|---|---|---|---|
| WARN | Server version disclosed | BaseHTTP/0.6 Python/3.13.18 | Hide the version: nginx 'server_tokens off;', Apache 'ServerTokens Prod'. |
| PASS | TLS 1.0 and 1.1 refused |  |  |
| PASS | TLS 1.3 supported |  |  |
| PASS | Strong cipher negotiated | TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bit) |  |
| PASS | Certificate chain and hostname valid |  |  |
| PASS | Certificate not near expiry | expires 2027-01-19 (59 days) |  |
| PASS | HSTS enabled | max-age=31536000; includeSubDomains |  |
| PASS | Content-Security-Policy set | default-src 'self'; frame-ancestors 'none' |  |
| PASS | X-Content-Type-Options: nosniff |  |  |
| PASS | Clickjacking protection (CSP frame-ancestors) |  |  |
| PASS | Referrer-Policy set | strict-origin-when-cross-origin |  |
| PASS | Permissions-Policy set | camera=(), microphone=() |  |
| PASS | Cookie 'sid' has secure flags |  |  |
| INFO | Certificate details | subject CN=localhost, issuer=Test CA, SAN=localhost |  |
