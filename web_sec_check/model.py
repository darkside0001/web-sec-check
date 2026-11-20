from __future__ import annotations

from dataclasses import asdict, dataclass

WEIGHT = {"high": 15, "medium": 6, "low": 2, "info": 0}


@dataclass
class Finding:
    id: str
    category: str      # TLS | Certificate | Headers | Cookies | Disclosure | Redirect
    status: str        # PASS | WARN | FAIL | INFO
    severity: str      # high | medium | low | info
    title: str
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def score(findings: list[Finding]) -> int:
    lost = 0.0
    for f in findings:
        if f.status == "FAIL":
            lost += WEIGHT[f.severity]
        elif f.status == "WARN":
            lost += WEIGHT[f.severity] / 2
    return max(0, round(100 - lost))


def grade(findings: list[Finding]) -> str:
    """A+ to F from the score, with two caps: an invalid or expired
    certificate is always F (browsers block the site), and accepting
    TLS 1.0/1.1 caps the grade at B, like SSL Labs does."""
    failed = {f.id for f in findings if f.status == "FAIL"}
    if failed & {"CERT-VALID", "CERT-EXPIRY"}:
        return "F"
    s = score(findings)
    g = "F"
    for limit, letter in ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D")):
        if s >= limit:
            g = letter
            break
    if "TLS-LEGACY" in failed and g in ("A+", "A"):
        g = "B"
    return g
