from __future__ import annotations

import json

from .model import grade, score
from .scanner import ScanResult

ICON = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL", "INFO": "INFO"}
COLOR = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m", "INFO": "\033[2m"}
RESET = "\033[0m"


def to_text(res: ScanResult, color: bool = False) -> str:
    t = res.target
    lines = [f"web-sec-check  https://{t.host}{'' if t.port == 443 else f':{t.port}'}{t.path}"]
    if res.error:
        return "\n".join(lines + [f"ERROR: {res.error}", ""])
    lines.append(f"Grade: {grade(res.findings)}   Score: {score(res.findings)}/100   HTTP status: {res.status}")
    cat = None
    for f in res.findings:
        if f.category != cat:
            cat = f.category
            lines += ["", f"== {cat} =="]
        tag = f"[{f.status}]"
        if color:
            tag = f"{COLOR[f.status]}{tag}{RESET}"
        lines.append(f"{tag} {f.title}" + (f": {f.detail}" if f.detail else ""))
        if f.fix and f.status in ("FAIL", "WARN"):
            lines.append(f"       fix: {f.fix}")
    return "\n".join(lines) + "\n"


def to_dict(res: ScanResult) -> dict:
    t = res.target
    d = {"target": f"https://{t.host}:{t.port}{t.path}", "error": res.error}
    if not res.error:
        d.update(grade=grade(res.findings), score=score(res.findings), status=res.status,
                 final_url=res.final_url, findings=[f.to_dict() for f in res.findings],
                 headers=res.headers)
    return d


def to_json(results: list[ScanResult]) -> str:
    return json.dumps([to_dict(r) for r in results], indent=2)


def to_markdown(results: list[ScanResult]) -> str:
    out = ["# Web security check", "", "| Site | Grade | Score | Fails | Warnings |", "|---|---|---|---|---|"]
    for r in results:
        name = f"{r.target.host}:{r.target.port}" if r.target.port != 443 else r.target.host
        if r.error:
            out.append(f"| {name} | error | - | - | - |")
            continue
        fails = sum(f.status == "FAIL" for f in r.findings)
        warns = sum(f.status == "WARN" for f in r.findings)
        out.append(f"| {name} | **{grade(r.findings)}** | {score(r.findings)} | {fails} | {warns} |")
    for r in results:
        if r.error:
            continue
        out += ["", f"## {r.target.host}", "", "| Status | Check | Detail | Fix |", "|---|---|---|---|"]
        order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3}
        for f in sorted(r.findings, key=lambda f: order[f.status]):
            esc = lambda s: s.replace("|", "\\|")
            out.append(f"| {f.status} | {esc(f.title)} | {esc(f.detail)} | {esc(f.fix) if f.status in ('FAIL', 'WARN') else ''} |")
    return "\n".join(out) + "\n"
