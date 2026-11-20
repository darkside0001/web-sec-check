from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .model import grade
from .report import to_json, to_markdown, to_text
from .scanner import Target, scan

GRADES = ["A+", "A", "B", "C", "D", "F"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="web-sec-check",
        description="Check TLS, certificate, security headers and cookies of web sites you own.")
    p.add_argument("targets", nargs="*", help="host or https:// URL, e.g. example.com or https://example.com:8443/login")
    p.add_argument("-i", "--input", help="file with one target per line")
    p.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--no-http", action="store_true", help="skip the http:// to https:// redirect check")
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--ca-file", help="extra CA bundle to trust (internal PKI)")
    p.add_argument("--fail-under", choices=GRADES, help="exit 1 if any site grades below this (for CI)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    raw = list(args.targets)
    if args.input:
        raw += [l.strip() for l in Path(args.input).read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not raw:
        p.error("give at least one target")
    try:
        targets = [Target.parse(x) for x in raw]
    except ValueError as e:
        p.error(str(e))

    results = [scan(t, args.timeout, not args.no_http, args.http_port, args.ca_file) for t in targets]

    if args.format == "json":
        text = to_json(results)
    elif args.format == "markdown":
        text = to_markdown(results)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        text = "\n".join(to_text(r, color) for r in results)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if any(r.error for r in results):
        return 2
    if args.fail_under:
        limit = GRADES.index(args.fail_under)
        if any(GRADES.index(grade(r.findings)) > limit for r in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
