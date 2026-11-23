"""Command line.

    os-audit check session.json          one session: prints the verdict and its proof; exit code 1 when the agent obeyed
    os-audit reproduce <archive|folder>  every figure of the paper, from a benchmark's recorded runs
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, audit
from .reproduce import report, show


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="os-audit", description="Did the agent act on a text that was never its owner's?")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="judge one recorded session")
    check.add_argument("session", help='JSON file: {"request": "...", "calls": [{"tool": "...", "args": {...}, "result": "..."}], "hidden_text": "..."}')
    rep = sub.add_parser("reproduce", help="reproduce the paper's figures on a benchmark's recorded runs")
    rep.add_argument("path", help="a GitHub archive (.tar.gz) or an unpacked folder of AgentDojo or AgentDyn")
    args = parser.parse_args(argv)
    if args.command == "check":
        with open(args.session, encoding="utf-8") as fh:
            s = json.load(fh)
        verdict = audit(s.get("request", ""), s.get("calls") or [], s.get("hidden_text", ""))
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
        return 1 if verdict.obeyed else 0
    show(report(args.path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
