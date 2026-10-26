"""Command line interface — stdlib only.

That constraint is load bearing: `skillvet` is a console script, so anything it
imports at module scope must be an install dependency. Keeping the CLI on the
standard library means the first command a visitor runs cannot fail on a missing
optional extra (a bug that shipped in another project of mine).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .demo import write_demo
from .model import Severity
from .render import render_report, render_rules, use_color
from .rules import RULES
from .sarif import dumps as sarif_dumps
from .scan import scan_path

EPILOG = "examples:\n  skillvet demo && skillvet scan ./demo-workspace\n  skillvet scan . --sarif results.sarif --fail-on high\n"


def force_utf8_stdio() -> None:
    """Make stdout/stderr UTF-8 before anything is printed.

    The whole point of skillvet is printing the hostile characters it finds —
    zero-width spaces, bidi overrides, invisible separators. On a Windows
    console the default encoding is cp1252 (or cp936), none of which can encode
    U+200B, so `skillvet demo` died with
    ``UnicodeEncodeError: 'charmap' codec can't encode character '\\u200b'``
    for every Windows user. That is the first command a new visitor runs.

    Reconfiguring up front fixes it without changing a single byte of output on
    platforms that were already UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # e.g. a plain StringIO in some hosts
            continue
        current = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if current == "utf8":
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # stream already detached or closed
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillvet",
        description="Static security review for AI agent skills and MCP configs.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"skillvet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a directory (default: current)")
    scan.add_argument("path", nargs="?", default=".", help="directory to review")
    scan.add_argument(
        "--min-severity",
        default=Severity.INFO,
        choices=Severity.ORDER,
        help="hide findings below this level (default: info)",
    )
    scan.add_argument("--json", action="store_true", help="emit the report as JSON")
    scan.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 to FILE ('-' for stdout)")
    scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="exit 1 when a finding at or above this level exists (CI gate)",
    )
    scan.add_argument(
        "--max-bytes", type=int, default=512 * 1024, help="skip files larger than N bytes"
    )
    scan.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colour output"
    )

    rules = sub.add_parser("rules", help="list the rule set")
    rules.add_argument("--json", action="store_true")
    rules.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colour output"
    )

    mcp_cmd = sub.add_parser("mcp", help="MCP server helpers")
    mcp_cmd.add_argument(
        "--check", action="store_true", help="list the registered MCP tools (needs the mcp extra)"
    )

    demo = sub.add_parser("demo", help="write a synthetic workspace and review it")
    demo.add_argument("path", nargs="?", default="demo-workspace", help="where to write it")
    demo.add_argument("--force", action="store_true", help="overwrite existing files")
    demo.add_argument("--no-scan", action="store_true", help="write files, do not scan")
    demo.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colour output"
    )
    return parser


def _cmd_scan(args) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    report = scan_path(root, max_bytes=args.max_bytes)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    if args.sarif:
        text = sarif_dumps(report.filtered(args.min_severity), version=__version__)
        if args.sarif == "-":
            print(text)
        else:
            Path(args.sarif).write_text(text, encoding="utf-8")
    if not args.json and args.sarif != "-":
        print(
            render_report(
                report,
                min_severity=args.min_severity,
                color=use_color(args.color),
            ),
            end="",
        )

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        keep = set(Severity.at_least(threshold))
        hits = [f for f in report.findings if f.severity in keep]
        if hits:
            print(
                f"fail-on {threshold}: {len(hits)} finding(s) at or above that level",
                file=sys.stderr,
            )
            return 1
    return 0


def _cmd_rules(args) -> int:
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "title": r.title,
                        "severity": r.severity,
                        "category": r.category,
                        "capability": r.capability,
                        "why": r.why,
                    }
                    for r in sorted(RULES, key=lambda x: x.id)
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    print(render_rules(RULES, color=use_color(args.color)), end="")
    return 0


def _cmd_mcp(args) -> int:
    if not args.check:
        print("use: skillvet mcp --check")
        return 0
    # Imported lazily on purpose: `mcp` lives in an optional extra, and this
    # module must stay importable with a plain `pip install skillvet`.
    try:
        from .mcp_server import tool_manifest
    except ImportError as exc:
        print(
            f"error: the MCP server needs the optional extra — "
            f'pip install "skillvet[mcp]" ({exc})',
            file=sys.stderr,
        )
        return 2
    tools = tool_manifest()
    print(f"skillvet MCP server — {len(tools)} tools")
    for tool in tools:
        print(f"  {tool['name']}")
    return 0


def _cmd_demo(args) -> int:
    try:
        root = write_demo(args.path, force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(list(root.iterdir()))} top-level entries to {root}")
    if args.no_scan:
        return 0
    report = scan_path(root)
    print(
        render_report(report, min_severity=Severity.INFO, color=use_color(args.color)),
        end="",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"scan": _cmd_scan, "rules": _cmd_rules, "demo": _cmd_demo, "mcp": _cmd_mcp}
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
