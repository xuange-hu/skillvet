"""MCP server — optional extra (`pip install "skillvet[mcp]"`).

Pinned to mcp>=1.2,<2 on purpose: the 2.x SDK renames FastMCP and moves its
package path, and there is no reason to rewrite working integrations for it.

Context budget is enforced here, not left to the caller: an alert flood from a
big scan is how an agent's context dies, so every text response is capped and
says plainly that it was capped.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import __version__
from .demo import write_demo
from .model import Severity
from .render import render_report
from .rules import RULES, get_rule
from .scan import describe_capability, scan_path

MAX_CHARS = 6000
# Version is advertised in tool output rather than via FastMCP(..., version=...):
# that kwarg is not part of the 1.x constructor contract and raises on some 1.x
# releases. Pinned to mcp>=1.2,<2 because 2.x renames FastMCP -> MCPServer.
mcp = FastMCP("skillvet")


def _budget(text: str, limit: int = MAX_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = text[:limit]
    dropped = len(text) - limit
    return f"{head}\n... [{dropped} more characters truncated — narrow the path or use skillvet_scan_json]"


def _resolve(path: str) -> Path:
    p = Path(path or ".").expanduser()
    # Refuse to review the entire filesystem from an MCP call.
    return p.resolve()


@mcp.tool()
def skillvet_scan(path: str = ".", min_severity: str = Severity.INFO, max_chars: int = MAX_CHARS) -> str:
    """Review a directory of agent skills / MCP configs and return a text report.

    Args:
        path: directory to review (default: current working directory).
        min_severity: one of critical, high, medium, low, info.
        max_chars: hard cap on the returned text (context budget).
    """
    root = _resolve(path)
    if not root.exists():
        return f"error: {root} does not exist"
    report = scan_path(root)
    text = render_report(report, min_severity=Severity.parse(min_severity), color=False)
    return _budget(text, max_chars)


@mcp.tool()
def skillvet_scan_json(path: str = ".", min_severity: str = Severity.INFO, max_findings: int = 50) -> str:
    """Review a directory and return structured findings as JSON.

    Same rules as skillvet_scan, machine-readable. Every finding includes
    file, line, rule_id, severity and the original snippet.
    """
    root = _resolve(path)
    if not root.exists():
        return json.dumps({"error": f"{root} does not exist"})
    report = scan_path(root)
    findings = [f.to_dict() for f in report.filtered(Severity.parse(min_severity))]
    truncated = 0
    if len(findings) > max_findings:
        truncated = len(findings) - max_findings
        findings = findings[:max_findings]
    payload = report.to_dict()
    payload["findings"] = findings
    payload["truncated_findings"] = truncated
    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
def skillvet_capabilities(path: str = ".") -> str:
    """Return the permission table: what the reviewed artifact would be able to do.

    This is the fastest answer to "should I install this?" — it lists capabilities
    (network egress, credential read, persistence, ...) rather than line findings.
    """
    root = _resolve(path)
    if not root.exists():
        return f"error: {root} does not exist"
    report = scan_path(root)
    caps = report.capabilities()
    if not caps:
        return f"skillvet {root}: no capabilities detected in {report.files_scanned()} file(s)."
    lines = [f"skillvet capabilities for {root} (risk {report.risk_score()}/100 {report.grade()})", ""]
    for cap, items in caps.items():
        worst = min(items, key=lambda f: Severity.index(f.severity)).severity
        lines.append(f"  {worst.upper().ljust(9)} {cap.ljust(16)} x{len(items)}  {describe_capability(cap)}")
    lines.append("")
    lines.append("run skillvet_scan for the file:line evidence behind each capability.")
    return _budget("\n".join(lines))


@mcp.tool()
def skillvet_list_rules() -> str:
    """List every skillvet rule with its severity, category and rationale."""
    lines = [f"skillvet {__version__} — {len(RULES)} instruction rules (+ MCP manifest rules)", ""]
    for rule in sorted(RULES, key=lambda r: (Severity.index(r.severity), r.id)):
        lines.append(f"  {rule.severity.upper().ljust(9)} {rule.id}  {rule.title}")
    return "\n".join(lines)


@mcp.tool()
def skillvet_explain(rule_id: str) -> str:
    """Explain one rule: what it looks for and why that matters."""
    try:
        rule = get_rule(rule_id)
    except KeyError:
        return f"unknown rule {rule_id!r}; try skillvet_list_rules"
    return (
        f"{rule.id} — {rule.title}\n"
        f"severity:  {rule.severity}\n"
        f"category:  {rule.category}\n"
        f"capability:{rule.capability or '-'}\n"
        f"why:       {rule.why}"
    )


@mcp.tool()
def skillvet_demo(path: str = "demo-workspace", force: bool = False) -> str:
    """Write a synthetic workspace (one clean skill, one hostile one) and review it.

    Useful when there is nothing to scan yet: the whole feature set in one call,
    with no network and no binary fixtures.
    """
    try:
        root = write_demo(path, force=force)
    except FileExistsError as exc:
        return f"error: {exc}"
    report = scan_path(root)
    return _budget(render_report(report, color=False))


def tool_manifest() -> list[dict]:
    """Introspect the registered tools (tests, CI and the docs all read this)."""

    async def _list():
        return await mcp.list_tools()

    tools = asyncio.run(_list())
    return [
        {"name": t.name, "description": (t.description or "").strip()}
        for t in sorted(tools, key=lambda x: x.name)
    ]


def main() -> None:  # pragma: no cover
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
