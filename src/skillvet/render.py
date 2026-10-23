"""Terminal renderer.

Zero-dependency by design: a handful of ANSI codes and fixed-width columns.
`rich` would be nicer and would put a hard dependency on the one command people
run first (`skillvet`), so it stays out of the core.
"""

from __future__ import annotations

import os
import sys

from .model import Severity
from .scan import Report, describe_capability

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
GRADE_COLORS = {
    "CLEAN": "\033[1;32m",
    "LOW": "\033[36m",
    "MEDIUM": "\033[1;33m",
    "HIGH": "\033[1;31m",
    "CRITICAL": "\033[1;97;41m",
}


def use_color(choice: str = "auto", stream=None) -> bool:
    stream = stream or sys.stdout
    if choice == "never":
        return False
    if choice == "always":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{RESET}" if color else text


def bar(value: int, maximum: int, width: int = 10) -> str:
    if maximum <= 0:
        return "." * width
    filled = max(0, min(width, round(value / maximum * width)))
    return "#" * filled + "." * (width - filled)


def render_report(report: Report, *, min_severity: str = Severity.INFO, color: bool = False, show_clean: bool = True) -> str:
    lines: list[str] = []
    add = lines.append

    counts = report.counts()
    score = report.risk_score()
    grade = report.grade()

    add("")
    add(_c(f"  skillvet  {report.root}", BOLD, color))
    add(
        _c(
            f"  {report.files_scanned()} file(s) reviewed · "
            f"{len(report.findings)} finding(s) · risk {score}/100 {grade}",
            DIM,
            color,
        )
    )
    if report.stats.truncated:
        add(_c("  ! walk truncated at the file limit — results are partial", "\033[1;33m", color))
    add("")

    keep = Severity.at_least(min_severity)
    visible = [f for f in report.filtered(min_severity)]

    # --- severity roll-up -------------------------------------------------
    add(_c("  by severity", BOLD, color))
    top = max(counts.values()) if counts else 0
    for level in Severity.ORDER:
        if level not in keep:
            continue
        add(
            f"    {_c(level.upper().ljust(9), COLORS[level], color)} "
            f"{_c(bar(counts[level], top), COLORS[level], color)} {counts[level]}"
        )
    add("")

    # --- capability / permission table ------------------------------------
    caps = {k: v for k, v in report.capabilities().items() if any(f.severity in keep for f in v)}
    if caps:
        add(_c("  what this artifact could do", BOLD, color))
        for cap, items in caps.items():
            worst = min(items, key=lambda f: Severity.index(f.severity)).severity
            add(
                f"    {_c(worst.upper().ljust(9), COLORS[worst], color)} "
                f"{cap.ljust(16)} x{len(items):<3} {_c(describe_capability(cap), DIM, color)}"
            )
        add("")

    # --- findings grouped by file -----------------------------------------
    if visible:
        add(_c("  findings", BOLD, color))
        by_file: dict[str, list] = {}
        for f in visible:
            by_file.setdefault(f.file, []).append(f)
        for name in sorted(by_file):
            items = by_file[name]
            ecosystem = next(
                (t.ecosystem for t in report.targets if t.display == name), "generic"
            )
            add(f"  {_c(name, BOLD, color)}  {_c(f'[{ecosystem}]', DIM, color)}")
            for f in items:
                add(
                    f"    {_c(f.severity.upper().ljust(9), COLORS[f.severity], color)}"
                    f"{f.rule_id}  {_c(f.location(), DIM, color)}"
                )
                add(f"      {_c(f.title, '', color)}")
                add(f"      {_c('> ' + f.snippet[:110], DIM, color)}")
            add("")

    elif show_clean:
        add(_c("  nothing matched. Re-run with a stricter scanner if you want a second opinion.", "\033[1;32m", color))
        add("")

    for file_name, err in report.errors:
        add(_c(f"  skip {file_name}: {err}", "\033[1;33m", color))

    add(
        _c(
            "  every finding above carries file:line — read the line before you trust or dismiss it.",
            DIM,
            color,
        )
    )
    return "\n".join(lines) + "\n"


def render_rules(rules, *, color: bool = False) -> str:
    lines = ["", _c("  skillvet rule set", BOLD, color), ""]
    for rule in sorted(rules, key=lambda r: (Severity.index(r.severity), r.id)):
        lines.append(
            f"  {_c(rule.severity.upper().ljust(9), COLORS[rule.severity], color)}"
            f"{rule.id}  {rule.title}"
        )
        lines.append(f"      {_c(rule.why, DIM, color)}")
    return "\n".join(lines) + "\n"
