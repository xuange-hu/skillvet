"""Data model: what a finding is, what a scannable target is.

Everything here is intentionally plain data so callers can serialise it to
JSON / SARIF without importing anything else from the package.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


class Severity:
    """Ordered severity levels.

    Plain class (not Enum) so that comparisons stay cheap and the values
    serialise to plain strings in JSON.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    #: contribution of a single hit to the 0-100 risk score
    WEIGHT = {CRITICAL: 45, HIGH: 22, MEDIUM: 8, LOW: 3, INFO: 0}

    @classmethod
    def index(cls, value: str) -> int:
        try:
            return cls.ORDER.index(value)
        except ValueError:
            return len(cls.ORDER)

    @classmethod
    def parse(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in cls.ORDER:
            raise ValueError(f"unknown severity {value!r}; expected one of {cls.ORDER}")
        return v

    @classmethod
    def at_least(cls, minimum: str) -> tuple[str, ...]:
        """All severities at or above *minimum*."""
        return cls.ORDER[: cls.index(minimum) + 1]


#: capability -> human label, used by the "permission table" output
CAPABILITIES = {
    "network-egress": "send data out over the network",
    "credential-read": "read secrets / credentials from disk",
    "shell-exec": "execute shell commands",
    "persistence": "persist itself beyond the current task",
    "destructive": "delete or overwrite data irreversibly",
    "obfuscation": "hide its real instructions",
    "supply-chain": "fetch and run third-party code",
    "prompt-injection": "override instructions or hide actions from the user",
    "hidden-text": "carry text the UI will not render",
    "scope": "act outside the reviewed directory",
}


@dataclass(frozen=True)
class Finding:
    """One rule hit. `file:line` plus `snippet` is the evidence."""

    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    snippet: str
    why: str
    capability: str = ""

    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return asdict(self)

    def sort_key(self) -> tuple:
        return (Severity.index(self.severity), self.file, self.line, self.rule_id)


@dataclass(frozen=True)
class Target:
    """A file selected for scanning, plus where we think it came from."""

    path: Path
    display: str
    ecosystem: str
    kind: str  # "instruction" | "mcp-config"


ECOSYSTEMS = {
    "claude-code": "Claude Code (CLAUDE.md / .claude/skills)",
    "cursor": "Cursor (.cursorrules / .cursor/rules)",
    "codex": "Codex / generic agents (AGENTS.md)",
    "mcp-config": "MCP server manifest (.mcp.json and friends)",
    "generic": "unattributed instruction file",
}
