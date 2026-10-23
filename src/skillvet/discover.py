"""Target discovery: find the instruction files and MCP manifests in a tree.

One pass, pruned walk, no third-party globbing. The ecosystem label is derived
from the path so the report can tell you *whose* config fired the rule.
"""

from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .model import Target

PRUNE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        ".idea",
        ".vscode-test",
    }
)

#: instruction files matched by exact relative name (case-insensitive)
ROOT_INSTRUCTION_FILES = {
    "claude.md": "claude-code",
    "agents.md": "codex",
    ".cursorrules": "cursor",
    ".windsurfrules": "cursor",
    ".github/copilot-instructions.md": "claude-code",
}

#: instruction files matched by basename anywhere in the tree
ANYWHERE_INSTRUCTION_FILES = {
    "skill.md",  # ecosystem inferred from path
    "agent.md",
}

#: directories that hold instructions regardless of the file's basename
INSTRUCTION_DIR_HINTS = (
    "/skills/",
    "/.cursor/rules/",
    "/.windsurf/rules/",
    "/.claude/agents/",
)

#: MCP manifests matched by exact relative name first, then by basename
MCP_NAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "mcp_servers.json",
    "mcpservers.json",
}

MAX_FILES = 50_000


@dataclass
class DiscoveryStats:
    files_walked: int = 0
    pruned_dirs: int = 0
    truncated: bool = False


def _walk(root: Path, stats: DiscoveryStats):
    """Breadth-first walk with pruning; bounded so a monorepo cannot hang it.

    `stats` is shared with the caller on purpose: the walk can stop mid-way, and
    the caller still needs to know it stopped. Copying it back at the end of the
    loop would lose the truncation flag set on the final `next()`.
    """
    queue: deque[Path] = deque([root])
    while queue:
        current = queue.popleft()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            continue
        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue
            if is_dir:
                if entry.name in PRUNE_DIRS:
                    stats.pruned_dirs += 1
                    continue
                queue.append(Path(entry.path))
                continue
            stats.files_walked += 1
            if stats.files_walked > MAX_FILES:
                stats.truncated = True
                return
            yield Path(entry.path)


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def infer_ecosystem(relpath: str, basename: str) -> str:
    low = relpath.lower()
    if low.startswith(".claude") or basename in {"claude.md", "claude_desktop_config.json"}:
        return "claude-code"
    if low.startswith(".cursor") or basename in {".cursorrules", ".windsurfrules"}:
        return "cursor"
    if low.startswith(".codex") or basename == "agents.md":
        return "codex"
    if low.startswith(".github/"):
        return "claude-code"
    return "generic"


def discover(root: Path | str) -> tuple[list[Target], DiscoveryStats]:
    """Return every scannable target under *root*, sorted by relative path."""
    root = Path(root)
    out: list[Target] = []
    stats = DiscoveryStats()

    for path in _walk(root, stats):
        if stats.truncated:
            break
        relpath = rel(path, root)
        basename = path.name.lower()
        is_markdown = basename.endswith((".md", ".mdc"))
        # Matched by basename too, not only by root-relative path: a monorepo keeps
        # per-package instruction files (packages/api/AGENTS.md) and those matter.
        known = basename in ROOT_INSTRUCTION_FILES
        if not (is_markdown or basename.endswith(".json") or known):
            continue

        kind = None
        ecosystem = "generic"
        if known:
            kind = "instruction"
            ecosystem = ROOT_INSTRUCTION_FILES[basename]
        elif is_markdown and (
            basename in ANYWHERE_INSTRUCTION_FILES
            or any(hint in f"/{relpath.lower()}" for hint in INSTRUCTION_DIR_HINTS)
        ):
            kind = "instruction"
            ecosystem = infer_ecosystem(relpath, basename)
        elif basename in MCP_NAMES:
            kind = "mcp-config"
            ecosystem = "mcp-config"

        if kind is None:
            continue
        out.append(
            Target(
                path=path,
                display=relpath,
                ecosystem=ecosystem,
                kind=kind,
            )
        )

    out.sort(key=lambda t: (t.display.lower(), t.kind))
    return out, stats
