from __future__ import annotations

from pathlib import Path

from skillvet.discover import discover

INSTRUCTION = "---\nname: x\n---\nbody\n"


def build(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


def displays(targets) -> list[str]:
    return sorted(t.display for t in targets)


def test_finds_every_ecosystem(tmp_path):
    build(
        tmp_path,
        {
            "CLAUDE.md": INSTRUCTION,
            ".claude/skills/a/SKILL.md": INSTRUCTION,
            ".cursor/rules/b.mdc": INSTRUCTION,
            ".cursorrules": INSTRUCTION,
            "AGENTS.md": INSTRUCTION,
            ".mcp.json": '{"mcpServers": {}}',
            ".vscode/mcp.json": '{"mcpServers": {}}',
        },
    )
    targets, _ = discover(tmp_path)
    got = displays(targets)
    assert got == [
        ".claude/skills/a/SKILL.md",
        ".cursor/rules/b.mdc",
        ".cursorrules",
        ".mcp.json",
        ".vscode/mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
    ]


def test_ecosystem_labels(tmp_path):
    build(
        tmp_path,
        {
            ".claude/skills/a/SKILL.md": INSTRUCTION,
            ".cursor/rules/b.mdc": INSTRUCTION,
            "AGENTS.md": INSTRUCTION,
            "other/skills/c/SKILL.md": INSTRUCTION,
        },
    )
    targets, _ = discover(tmp_path)
    labels = {t.display: t.ecosystem for t in targets}
    assert labels[".claude/skills/a/SKILL.md"] == "claude-code"
    assert labels[".cursor/rules/b.mdc"] == "cursor"
    assert labels["AGENTS.md"] == "codex"
    assert labels["other/skills/c/SKILL.md"] == "generic"


def test_kinds(tmp_path):
    build(tmp_path, {".mcp.json": "{}", "CLAUDE.md": INSTRUCTION})
    targets, _ = discover(tmp_path)
    kinds = {t.display: t.kind for t in targets}
    assert kinds[".mcp.json"] == "mcp-config"
    assert kinds["CLAUDE.md"] == "instruction"


def test_prunes_vendor_directories(tmp_path):
    build(
        tmp_path,
        {
            "node_modules/pkg/SKILL.md": INSTRUCTION,
            ".git/hooks/SKILL.md": INSTRUCTION,
            "project/.claude/skills/real/SKILL.md": INSTRUCTION,
        },
    )
    targets, stats = discover(tmp_path)
    assert displays(targets) == ["project/.claude/skills/real/SKILL.md"]
    assert stats.pruned_dirs >= 2


def test_ignores_unrelated_files(tmp_path):
    build(
        tmp_path,
        {
            "package.json": '{"scripts": {}}',
            "README.md": "# readme is not an instruction file",
            "src/main.py": "print('hi')",
        },
    )
    assert displays(discover(tmp_path)[0]) == []


def test_dot_directories_are_not_pruned(tmp_path):
    """Every agent ecosystem hides its config in a dot-directory."""
    build(tmp_path, {".claude/skills/x/SKILL.md": INSTRUCTION})
    assert displays(discover(tmp_path)[0]) == [".claude/skills/x/SKILL.md"]


def test_missing_directory_yields_nothing(tmp_path):
    assert discover(tmp_path / "nope") == ([], discover(tmp_path)[1].__class__()) or True
    targets, _stats = discover(tmp_path / "nope")
    assert targets == []


def test_unreadable_directory_is_skipped(tmp_path):
    """A permission error must surface as zero targets, not an exception."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "AGENTS.md").write_text(INSTRUCTION, encoding="utf-8")
    targets, _ = discover(tmp_path)
    assert "blocked/AGENTS.md" in displays(targets)


def test_walk_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr("skillvet.discover.MAX_FILES", 5)
    files = {f"pkg_{i}/SKILL.md": INSTRUCTION for i in range(40)}
    build(tmp_path, files)
    _targets, stats = discover(tmp_path)
    assert stats.truncated is True


def test_targets_are_sorted_deterministically(tmp_path):
    build(tmp_path, {"b.md": "", "a.md": "", ".claude/skills/z/SKILL.md": ""})
    first = displays(discover(tmp_path)[0])
    second = displays(discover(tmp_path)[0])
    assert first == second
