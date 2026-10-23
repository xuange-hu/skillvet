"""Packaging contract guard.

Learned the hard way on another project: CI installs `.[all]`, so a console
script whose module imports something from an optional extra builds green and
then explodes for everyone doing a plain `pip install`. These assertions read
pyproject.toml and the AST instead of installing anything.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src"


def load_config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def scripts() -> dict[str, str]:
    return load_config()["project"]["scripts"]


def _req_name(requirement: str) -> str:
    """PEP 508 name without the version specifier or the extras bracket."""
    return re.split(r"[<>=!~;\[\s]", requirement.strip(), maxsplit=1)[0].strip().lower()


def _module_of(target: str) -> str:
    return target.split(":")[0]


def _third_party_imports(module_path: Path) -> set[str]:
    """Top-level module names imported at module scope (not inside a function)."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module.split(".")[0])
    return {n for n in names if n not in sys.stdlib_module_names}


def test_every_console_script_resolves():
    for name, target in scripts().items():
        module_path = SRC / Path(_module_of(target).replace(".", "/")).with_suffix(".py")
        assert module_path.exists(), f"{name} -> missing {module_path}"
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        _, _, func = target.partition(":")
        assert func in functions, f"{target}: no function {func}"


def test_base_install_does_not_need_optional_deps():
    """The dependency bug this file exists to prevent."""
    config = load_config()
    base = {_req_name(d) for d in config["project"]["dependencies"]}
    extras = {k.lower(): v for k, v in config["project"].get("optional-dependencies", {}).items()}
    for name, target in scripts().items():
        # `skillvet-mcp` may rely on the `mcp` extra; the bare `skillvet` may not
        allowed = set(base)
        for candidate in {name.lower(), name.lower().rsplit("-", 1)[-1]}:
            if candidate in extras:
                allowed |= {_req_name(r) for r in extras[candidate]}
        module_path = SRC / Path(_module_of(target).replace(".", "/")).with_suffix(".py")
        missing = {
            mod
            for mod in _third_party_imports(module_path)
            if mod.lower() not in allowed and mod != "skillvet"
        }
        assert not missing, f"{name} needs {sorted(missing)} which is not an install dependency"


def test_version_matches_pyproject():
    import skillvet

    assert skillvet.__version__ == load_config()["project"]["version"]


def test_core_packages_are_stdlib_only():
    """The zero-dependency promise: core modules must not import third-party code."""
    core = ["model", "rules", "mcprules", "discover", "scan", "render", "sarif", "demo", "cli"]
    for name in core:
        path = SRC / "skillvet" / f"{name}.py"
        third_party = {m for m in _third_party_imports(path) if m != "skillvet"}
        assert not third_party, f"{name}.py pulls in {sorted(third_party)}"


def test_mcp_server_is_the_only_module_needing_mcp():
    path = SRC / "skillvet" / "mcp_server.py"
    assert "mcp" in _third_party_imports(path)


def test_readme_exists_and_mentions_the_one_liner():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "skillvet demo" in readme
    assert str(load_config()["project"]["version"]) in readme


def test_tests_directory_is_not_packaged():
    packages = load_config()["tool"]["setuptools"]["packages"]
    assert packages["find"]["where"] == ["src"]


def test_mcp_entry_point_declared():
    assert "skillvet-mcp" in scripts()
    assert scripts()["skillvet-mcp"].endswith("mcp_server:main")
