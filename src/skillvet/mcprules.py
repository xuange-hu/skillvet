"""MCP-manifest rules.

These run on parsed JSON rather than regex lines, because the interesting facts
about an MCP server live in structure (which command, which args, which env)
— but each finding still points back to a real line in the file. A finding you
cannot locate is just an opinion.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from .model import Finding, Severity, Target

SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
)

#: filesystem-shaped servers get called out when rooted at a filesystem root
_ROOTS = {"/", "c:\\", "c:/", "~/", "$home", "%userprofile%", "~"}
HTTPISH = re.compile(r"^https?://", re.IGNORECASE)
UNPINNED_RUNNER = re.compile(r"^(npx|bunx|uvx|pnpx|dlx)$", re.IGNORECASE)


def json_line_of(text: str, needle: str) -> int:
    """Line number (1-based) of *needle* inside the raw JSON text."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _is_filesystem_root(value: str) -> bool:
    """/, C:\\, ~/ and the like: nothing narrower than a whole filesystem."""
    raw = value.strip()
    if raw.lower() in _ROOTS:
        return True
    normalized = raw.replace("\\", "/").lower()
    core = normalized.rstrip("/").lstrip("/")
    if core in {"", "users", "home", "system"}:  # "/" -> "" after stripping
        return True
    return bool(re.fullmatch(r"[a-z]:", core))


def _finding(rule_id, title, sev, cat, target, line, snippet, why, cap):
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=sev,
        category=cat,
        file=target.display,
        line=line,
        snippet=snippet[:300],
        why=why,
        capability=cap,
    )


def _iter_strings(node, path: str = "") -> Iterable[tuple[str, str]]:
    """Yield (json_path, value) for every string in the document."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_strings(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def servers(document: dict) -> dict:
    for key in ("mcpServers", "servers"):
        value = document.get(key)
        if isinstance(value, dict):
            return value
    return {}


def check_manifest(text: str, target: Target) -> list[Finding]:
    """Return findings for one MCP manifest. Malformed JSON is itself a finding."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            _finding(
                "SKV030",
                "Manifest is not valid JSON",
                Severity.HIGH,
                "malformed",
                target,
                getattr(exc, "lineno", 1),
                getattr(exc, "msg", "invalid JSON"),
                "A manifest the agent cannot parse is either broken or trying to "
                "confuse two different parsers. Both deserve manual review.",
                "supply-chain",
            )
        ]
    if not isinstance(document, dict):
        return []

    out: list[Finding] = []
    found = servers(document)
    if not found:
        out.append(
            _finding(
                "SKV031",
                "No recognizable server block",
                Severity.INFO,
                "malformed",
                target,
                1,
                (text.splitlines() or [""])[0][:120],
                "No `mcpServers` object found — either a different schema, or a "
                "config that another tool will read and this one did not.",
                "supply-chain",
            )
        )
        return out

    for name, spec in found.items():
        if not isinstance(spec, dict):
            continue
        where = f"{name}"
        command = str(spec.get("command", "") or "")
        args = spec.get("args")
        args = args if isinstance(args, list) else []
        args_text = " ".join(str(a) for a in args)
        env = spec.get("env")
        env = env if isinstance(env, dict) else {}

        # --- SKV020: a literal secret written into the config -----------------
        for container, kind in ((env, "env"), ({"args": args_text}, "args")):
            for key, value in (container.items() if isinstance(container, dict) else []):
                hit = SECRET_RE.search(str(value))
                if not hit:
                    continue
                needle = str(value)[:60]
                out.append(
                    _finding(
                        "SKV020",
                        "Hard-coded credential in server config",
                        Severity.CRITICAL,
                        "credential-read",
                        target,
                        json_line_of(text, needle),
                        f"{where} {kind}.{key} = {str(value)[:80]}",
                        "A secret in a config file gets copied, committed and "
                        "uploaded. Use an env-file the scanner cannot see instead.",
                        "credential-read",
                    )
                )

        # --- SKV021: unpinned runner -> the "latest" supply-chain attack ------
        # `removesuffix`, not `rstrip(".exe")` — rstrip takes a *character set*
        # and would eat the trailing "e" off "serve.exe" too.
        base = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        stem = base.lower().removesuffix(".exe")
        if UNPINNED_RUNNER.match(base):
            first_pkg = next((a for a in args if isinstance(a, str) and not a.startswith("-")), "")
            # A missing tag ("@acme/tools") and a floating one ("@latest", "@^1")
            # are equally unresolvable later. rpartition handles @scope/pkg@1.2.3
            # and @scope/pkg alike; only a real version token counts as pinned.
            # `^1` floats inside the major series and `latest` floats everywhere,
            # so neither reproduces a known artifact — only `~x.y` or `x.y.z` do.
            version_part = first_pkg.rpartition("@")[2].rsplit("/", 1)[-1]
            pinned = bool(re.match(r"^(\d|~\d)", version_part))
            if not pinned:
                out.append(
                    _finding(
                        "SKV021",
                        "Runner executes an unpinned package",
                        Severity.HIGH,
                        "supply-chain",
                        target,
                        json_line_of(text, first_pkg or name),
                        f"{where}: {command} {first_pkg}".strip(),
                        f"`{base}` resolves the tag every launch; whoever controls "
                        "that tag controls what runs next time. Pin an exact version.",
                        "supply-chain",
                    )
                )

        # --- SKV022: a shell is doing something indirect ----------------------
        shell_command = stem in {"sh", "bash", "zsh", "cmd", "powershell", "pwsh", "python", "python3"}
        joined = (command + " " + args_text).lower()
        remote_pipe = bool(re.search(r"(curl|wget|iwr)[^|]*\|\s*(ba)?sh", joined))
        if (shell_command and re.search(r"-(c|e|command|enc)\b", joined)) or remote_pipe:
            out.append(
                _finding(
                    "SKV022",
                    "Server launched through a shell wrapper",
                    Severity.MEDIUM,
                    "supply-chain",
                    target,
                    json_line_of(text, command.strip() or name),
                    f"{where}: {command} {args_text}".strip()[:160],
                    "`-c` hides the real binary from every allowlist that matches "
                    "on `command`. Declare the actual executable instead.",
                    "supply-chain",
                )
            )

        # --- SKV023: filesystem rooted wider than the project -----------------
        for arg in args:
            value = str(arg)
            if _is_filesystem_root(value):
                out.append(
                    _finding(
                        "SKV023",
                        "Server granted filesystem-wide root",
                        Severity.HIGH,
                        "scope",
                        target,
                        json_line_of(text, value),
                        f"{where}: {value}",
                        "A filesystem root means every other control in this report "
                        "is optional. Point it at the project directory.",
                        "scope",
                    )
                )

        # --- SKV024: capabilities that disable the sandbox --------------------
        for arg in args:
            value = str(arg)
            if re.search(r"(--allow-all|--no-sandbox|--dangerously|--disable-web-security|--insecure|--disable-auth)", value, re.IGNORECASE):
                out.append(
                    _finding(
                        "SKV024",
                        "Sandbox / safety flag disabled",
                        Severity.HIGH,
                        "scope",
                        target,
                        json_line_of(text, value),
                        f"{where}: {value}",
                        "Flags like this are exactly what the tool's own threat model "
                        "says not to set; there is no project-level justification.",
                        "scope",
                    )
                )

        # --- SKV025: remote endpoint over cleartext ---------------------------
        url = str(spec.get("url", "") or "")
        if HTTPISH.match(url) and url.lower().startswith("http://"):
            out.append(
                _finding(
                    "SKV025",
                    "Remote server over cleartext HTTP",
                    Severity.MEDIUM,
                    "network-egress",
                    target,
                    json_line_of(text, url),
                    f"{where}: {url}",
                    "Tokens and tool arguments cross the network in the clear; use https.",
                    "network-egress",
                )
            )

    return out
