"""MCP surface: stable names and non-empty descriptions.

skillvet's tool_manifest() introspects the live server, so served == manifest
is true by construction and comparing them would prove nothing. What matters
here is the contract agents are configured against: an exact name list, and a
description on every tool (FastMCP serves an empty one when the registered
function has no docstring).

The importorskip lives inside a helper, not at module scope: a module-level
skip hides the tests from ``--collect-only`` output, which makes any badge
that counts ``::`` lines drift by the size of this file on machines without
the mcp extra.
"""

from __future__ import annotations

import asyncio

import pytest

EXPECTED = {
    "skillvet_scan",
    "skillvet_scan_json",
    "skillvet_list_rules",
    "skillvet_explain",
    "skillvet_demo",
    "skillvet_capabilities",
}


def _mcp_server():
    pytest.importorskip("mcp")
    from skillvet import mcp_server  # needs the mcp extra to import

    return mcp_server


def test_served_names_are_the_documented_ones():
    mcp_server = _mcp_server()
    tools = asyncio.run(mcp_server.mcp.list_tools())
    served = {t.name for t in tools}
    assert served == EXPECTED, f"missing: {EXPECTED - served}; unexpected: {served - EXPECTED}"


def test_every_served_tool_has_a_description():
    mcp_server = _mcp_server()
    for t in asyncio.run(mcp_server.mcp.list_tools()):
        assert (t.description or "").strip(), f"{t.name} has no description"


def test_manifest_reflects_the_live_server():
    mcp_server = _mcp_server()
    names = {t["name"] for t in mcp_server.tool_manifest()}
    served = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert names == served
