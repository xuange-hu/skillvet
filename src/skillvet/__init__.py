"""skillvet — static security review for AI agent skills and MCP configs.

Design notes (why this exists, and what it deliberately does not do):

* **Deterministic.** Every finding comes from a reviewed, readable Python rule.
  No LLM call, no network, no API key, no "vibes". Same input -> same output.
* **Zero-dependency core.** The parser, the rule engine, the renderers and the
  CLI use the standard library only. `mcp` is an optional extra.
* **Evidence first.** A finding without a file, a line number and the original
  text is an opinion. Every finding here carries all three.
"""

from __future__ import annotations

from .model import Finding, Severity, Target
from .rules import RULES, Rule, scan_text
from .scan import scan_path, scan_targets

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Rule",
    "RULES",
    "Severity",
    "Target",
    "__version__",
    "scan_path",
    "scan_targets",
    "scan_text",
]
