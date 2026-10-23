"""SARIF 2.1.0 output so GitHub Code Scanning can ingest this in CI.

Chosen deliberately over a custom format: one flag (`--sarif`) and the findings
land as review annotations on the pull request that introduced them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from .model import Finding, Severity
from .rules import RULES

TOOL_NAME = "skillvet"
TOOL_URI = "https://github.com/xuange-hu/skillvet"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

#: SARIF has four levels; map our five severities onto them
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def rule_descriptor(rule_id: str) -> dict:
    from .rules import get_rule

    rule = get_rule(rule_id)
    return {
        "id": rule.id,
        "name": rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.why},
        "defaultConfiguration": {"level": LEVEL.get(rule.severity, "note")},
        "properties": {
            "tags": ["security", "supply-chain", rule.category],
            "severity": rule.severity,
            "capability": rule.capability or rule.category,
        },
    }


def _result(finding: Finding) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": LEVEL.get(finding.severity, "note"),
        "message": {"text": f"{finding.title} — {finding.why}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {
                        "startLine": max(1, finding.line),
                        "snippet": {"text": finding.snippet[:200]},
                    },
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "capability": finding.capability,
        },
    }


def to_sarif(findings: Iterable[Finding], version: str = "0.1.0", driver_rules=None) -> dict:
    findings = list(findings)
    used = sorted({f.rule_id for f in findings})
    rules = []
    for rule_id in used:
        try:
            rules.append(rule_descriptor(rule_id))
        except KeyError:
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": rule_id},
                }
            )
    if driver_rules is not None:
        rules = [rule_descriptor(r.id) for r in driver_rules]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": version,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }


def dumps(findings: Iterable[Finding], version: str = "0.1.0", indent: int = 2) -> str:
    return json.dumps(to_sarif(findings, version=version), indent=indent, ensure_ascii=False)


def all_rules_sarif(version: str = "0.1.0") -> dict:
    """SARIF document listing every rule with zero results — useful for a dry run."""
    doc = to_sarif([], version=version, driver_rules=RULES)
    return doc
