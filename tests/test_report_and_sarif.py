from __future__ import annotations

import json

import pytest

from skillvet.demo import write_demo
from skillvet.model import Severity, Target
from skillvet.sarif import LEVEL, dumps, to_sarif
from skillvet.scan import Report, read_text, scan_path, scan_targets

T = Target(path=None, display="x.md", ecosystem="generic", kind="instruction")


def finding(**kw):
    base = dict(
        rule_id="SKV001",
        title="t",
        severity=Severity.HIGH,
        category="cats",
        file="x.md",
        line=3,
        snippet="s",
        why="w",
        capability="network-egress",
    )
    base.update(kw)
    from skillvet.model import Finding

    return Finding(**base)


# --------------------------------------------------------------------------
# report arithmetic
# --------------------------------------------------------------------------


def test_counts_bucket_every_severity():
    report = Report(
        root=".",
        findings=[
            finding(severity=Severity.CRITICAL, file="a.md"),
            finding(severity=Severity.LOW, file="b.md"),
            finding(severity=Severity.HIGH, file="c.md"),
        ],
    )
    counts = report.counts()
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.LOW] == 1
    assert counts[Severity.INFO] == 0


def test_risk_score_saturates_at_100():
    report = Report(root=".", findings=[finding(severity=Severity.CRITICAL)] * 10)
    assert report.risk_score() == 100


def test_risk_score_is_zero_when_clean():
    assert Report(root=".").risk_score() == 0
    assert Report(root=".").grade() == "CLEAN"


def test_grade_escalates_on_any_critical():
    report = Report(root=".", findings=[finding(severity=Severity.CRITICAL)])
    assert report.grade() == "CRITICAL"


def test_grade_steps():
    def grade_for(severity, n=1):
        return Report(root=".", findings=[finding(severity=severity)] * n).grade()

    assert grade_for(Severity.LOW) == "LOW"
    assert grade_for(Severity.MEDIUM) == "MEDIUM"
    assert grade_for(Severity.HIGH) == "HIGH"


def test_filtered_respects_minimum_and_order():
    report = Report(
        root=".",
        findings=[
            finding(severity=Severity.INFO, file="b.md", line=2),
            finding(severity=Severity.CRITICAL, file="a.md", line=1),
            finding(severity=Severity.MEDIUM, file="a.md", line=5),
        ],
    )
    got = report.filtered(Severity.MEDIUM)
    assert [f.severity for f in got] == [Severity.CRITICAL, Severity.MEDIUM]
    assert [f.location() for f in got] == ["a.md:1", "a.md:5"]


def test_capabilities_group_and_sort_by_volume():
    report = Report(
        root=".",
        findings=[
            finding(capability="credential-read"),
            finding(capability="credential-read"),
            finding(capability="network-egress"),
        ],
    )
    caps = report.capabilities()
    assert list(caps) == ["credential-read", "network-egress"]


def test_to_dict_is_json_serialisable():
    report = Report(root=".", targets=[T], findings=[finding()])
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["summary"]["risk_score"] == 22
    assert payload["summary"]["grade"] == "HIGH"
    assert payload["findings"][0]["rule_id"] == "SKV001"


# --------------------------------------------------------------------------
# scanning behaviour
# --------------------------------------------------------------------------


def test_read_text_rejects_oversized_files(tmp_path):
    big = tmp_path / "big.md"
    big.write_bytes(b"x" * 2048)
    with pytest.raises(ValueError, match="exceeds"):
        read_text(big, max_bytes=1024)


def test_scan_targets_records_io_errors(tmp_path):
    missing = Target(path=tmp_path / "gone.md", display="gone.md", ecosystem="generic", kind="instruction")
    report = scan_targets([missing])
    assert report.errors and report.errors[0][0] == "gone.md"
    assert report.findings == []


def test_scan_path_on_demo_workspace(tmp_path):
    write_demo(tmp_path / "demo")
    report = scan_path(tmp_path / "demo")
    assert report.files_scanned() == 5
    assert report.grade() == "CRITICAL"
    names = {t.display for t in report.targets}
    assert ".mcp.json" in names and "AGENTS.md" in names
    rule_ids = {f.rule_id for f in report.findings}
    assert {"SKV001", "SKV009", "SKV010", "SKV020", "SKV023"} <= rule_ids


def test_clean_directory_scores_zero(tmp_path):
    (tmp_path / "CLAUDE.md").write_text(
        "---\nname: ok\nallowed-tools: [Read]\n---\n\nExplain the diff in one line.\n",
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert report.findings == []
    assert report.grade() == "CLEAN"


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def test_level_mapping_matches_severity():
    assert LEVEL[Severity.CRITICAL] == "error"
    assert LEVEL[Severity.MEDIUM] == "warning"
    assert LEVEL[Severity.INFO] == "note"


def test_sarif_structure():
    doc = to_sarif([finding()], version="9.9.9")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "skillvet"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "SKV001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert run["tool"]["driver"]["rules"][0]["id"] == "SKV001"


def test_sarif_with_no_findings_is_still_valid():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert json.loads(dumps([]))


def test_sarif_unknown_rule_id_does_not_crash():
    doc = to_sarif([finding(rule_id="SKV999")])
    assert doc["runs"][0]["results"][0]["ruleId"] == "SKV999"


def test_sarif_roundtrips_through_json():
    text = dumps([finding()])
    assert json.loads(text)["runs"][0]["results"][0]["ruleId"] == "SKV001"
