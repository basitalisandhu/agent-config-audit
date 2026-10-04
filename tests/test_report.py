from __future__ import annotations

import json
from pathlib import Path

from agent_config_audit.report import SARIF_LEVELS, sarif_document, to_markdown, to_table
from agent_config_audit.rules import RULES
from agent_config_audit.scanner import Auditor

from .conftest import FIXTURES, run, write


def _report(root: Path) -> dict:
    a = Auditor(root)
    a.run()
    return a.report()


def test_table_output_lists_findings_and_fixes():
    text = to_table(_report(FIXTURES / "risky-settings"))
    assert "SEVERITY" in text and "PERM-001" in text and "Fixes:" in text
    assert ".claude/settings.json:" in text
    assert "critical" in text


def test_table_output_for_clean_project():
    text = to_table(_report(FIXTURES / "clean"))
    assert "No findings" in text


def test_markdown_output():
    text = to_markdown(_report(FIXTURES / "risky-settings"))
    assert text.startswith("# Agent configuration audit")
    assert "| PERM-001 | critical |" in text
    assert "## Recommendations" in text and "## Files scanned" in text


def test_markdown_lists_suppressions():
    text = to_markdown(_report(FIXTURES / "allowlist"))
    assert "## Suppressed by configuration" in text and "lockfile" in text


def test_json_report_shape():
    rep = _report(FIXTURES / "risky-settings")
    assert rep["tool"] == "agent-config-audit"
    assert set(rep) >= {
        "version",
        "root",
        "scanned_files",
        "errors",
        "summary",
        "findings",
        "suppressed",
    }
    assert rep["summary"]["total"] == len(rep["findings"])
    for f in rep["findings"]:
        assert set(f) == {
            "id",
            "severity",
            "category",
            "title",
            "file",
            "line",
            "evidence",
            "recommendation",
        }
        assert f["id"] in RULES


def test_findings_are_sorted_by_severity_then_file(project):
    rep = _report(project("risky-mcp"))
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(f["severity"]) for f in rep["findings"]]
    assert ranks == sorted(ranks)


def test_output_file_and_formats(tmp_path):
    write(tmp_path, ".claude/settings.json", '{"permissions": {"allow": ["Bash(*)"]}}')
    out = tmp_path / "report.sarif"
    rc, _, err = run(str(tmp_path), "--format", "sarif", "--output", str(out))
    assert rc == 0 and out.exists() and "wrote" in err
    assert json.loads(out.read_text())["version"] == "2.1.0"
    for fmt in ("table", "json", "markdown"):
        rc, text, _ = run(str(tmp_path), "--format", fmt)
        assert rc == 0 and "PERM-001" in text


def test_sarif_levels_cover_every_severity():
    assert set(SARIF_LEVELS) == {"critical", "high", "medium", "low", "info"}
    assert set(SARIF_LEVELS.values()) <= {"error", "warning", "note"}
    doc = sarif_document(_report(FIXTURES / "clean"))
    assert doc["runs"][0]["results"] == []
