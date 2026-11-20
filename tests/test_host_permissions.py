from __future__ import annotations

import json
from pathlib import Path

from agent_config_audit.patterns import HOME_FILES, PROJECT_GLOBS

from .conftest import FIXTURES, audit


def count_findings(report: dict, rule_id: str, severity: str) -> int:
    return sum(
        finding["id"] == rule_id and finding["severity"] == severity
        for finding in report["findings"]
    )


def test_windsurf_risky_settings_report_catch_all_and_dangerous_command_allowlists():
    _, report = audit(FIXTURES / "risky-windsurf")
    findings = report["findings"]
    assert [(f["id"], f["severity"]) for f in findings if f["id"] == "PERM-003"] == [
        ("PERM-003", "critical")
    ]
    assert any(
        f["id"] == "PERM-002" and f["severity"] == "high" and "rm" in f["title"] for f in findings
    )


def test_windsurf_narrow_allowlist_is_not_reported():
    rc, report = audit(FIXTURES / "clean-windsurf")
    assert rc == 0
    assert report["findings"] == []


def test_cline_risky_global_and_mcp_approvals_use_existing_permission_rules():
    root = FIXTURES / "risky-cline"
    _, report = audit(
        root,
        "--extra",
        str(root / "globalState.json"),
        "--extra",
        str(root / "cline_mcp_settings.json"),
        "--extra",
        str(root / "global-settings.json"),
    )
    assert count_findings(report, "PERM-003", "critical") == 1
    assert count_findings(report, "PERM-002", "high") == 1
    assert count_findings(report, "PERM-006", "medium") == 1


def test_cline_restricted_actions_and_individual_mcp_approvals_are_clean():
    root = FIXTURES / "clean-cline"
    rc, report = audit(
        root,
        "--extra",
        str(root / "globalState.json"),
        "--extra",
        str(root / "cline_mcp_settings.json"),
        "--extra",
        str(root / "global-settings.json"),
    )
    assert rc == 0
    assert report["findings"] == []


def test_windsurf_and_cline_settings_paths_are_discovered():
    assert ".vscode/settings.json" in PROJECT_GLOBS
    expected_home_files = {
        "~/Library/Application Support/Windsurf/User/settings.json",
        "~/.config/Windsurf/User/settings.json",
        "~/AppData/Roaming/Windsurf/User/settings.json",
        "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/globalState.json",
        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/globalState.json",
        "~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/globalState.json",
        "~/.cline/data/settings/cline_mcp_settings.json",
        "~/.cline/data/settings/global-settings.json",
    }
    assert expected_home_files.issubset(set(HOME_FILES))


def test_cline_mcp_auto_approve_does_not_flag_individual_tool_names(tmp_path: Path):
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "node",
                "args": ["server.js"],
                "autoApprove": ["read_file", "list_files"],
            }
        }
    }
    (tmp_path / "cline_mcp_settings.json").write_text(json.dumps(config), encoding="utf-8")
    _, report = audit(tmp_path, "--extra", str(tmp_path / "cline_mcp_settings.json"))
    assert "PERM-006" not in {finding["id"] for finding in report["findings"]}
