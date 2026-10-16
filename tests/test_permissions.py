from __future__ import annotations

import json

import pytest

from .conftest import FIXTURES, audit, by_id, ids, write


@pytest.mark.parametrize(
    "spec",
    [
        "./.env*",
        "~/.ssh/**",
        "/home/alice/.aws/credentials",
        "~/.netrc",
        "**/*.pem",
        "**/*.key",
        "./id_rsa",
        "./id_ed25519",
        "./.env.local",
        "./.env.example.local",
        "./.env.examples",
        "./.env.sample*",
    ],
)
def test_perm_012_secret_path_read_allow(tmp_path, spec):
    rule = f"Read({spec})"
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}}))
    _, rep = audit(tmp_path)
    findings = by_id(rep, "PERM-012")
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"] == rule
    assert findings[0]["line"]


@pytest.mark.parametrize(
    "rule",
    [
        "Read(./src/**)",
        "Read(./keynote.md)",
        "Read(./environment.md)",
        "Read(./aws-guide.md)",
        "Write(./id_rsa)",
        "Read(./.env.example)",
        "Read(./.env.sample)",
        "Read(./.env.template)",
        "Read(./config/.env.local.example)",
        r"Read(C:\project\.env.sample)",
        "Read(./.env.template/README.md)",
    ],
)
def test_perm_012_ordinary_or_non_read_rules_are_not_secret_reads(tmp_path, rule):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}}))
    _, rep = audit(tmp_path)
    assert "PERM-012" not in ids(rep)


def test_perm_012_risky_reads_fixture():
    _, rep = audit(FIXTURES / "risky-reads")
    findings = by_id(rep, "PERM-012")
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"] == "Read(./.env.local)"
    assert findings[0]["line"]
    assert ".claude/settings.json" in rep["scanned_files"]


def test_perm_012_windows_secret_path_still_warns(tmp_path):
    rule = r"Read(C:\project\.env.local)"
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}}))
    _, rep = audit(tmp_path)
    findings = by_id(rep, "PERM-012")
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"] == rule


def test_clean_project_has_no_findings():
    rc, rep = audit(FIXTURES / "clean")
    assert rc == 0
    assert rep["findings"] == [], rep["findings"]
    assert ".claude/settings.json" in rep["scanned_files"]
    assert "CLAUDE.md" in rep["scanned_files"]
    assert ".claude/skills/demo/SKILL.md" in rep["scanned_files"]


def test_every_permission_rule_fires_on_risky_settings():
    _, rep = audit(FIXTURES / "risky-settings")
    found = ids(rep)
    for fid in [
        "PERM-001",
        "PERM-002",
        "PERM-003",
        "PERM-004",
        "PERM-005",
        "PERM-006",
        "PERM-007",
        "PERM-008",
        "PERM-009",
        "PERM-010",
    ]:
        assert fid in found, fid


def test_permission_severities_and_lines():
    _, rep = audit(FIXTURES / "risky-settings")
    sev = {f["id"]: f["severity"] for f in rep["findings"]}
    assert sev["PERM-001"] == "critical"
    # Project settings: current Claude Code ignores bypassPermissions there, so it is high, not critical.
    assert sev["PERM-003"] == "high"
    assert rep["summary"]["critical"] == 1
    assert all(f["line"] for f in rep["findings"] if f["id"] in {"PERM-001", "PERM-003"})


def test_perm_002_distinguishes_dangerous_from_broad_programs():
    _, rep = audit(FIXTURES / "risky-settings")
    perm2 = {f["title"]: f["severity"] for f in by_id(rep, "PERM-002")}
    assert any("rm" in t and s == "high" for t, s in perm2.items())
    assert any("git" in t and s == "medium" for t, s in perm2.items())
    assert any("curl" in t and s == "low" for t, s in perm2.items())


def test_perm_011_requires_broad_allow_without_deny(tmp_path):
    write(tmp_path, ".claude/settings.json", '{"permissions": {"allow": ["Write"]}}')
    _, rep = audit(tmp_path)
    assert "PERM-011" in ids(rep)
    write(
        tmp_path,
        ".claude/settings.json",
        '{"permissions": {"allow": ["Write"], "deny": ["Read(./.env)"]}}',
    )
    _, rep = audit(tmp_path)
    assert "PERM-011" not in ids(rep)


def test_dont_ask_mode_only_denies_so_it_is_not_reported(tmp_path):
    # https://code.claude.com/docs/en/permissions#permission-modes: dontAsk auto-denies every prompt.
    write(tmp_path, ".claude/settings.json", '{"permissions": {"defaultMode": "dontAsk"}}')
    _, rep = audit(tmp_path)
    assert "PERM-003" not in ids(rep)


@pytest.mark.parametrize("mode", ["default", "manual", "acceptEdits", "plan", "dontAsk"])
def test_prompting_or_restrictive_modes_are_not_reported(tmp_path, mode):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": mode}}))
    _, rep = audit(tmp_path)
    assert "PERM-003" not in ids(rep)


@pytest.mark.parametrize(
    ("mode", "project_sev", "user_sev"),
    [("bypassPermissions", "high", "critical"), ("auto", "low", "medium")],
)
def test_mode_severity_depends_on_settings_scope(tmp_path, mode, project_sev, user_sev):
    body = json.dumps({"permissions": {"defaultMode": mode}})
    write(tmp_path / "proj", ".claude/settings.json", body)
    _, rep = audit(tmp_path / "proj")
    assert [f["severity"] for f in by_id(rep, "PERM-003")] == [project_sev]
    user = write(tmp_path / "home", ".claude/settings.json", body)
    (tmp_path / "empty").mkdir()
    _, rep = audit(tmp_path / "empty", "--extra", str(user))
    assert [f["severity"] for f in by_id(rep, "PERM-003")] == [user_sev]


@pytest.mark.parametrize(
    ("rule", "fid", "severity"),
    [
        ("Bash(:*)", "PERM-001", "critical"),
        ("PowerShell", "PERM-001", "critical"),
        ("PowerShell(*)", "PERM-001", "critical"),
        ("Bash(rm:*)", "PERM-002", "high"),
        ("Bash(curl:*)", "PERM-002", "high"),
        ("Bash(git:*)", "PERM-002", "medium"),
        ("Bash(npm run test:*)", None, None),
        ("Bash(rm*)", "PERM-002", "high"),
        ("Bash(git * main)", "PERM-002", "medium"),
        ("Bash(* --version)", "PERM-002", "high"),
        ("Bash(timeout 30 rm -rf *)", "PERM-002", "high"),
        ("Bash(NODE_ENV=test curl *)", "PERM-002", "high"),
        ("Bash(timeout *)", None, None),
        ("Bash(npx *)", "PERM-002", "high"),
        ("Bash(npx prettier --check *)", None, None),
        ("Bash(devbox run *)", "PERM-002", "high"),
        ("Bash(docker exec:*)", "PERM-002", "high"),
        ("Bash(xargs *)", "PERM-002", "high"),
        ("PowerShell(Remove-Item *)", None, None),
        ("PowerShell(curl *)", "PERM-002", "high"),
    ],
)
def test_shell_rules_follow_current_claude_code_syntax(tmp_path, rule, fid, severity):
    # https://code.claude.com/docs/en/permissions#wildcard-patterns and #process-wrappers
    write(
        tmp_path,
        ".claude/settings.json",
        json.dumps({"permissions": {"allow": [rule], "deny": ["Read(./.env)"]}}),
    )
    _, rep = audit(tmp_path)
    shell = [f for f in rep["findings"] if f["id"] in {"PERM-001", "PERM-002"}]
    if fid is None:
        assert shell == []
    else:
        assert [(f["id"], f["severity"]) for f in shell] == [(fid, severity)]


def test_runner_finding_names_the_runner(tmp_path):
    write(
        tmp_path,
        ".claude/settings.json",
        json.dumps({"permissions": {"allow": ["Bash(devbox run *)"]}}),
    )
    _, rep = audit(tmp_path)
    assert (
        by_id(rep, "PERM-002")[0]["title"] == "Pre-approved runner executes any command: devbox run"
    )


@pytest.mark.parametrize(
    ("kind", "rule", "severity"),
    [
        ("allow", "*", "info"),
        ("allow", "B*", "info"),
        ("allow", "mcp__*", "info"),
        ("allow", "mcp__github(owner:me)", "info"),
        ("deny", "mcp__github__delete_repo(repo:*)", "medium"),
        ("deny", "Bash(command:rm *)", "medium"),
        ("ask", "Read(file_path:./.env)", "medium"),
        ("deny", "WebFetch(url : https://evil.example)", "medium"),
        ("deny", "Bash(git:* push)", "medium"),
    ],
)
def test_perm_013_rules_claude_code_ignores(tmp_path, kind, rule, severity):
    # https://code.claude.com/docs/en/permissions#tool-name-wildcards and #match-by-input-parameter
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {kind: [rule]}}))
    _, rep = audit(tmp_path)
    found = by_id(rep, "PERM-013")
    assert [(f["severity"], f["evidence"]) for f in found] == [(severity, rule)]
    assert "PERM-006" not in ids(rep)


@pytest.mark.parametrize(
    ("kind", "rule"),
    [
        ("deny", "*"),
        ("deny", "mcp__*"),
        ("allow", "mcp__github__get_*"),
        ("deny", "Agent(model:opus)"),
        ("deny", "Bash(run_in_background:true)"),
        ("deny", "Bash(git push:*)"),
        ("deny", "WebFetch(domain:*.example.com)"),
    ],
)
def test_perm_013_valid_rules_are_not_reported(tmp_path, kind, rule):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {kind: [rule]}}))
    _, rep = audit(tmp_path)
    assert "PERM-013" not in ids(rep)


@pytest.mark.parametrize(
    ("rule", "whole_server"),
    [
        ("mcp__github", True),
        ("mcp__github__*", True),
        ("mcp__github__get_*", False),
        ("mcp__github__get_issue", False),
    ],
)
def test_perm_006_only_for_a_whole_named_server(tmp_path, rule, whole_server):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}}))
    _, rep = audit(tmp_path)
    assert ("PERM-006" in ids(rep)) is whole_server


def test_malformed_permissions_do_not_crash(tmp_path):
    write(
        tmp_path,
        ".claude/settings.json",
        json.dumps(
            {"permissions": {"allow": "Bash", "deny": {"x": 1}, "additionalDirectories": "/"}}
        ),
    )
    rc, _ = audit(tmp_path)
    assert rc == 0
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": ["Bash"], "hooks": {}}))
    rc, _ = audit(tmp_path)
    assert rc == 0


def test_perm_002_treats_flags_before_a_wildcard_as_a_wildcard(tmp_path):
    write(
        tmp_path,
        ".claude/settings.json",
        '{"permissions": {"allow": ["Bash(rm -rf *)", "Bash(rm -rf ./build)"], "deny": ["Read(./.env)"]}}',
    )
    _, rep = audit(tmp_path)
    perm2 = {f["evidence"]: f["severity"] for f in by_id(rep, "PERM-002")}
    assert perm2["Bash(rm -rf *)"] == "high"
    assert perm2["Bash(rm -rf ./build)"] == "low"
