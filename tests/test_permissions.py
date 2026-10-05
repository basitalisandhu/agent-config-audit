from __future__ import annotations

import json

import pytest

from .conftest import FIXTURES, audit, by_id, ids


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
    ],
)
def test_perm_012_secret_path_read_allow(tmp_path, spec):
    from .conftest import write

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
    ],
)
def test_perm_012_ordinary_or_non_read_rules_are_not_secret_reads(tmp_path, rule):
    from .conftest import write

    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}}))
    _, rep = audit(tmp_path)
    assert "PERM-012" not in ids(rep)


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
    assert sev["PERM-003"] == "critical"
    assert rep["summary"]["critical"] == 2
    assert all(f["line"] for f in rep["findings"] if f["id"] in {"PERM-001", "PERM-003"})


def test_perm_002_distinguishes_dangerous_from_broad_programs():
    _, rep = audit(FIXTURES / "risky-settings")
    perm2 = {f["title"]: f["severity"] for f in by_id(rep, "PERM-002")}
    assert any("rm" in t and s == "high" for t, s in perm2.items())
    assert any("git" in t and s == "medium" for t, s in perm2.items())
    assert any("curl" in t and s == "low" for t, s in perm2.items())


def test_perm_011_requires_broad_allow_without_deny(tmp_path):
    from .conftest import write

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


def test_dont_ask_mode_is_medium(tmp_path):
    from .conftest import write

    write(tmp_path, ".claude/settings.json", '{"permissions": {"defaultMode": "dontAsk"}}')
    _, rep = audit(tmp_path)
    f = by_id(rep, "PERM-003")
    assert f and f[0]["severity"] == "medium"


def test_perm_002_treats_flags_before_a_wildcard_as_a_wildcard(tmp_path):
    from .conftest import write

    write(
        tmp_path,
        ".claude/settings.json",
        '{"permissions": {"allow": ["Bash(rm -rf *)", "Bash(rm -rf ./build)"], "deny": ["Read(./.env)"]}}',
    )
    _, rep = audit(tmp_path)
    perm2 = {f["evidence"]: f["severity"] for f in by_id(rep, "PERM-002")}
    assert perm2["Bash(rm -rf *)"] == "high"
    assert perm2["Bash(rm -rf ./build)"] == "low"
