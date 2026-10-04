from __future__ import annotations

from .conftest import FIXTURES, audit, by_id, ids, write


def test_instruction_file_patterns():
    _, rep = audit(FIXTURES / "injection")
    found = ids(rep)
    for fid in [
        "INJ-001",
        "INJ-002",
        "INJ-003",
        "INJ-004",
        "INJ-005",
        "INJ-006",
        "INJ-007",
        "INJ-008",
        "INJ-009",
    ]:
        assert fid in found, fid
    files = {f["file"] for f in rep["findings"]}
    assert ".cursor/rules/evil.mdc" in files
    assert all(f["line"] for f in rep["findings"] if f["id"].startswith("INJ"))


def test_negated_security_guidance_is_not_flagged():
    _, rep = audit(FIXTURES / "injection")
    agents = [f for f in rep["findings"] if f["file"] == "AGENTS.md"]
    # only the bidi override, not the "never send the API keys" guidance
    assert {f["id"] for f in agents} == {"INJ-005"}
    assert "Bidirectional" in agents[0]["title"]


def test_skill_and_agent_frontmatter():
    _, rep = audit(FIXTURES / "injection")
    found = ids(rep)
    assert "SKILL-001" in found
    assert "SKILL-002" in found
    perm = [f for f in by_id(rep, "PERM-003") if f["file"] == ".claude/agents/root.md"]
    assert perm and "bypassPermissions" in perm[0]["title"]


def test_skill_without_frontmatter_is_info(tmp_path):
    write(tmp_path, ".claude/skills/bare/SKILL.md", "Just a body.\n")
    _, rep = audit(tmp_path)
    f = by_id(rep, "SKILL-002")
    assert f and f[0]["severity"] == "info" and "no frontmatter" in f[0]["title"]


def test_benign_instruction_file_is_clean(tmp_path):
    write(
        tmp_path,
        "CLAUDE.md",
        "# Guide\n\nRun the tests with `pytest`. Never commit secrets. Do not run `rm -rf` on shared folders.\n"
        "Ask the user before deploying. Use the API key from the environment.\n",
    )
    rc, rep = audit(tmp_path)
    assert rc == 0 and rep["findings"] == [], rep["findings"]
