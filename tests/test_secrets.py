from __future__ import annotations

import json

from agent_config_audit.findings import redact, shannon_entropy

from .conftest import ANTHROPIC_KEY, GITHUB_TOKEN, JWT, PRIVATE_KEY_HEADER, audit, by_id, write


def test_known_patterns_and_placeholders(project):
    _, rep = audit(project("secrets"))
    titles = {f["title"] for f in by_id(rep, "SEC-001")}
    assert any("OpenAI" in t for t in titles), titles
    assert any("Slack" in t for t in titles), titles
    assert not any("AWS" in t for t in titles), "AKIA...EXAMPLE is a documented placeholder"
    assert "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVbNm" not in json.dumps(rep)


def test_generic_assignment_requires_entropy(tmp_path):
    high_entropy = "Qp7zX2mL9vB4nR8tW3yK6cH1"
    write(
        tmp_path,
        "CLAUDE.md",
        f'password = "aaaaaaaaaaaaaaaaaaaa"\nsecret_key = "{high_entropy}"\n',
    )
    _, rep = audit(tmp_path)
    sec = by_id(rep, "SEC-001")
    assert len(sec) == 1 and sec[0]["line"] == 2
    assert "Qp7zX2mL9vB4nR8tW3yK6cH1" not in sec[0]["evidence"]


def test_private_key_block_and_jwt(tmp_path):
    write(
        tmp_path,
        ".mcp.json",
        json.dumps({"mcpServers": {"a": {"command": "x", "env": {"KEY": PRIVATE_KEY_HEADER}}}}),
    )
    write(tmp_path, "AGENTS.md", f"token: {JWT}\n")
    _, rep = audit(tmp_path)
    titles = {f["title"] for f in by_id(rep, "SEC-001")}
    assert any("Private key" in t for t in titles)
    assert any("JSON Web Token" in t for t in titles)


def test_redact_masks_values():
    high_entropy = "Zx9Qw8Er7Ty6Ui5Op4As3Df2"
    assert "****" in redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    assert "****" in redact(f'api_key = "{high_entropy}"')
    assert redact("plain text") == "plain text"
    assert redact(GITHUB_TOKEN) == "ghp_A1****t0"


def test_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcdefgh") > 2.9


def test_anthropic_key_is_not_reported_as_openai(tmp_path):
    write(
        tmp_path,
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "a": {
                        "type": "http",
                        "url": "https://example.com/mcp",
                        "headers": {"Authorization": f"Bearer {ANTHROPIC_KEY}"},
                    }
                }
            }
        ),
    )
    _, rep = audit(tmp_path)
    titles = {f["title"] for f in by_id(rep, "SEC-001")} | {
        f["title"] for f in by_id(rep, "MCP-002")
    }
    assert any("Anthropic" in t for t in titles), titles
    assert not any("OpenAI" in t for t in titles), titles
