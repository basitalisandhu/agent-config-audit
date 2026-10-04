from __future__ import annotations

import json

from .conftest import FIXTURES, audit, by_id, ids, write


def test_every_mcp_rule_fires(project):
    root = project("risky-mcp")
    _, rep = audit(root, "--extra", str(root / "elsewhere/claude_desktop_config.json"))
    found = ids(rep)
    for fid in [
        "MCP-001",
        "MCP-002",
        "MCP-003",
        "MCP-004",
        "MCP-005",
        "MCP-006",
        "MCP-007",
        "MCP-008",
        "SEC-001",
    ]:
        assert fid in found, fid


def test_tokens_never_appear_in_full(project):
    _, rep = audit(project("risky-mcp"))
    blob = json.dumps(rep)
    assert "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" not in blob
    assert "ghp_A1****" in blob
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in blob


def test_unpinned_detection_covers_npm_python_and_images(project):
    _, rep = audit(project("risky-mcp"))
    titles = [f["title"] for f in by_id(rep, "MCP-003")]
    assert any("unpinned npm package" in t for t in titles)
    assert any("@latest" in t for t in titles)
    assert any("unpinned Python package" in t for t in titles)
    assert any("container image" in t for t in titles)


def test_shell_launch_is_low_and_flag_is_medium(project):
    _, rep = audit(project("risky-mcp"))
    mcp5 = {f["title"]: f["severity"] for f in by_id(rep, "MCP-005")}
    assert any("shell string" in t and s == "low" for t, s in mcp5.items())
    assert any("--dangerously-skip-permissions" in t and s == "medium" for t, s in mcp5.items())


def test_vscode_servers_shape_and_raw_ip(project):
    _, rep = audit(project("risky-mcp"))
    vscode = [f for f in rep["findings"] if f["file"] == ".vscode/mcp.json"]
    assert {f["id"] for f in vscode} >= {"MCP-001", "MCP-008"}


def test_extra_file_outside_root_is_reported_with_absolute_path(project):
    desktop = project("risky-mcp") / "elsewhere/claude_desktop_config.json"
    _, rep = audit(FIXTURES / "clean", "--extra", str(desktop))
    fs = [f for f in rep["findings"] if f["id"] == "MCP-007"]
    assert fs and fs[0]["file"] == desktop.as_posix()


def test_loopback_plain_http_is_allowed(tmp_path):
    write(
        tmp_path,
        ".mcp.json",
        json.dumps({"mcpServers": {"dev": {"type": "http", "url": "http://localhost:8000/mcp"}}}),
    )
    _, rep = audit(tmp_path)
    assert "MCP-001" not in ids(rep) and "MCP-008" not in ids(rep)


def test_codex_toml_and_broken_json():
    _, rep = audit(FIXTURES / "codex")
    found = ids(rep)
    assert {"PERM-003", "MCP-001", "CFG-001"} <= found
    assert len(by_id(rep, "PERM-003")) == 2
