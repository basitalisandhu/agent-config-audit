from __future__ import annotations

import io
import json
import shutil
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from agent_config_audit.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def audit(root: Path, *extra: str) -> tuple[int, dict]:
    rc, out, _ = run(str(root), "--format", "json", *extra)
    return rc, json.loads(out)


def ids(rep: dict) -> set[str]:
    return {f["id"] for f in rep["findings"]}


def by_id(rep: dict, fid: str) -> list[dict]:
    return [f for f in rep["findings"] if f["id"] == fid]


# --------------------------------------------------------------------------- secret-shaped values
#
# Nothing committed to this repository may contain a string in a known credential format: GitHub
# push protection rejects the push and secret scanners flag the file. The tests still have to
# exercise every pattern, so each value is split into parts here and joined when the tests run.
# The join is a method call rather than a ``+`` of literals so that the byte-code cache does not
# hold the assembled value either (CPython folds constant expressions at compile time).


def secret(*parts: str) -> str:
    """Assemble a credential-shaped test value from its parts at run time."""
    return "".join(parts)


GITHUB_TOKEN = secret("ghp_", "A1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6", "Q7r8S9t0")
OPENAI_KEY = secret("sk-proj-", "Zx9Qw8Er7Ty6Ui5Op4As3Df2", "Gh1Jk0LzXcVbNm")
ANTHROPIC_KEY = secret("sk-ant-", "api03-Qp7zX2mL9vB4nR8tW3yK6cH1", "Fd5Gs0Jh2Lk4Mn6")
SLACK_TOKEN = secret("xoxb-", "1234567890-", "abcdefghijklmnop")
JWT = secret(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ".",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    ".",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
)
PRIVATE_KEY_HEADER = secret("-----BEGIN ", "RSA PRIVATE KEY-----")


# --------------------------------------------------------------------------- generated projects
#
# Fixture projects whose files would contain a secret-shaped value are not committed under
# tests/fixtures/; they are written into a temporary directory by the ``project`` fixture below.
# The file layout mirrors a committed fixture: {relative path: content}.


def _secrets_project() -> dict[str, str]:
    placeholder_openai = "sk-" + "x" * 39
    return {
        ".claude/settings.json": json.dumps({"env": {"OPENAI_API_KEY": OPENAI_KEY}}),
        ".cursor/mcp.json": json.dumps(
            {"mcpServers": {"s": {"command": "x", "env": {"SLACK_TOKEN": SLACK_TOKEN}}}}
        ),
        "CLAUDE.md": (
            f"Use OPENAI_API_KEY={placeholder_openai} as a placeholder.\n"
            "AWS key example: AKIAIOSFODNN7EXAMPLE\n"
            'api_key = "${API_KEY}"\n'
        ),
    }


def _risky_mcp_project() -> dict[str, str]:
    bearer = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    # One server per line so that every finding lands on a distinct line.
    mcp_json = (
        "{\n"
        '  "mcpServers": {\n'
        f'    "plain": {{"type": "http", "url": "http://mcp.example.com/mcp", "headers": {{"Authorization": "{bearer}"}}}},\n'
        '    "ip": {"type": "sse", "url": "https://93.184.216.34/sse"},\n'
        '    "unpinned": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},\n'
        '    "latest": {"command": "npx", "args": ["-y", "some-server@latest", "--dangerously-skip-permissions"]},\n'
        '    "pyun": {"command": "uvx", "args": ["mcp-server-fetch"]},\n'
        '    "tmp": {"command": "/tmp/downloaded/server", "args": []},\n'
        f'    "envsecret": {{"command": "node", "args": ["s.js"], "env": {{"GITHUB_TOKEN": "{GITHUB_TOKEN}"}}}},\n'
        '    "shelled": {"command": "sh", "args": ["-c", "node server.js"]},\n'
        '    "image": {"command": "docker", "args": ["run", "-i", "ghcr.io/example/server"]}\n'
        "  }\n"
        "}\n"
    )
    return {
        ".mcp.json": mcp_json,
        ".vscode/mcp.json": json.dumps(
            {"servers": {"x": {"type": "http", "url": "http://10.1.2.3:8000/mcp"}}}
        ),
        "elsewhere/claude_desktop_config.json": json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "~"],
                    }
                }
            }
        ),
    }


GENERATED_PROJECTS: dict[str, Callable[[], dict[str, str]]] = {
    "secrets": _secrets_project,
    "risky-mcp": _risky_mcp_project,
}


def build_project(name: str, dest: Path) -> Path:
    """Materialise fixture project ``name`` at ``dest``.

    Generated projects are written from GENERATED_PROJECTS; every other name is copied from
    tests/fixtures/<name> (a copy, so tests may change permission bits).
    """
    if name in GENERATED_PROJECTS:
        for rel, content in GENERATED_PROJECTS[name]().items():
            write(dest, rel, content)
    else:
        shutil.copytree(FIXTURES / name, dest)
    return dest.resolve()


@pytest.fixture
def project(tmp_path: Path):
    """Return a builder that materialises a named fixture project under tmp_path."""

    def _build(name: str) -> Path:
        return build_project(name, tmp_path / name)

    return _build
