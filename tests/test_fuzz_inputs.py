"""Seeded fuzz tests: bad bytes and wrong value types in every file the audit reads.

An audit must end with exit code 0 or 1 (unreadable config files are reported, not fatal), and a bad --baseline,
--config or allowlist file with exit code 2 and a message naming it. Each run has a time limit, so a hang fails
the test instead of stalling CI.
"""

from __future__ import annotations

import contextlib
import io
import json
import random
import shutil
import threading
from pathlib import Path

import pytest

from agent_config_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
FILES = sorted(
    (fixture.name, str(p.relative_to(fixture)))
    for fixture in FIXTURES.iterdir()
    if fixture.is_dir()
    for p in fixture.rglob("*")
    if p.is_file()
)


def _parses(fixture: str, rel: str) -> bool:
    try:
        json.loads((FIXTURES / fixture / rel).read_text(encoding="utf-8"))
    except ValueError:
        return False  # deliberately broken fixtures
    return True


JSON_FILES = [(f, r) for f, r in FILES if r.endswith(".json") and _parses(f, r)]
SEED = 20261028
BAD = {
    "empty": b"",
    "not-utf8": b"\xff\xfe\x00"
    + bytes(random.Random(SEED).randrange(128, 256) for _ in range(256)),
    "truncated": b'{"permissions": {"allow": [',
    "deep-json": b"[" * 50_000 + b"]" * 50_000,
    "deep-toml": b"a = " + b"[" * 50_000 + b"]" * 50_000,
    "nul": b"\x00" * 64,
}
WRONG = [None, True, 7, -1.5, "x", [], {}, [1, [2]], {"a": {"b": None}}, "*"]


def _run(argv: list[str], limit: float = 30.0) -> tuple[int, str]:
    out: dict[str, object] = {}

    def target() -> None:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                out["code"] = main(argv)
            except SystemExit as e:
                out["code"] = e.code
            except BaseException as e:  # the test reports any escape as a crash
                out["crash"] = repr(e)
        out["text"] = sink.getvalue()

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(limit)
    assert not t.is_alive(), f"agent-config-audit {' '.join(argv)} did not finish in {limit}s"
    assert "crash" not in out, out["crash"]
    return out["code"], out["text"]  # type: ignore[return-value]


@pytest.mark.parametrize("kind", sorted(BAD))
@pytest.mark.parametrize(("fixture", "rel"), FILES, ids=[f"{f}/{r}" for f, r in FILES])
def test_bad_bytes_never_crash(tmp_path, fixture, rel, kind):
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / fixture, root)
    (root / rel).write_bytes(BAD[kind])
    code, text = _run([str(root), "--format", "json"])
    if rel.endswith(".agent-config-audit.toml"):
        # The allowlist is the user's own input: a bad one is exit code 2 naming the file.
        assert code == 2 or kind == "empty", text[-500:]
        if code == 2:
            assert ".agent-config-audit.toml" in text
        return
    assert code == 0, text[-500:]


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _paths(v, (*prefix, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _paths(v, (*prefix, i))


@pytest.mark.parametrize(("fixture", "rel"), JSON_FILES, ids=[f"{f}/{r}" for f, r in JSON_FILES])
def test_wrong_types_never_crash(tmp_path, fixture, rel):
    rng = random.Random(f"{SEED}/{fixture}/{rel}")
    original = json.loads((FIXTURES / fixture / rel).read_text(encoding="utf-8"))
    for trial in range(25):
        doc = json.loads(json.dumps(original))
        for _ in range(rng.randint(1, 3)):
            paths = [p for p in _paths(doc) if p]
            if not paths:
                doc = json.loads(json.dumps(rng.choice(WRONG)))
                break
            path = rng.choice(paths)
            node = doc
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = json.loads(json.dumps(rng.choice(WRONG)))
        root = tmp_path / f"repo{trial}"
        shutil.copytree(FIXTURES / fixture, root)
        (root / rel).write_text(json.dumps(doc), encoding="utf-8")
        code, text = _run([str(root)])
        assert code == 0, (json.dumps(doc)[:300], text[-500:])


@pytest.mark.parametrize("kind", ["empty", "not-utf8", "truncated", "deep-json", "nul"])
def test_bad_baseline_exits_2(tmp_path, kind):
    bad = tmp_path / "old-report.json"
    bad.write_bytes(BAD[kind])
    code, text = _run([str(FIXTURES / "clean"), "--baseline", str(bad)])
    assert code == 2, text
    assert "old-report.json" in text


@pytest.mark.parametrize("kind", ["not-utf8", "truncated", "deep-toml", "nul"])
def test_bad_config_exits_2(tmp_path, kind):
    bad = tmp_path / "audit.toml"
    bad.write_bytes(BAD[kind])
    code, text = _run([str(FIXTURES / "clean"), "--config", str(bad)])
    assert code == 2, text
    assert "audit.toml" in text


@pytest.mark.parametrize("kind", sorted(BAD))
def test_bad_extra_file_never_crashes(tmp_path, kind):
    extra = tmp_path / "claude_desktop_config.json"
    extra.write_bytes(BAD[kind])
    code, text = _run([str(FIXTURES / "clean"), "--extra", str(extra)])
    assert code == 0, text[-500:]
