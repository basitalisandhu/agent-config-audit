"""docs/checks.md is generated from RULES (scripts/gen_checks_doc.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from agent_config_audit.patterns import SEVERITIES
from agent_config_audit.rules import RULES, rule_ids

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "checks.md"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_checks_doc", ROOT / "scripts" / "gen_checks_doc.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_rule_id_is_documented_with_an_anchor():
    text = DOC.read_text(encoding="utf-8")
    for rid in rule_ids():
        assert f'<a id="{rid.lower()}"></a>{rid} [' in text, rid


@pytest.mark.parametrize("rid", list(RULES))
def test_rule_entries_are_complete(rid):
    rule = RULES[rid]
    assert {"name", "category", "severity", "description", "levels", "trigger"} <= set(rule)
    assert rule["severity"] in SEVERITIES
    levels = [lvl.strip() for lvl in rule["levels"].split(",")]
    assert set(levels) <= set(SEVERITIES) and rule["severity"] in levels


def test_every_rule_category_has_a_table():
    covered = set().union(*(cats for cats, _ in _generator().TABLES.values()))
    assert {r["category"] for r in RULES.values()} <= covered


def test_checks_doc_is_current():
    gen = _generator()
    assert gen.main(["--check"]) == 0


def test_check_flags_a_stale_doc(monkeypatch, tmp_path):
    gen = _generator()
    stale = tmp_path / "checks.md"
    stale.write_text(
        DOC.read_text(encoding="utf-8").replace("PERM-001 [critical]", "PERM-001 [low]"),
        encoding="utf-8",
    )
    monkeypatch.setattr(gen, "DOC", stale)
    assert gen.main(["--check"]) == 1
    assert gen.main([]) == 0
    assert stale.read_text(encoding="utf-8") == DOC.read_text(encoding="utf-8")


def test_missing_marker_is_an_error():
    with pytest.raises(SystemExit):
        _generator().render("# no markers\n")
