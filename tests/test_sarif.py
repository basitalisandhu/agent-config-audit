"""Structural validation of the SARIF output against the parts of the 2.1.0 schema we rely on."""

from __future__ import annotations

import json
from pathlib import Path

from agent_config_audit.report import sarif_document, to_sarif
from agent_config_audit.rules import RULES
from agent_config_audit.scanner import Auditor

from .conftest import FIXTURES

REQUIRED_RULE_KEYS = {
    "id",
    "name",
    "shortDescription",
    "fullDescription",
    "helpUri",
    "defaultConfiguration",
    "properties",
}


def _doc(root: Path) -> dict:
    a = Auditor(root)
    a.run()
    return sarif_document(a.report())


def test_top_level_structure(project):
    doc = _doc(project("risky-mcp"))
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert (
        driver["name"] == "agent-config-audit"
        and driver["version"]
        and driver["informationUri"].startswith("https://")
    )
    assert "%SRCROOT%" in run["originalUriBaseIds"]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file://")
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].endswith("/")


def test_rules_are_complete_and_unique():
    rules = _doc(FIXTURES / "clean")["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == list(RULES) and len(set(ids)) == len(ids)
    for r in rules:
        assert set(r) >= REQUIRED_RULE_KEYS
        assert r["defaultConfiguration"]["level"] in {"error", "warning", "note", "none"}
        assert r["shortDescription"]["text"] and r["fullDescription"]["text"]
        assert float(r["properties"]["security-severity"]) >= 0.0
        assert " " not in r["name"]


def test_results_reference_rules_and_locations(project):
    doc = _doc(project("risky-mcp"))
    run = doc["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert run["results"], "fixture should produce findings"
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        assert res["message"]["text"]
        assert len(res["locations"]) == 1
        phys = res["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"]
        assert "\\" not in phys["artifactLocation"]["uri"]
        if "region" in phys:
            assert phys["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["agentConfigAudit/v1"]
        assert res["properties"]["severity"] in {"critical", "high", "medium", "low", "info"}


def test_relative_uris_use_srcroot_and_absolute_do_not(project):
    a = Auditor(
        FIXTURES / "clean", extra=[project("risky-mcp") / "elsewhere/claude_desktop_config.json"]
    )
    a.run()
    doc = sarif_document(a.report())
    locs = [
        r["locations"][0]["physicalLocation"]["artifactLocation"] for r in doc["runs"][0]["results"]
    ]
    assert locs, "expected findings from the extra file"
    for loc in locs:
        if loc["uri"].startswith("/"):
            assert "uriBaseId" not in loc
        else:
            assert loc["uriBaseId"] == "%SRCROOT%"


def test_artifacts_and_invocations():
    doc = _doc(FIXTURES / "codex")
    run = doc["runs"][0]
    assert {a["location"]["uri"] for a in run["artifacts"]} == {".codex/config.toml", ".mcp.json"}
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert isinstance(inv["toolExecutionNotifications"], list)


def test_sarif_serialises_and_is_deterministic():
    a = Auditor(FIXTURES / "risky-settings")
    a.run()
    rep = a.report()
    first, second = to_sarif(rep), to_sarif(rep)
    assert first == second
    assert json.loads(first)["runs"][0]["results"]


def test_fingerprints_are_stable_across_runs():
    f1 = {
        r["partialFingerprints"]["agentConfigAudit/v1"]
        for r in _doc(FIXTURES / "risky-settings")["runs"][0]["results"]
    }
    f2 = {
        r["partialFingerprints"]["agentConfigAudit/v1"]
        for r in _doc(FIXTURES / "risky-settings")["runs"][0]["results"]
    }
    assert f1 == f2 and all(len(x) == 64 for x in f1)
