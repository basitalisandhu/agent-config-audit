"""Report renderers: table, JSON, Markdown and SARIF 2.1.0."""

from __future__ import annotations

import hashlib
import json

from . import __version__
from .patterns import SEVERITIES
from .rules import HELP_URI, RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}
FORMATS = ("table", "json", "sarif", "markdown")


def to_json(rep: dict) -> str:
    return json.dumps(rep, indent=1, ensure_ascii=False) + "\n"


def to_table(rep: dict) -> str:
    s = rep["summary"]
    findings = rep["findings"]
    lines = [
        f"agent-config-audit {rep['version']}: {len(rep['scanned_files'])} file(s) scanned under {rep['root']}",
    ]
    if findings:
        rows = []
        for f in findings:
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            rows.append((f["severity"].upper(), f["id"], where, f["title"]))
        widths = [
            max(len(r[i]) for r in [*rows, ("SEVERITY", "ID", "FILE", "FINDING")]) for i in range(3)
        ]
        header = f"{'SEVERITY':<{widths[0]}}  {'ID':<{widths[1]}}  {'FILE':<{widths[2]}}  FINDING"
        lines += ["", header, "-" * len(header)]
        for sev, fid, where, title in rows:
            lines.append(f"{sev:<{widths[0]}}  {fid:<{widths[1]}}  {where:<{widths[2]}}  {title}")
        lines.append("")
        counts = ", ".join(f"{s[sev]} {sev}" for sev in SEVERITIES if s[sev])
        lines.append(f"{s['total']} finding(s): {counts}.")
        if s.get("suppressed"):
            lines.append(f"{s['suppressed']} finding(s) suppressed by configuration.")
        lines += ["", "Fixes:"]
        seen: set[str] = set()
        for f in findings:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            lines.append(f"  {f['id']}: {f['recommendation']}")
    else:
        lines.append(
            "No findings. The scanned configuration has no risky permissions, secrets, unpinned servers or injection patterns that this tool detects."
        )
        if s.get("suppressed"):
            lines.append(f"{s['suppressed']} finding(s) suppressed by configuration.")
    if rep["errors"]:
        lines += ["", "Scan errors:"] + [f"  {e}" for e in rep["errors"]]
    return "\n".join(lines) + "\n"


def to_markdown(rep: dict) -> str:
    s = rep["summary"]
    lines = (
        [
            "# Agent configuration audit",
            "",
            f"Root: `{rep['root']}`  ",
            f"Files scanned: {len(rep['scanned_files'])}  ",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]
        + [f"| {sev} | {s[sev]} |" for sev in SEVERITIES]
        + ["", f"Total findings: {s['total']}", ""]
    )
    if rep["findings"]:
        lines += ["| ID | Severity | Title | File | Line | Evidence |", "|---|---|---|---|---|---|"]
        for f in rep["findings"]:
            ev = f["evidence"].replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {f['id']} | {f['severity']} | {f['title']} | `{f['file']}` | {f['line'] or ''} | `{ev[:80]}` |"
            )
        lines += ["", "## Recommendations", ""]
        seen: set[str] = set()
        for f in rep["findings"]:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            lines.append(f"- **{f['id']}** ({f['severity']}): {f['recommendation']}")
    else:
        lines.append(
            "No findings. The scanned configuration has no risky permissions, secrets, unpinned servers or injection patterns that this tool detects."
        )
    if rep.get("suppressed"):
        lines += ["", "## Suppressed by configuration", ""] + [
            f"- {x['id']} in `{x['file']}`: {x['reason']}" for x in rep["suppressed"]
        ]
    if rep["errors"]:
        lines += ["", "## Scan errors", ""] + [f"- {e}" for e in rep["errors"]]
    lines += ["", "## Files scanned", ""] + [f"- `{p}`" for p in rep["scanned_files"]]
    return "\n".join(lines) + "\n"


def _fingerprint(f: dict) -> str:
    raw = "|".join([f["id"], f["file"], str(f["line"] or 0), f["evidence"]])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sarif_document(rep: dict) -> dict:
    rule_ids = list(RULES)
    rules = []
    for rid in rule_ids:
        r = RULES[rid]
        rules.append(
            {
                "id": rid,
                "name": r["name"].replace(" ", ""),
                "shortDescription": {"text": r["name"]},
                "fullDescription": {"text": r["description"]},
                "helpUri": f"{HELP_URI}#{rid.lower()}",
                "help": {"text": r["description"]},
                "defaultConfiguration": {"level": SARIF_LEVELS[r["severity"]]},
                "properties": {
                    "category": r["category"],
                    "security-severity": SECURITY_SEVERITY[r["severity"]],
                    "tags": ["security", "agent-configuration", r["category"]],
                },
            }
        )
    results = []
    for f in rep["findings"]:
        uri = f["file"].replace("\\", "/")
        location: dict = {"artifactLocation": {"uri": uri}}
        if not uri.startswith("/"):
            location["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
        if f["line"]:
            location["region"] = {"startLine": int(f["line"])}
        results.append(
            {
                "ruleId": f["id"],
                "ruleIndex": rule_ids.index(f["id"]),
                "level": SARIF_LEVELS[f["severity"]],
                "message": {"text": f"{f['title']}. {f['recommendation']}"},
                "locations": [{"physicalLocation": location}],
                "partialFingerprints": {"agentConfigAudit/v1": _fingerprint(f)},
                "properties": {
                    "severity": f["severity"],
                    "category": f["category"],
                    "evidence": f["evidence"],
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-config-audit",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/basitalisandhu/agent-config-audit",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": _as_uri(rep["root"])}},
                "artifacts": [
                    {
                        "location": {
                            "uri": p.replace("\\", "/"),
                            **({} if p.startswith("/") else {"uriBaseId": "%SRCROOT%"}),
                        }
                    }
                    for p in rep["scanned_files"]
                ],
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": e}} for e in rep["errors"]
                        ],
                    }
                ],
            }
        ],
    }


def _as_uri(path: str) -> str:
    p = path.replace("\\", "/")
    if not p.endswith("/"):
        p += "/"
    return "file://" + p if p.startswith("/") else "file:///" + p


def to_sarif(rep: dict) -> str:
    return json.dumps(sarif_document(rep), indent=1) + "\n"


def render(rep: dict, fmt: str) -> str:
    if fmt == "json":
        return to_json(rep)
    if fmt == "sarif":
        return to_sarif(rep)
    if fmt == "markdown":
        return to_markdown(rep)
    return to_table(rep)
