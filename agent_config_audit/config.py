"""Allowlist configuration: which rules, paths and specific findings to leave out of a report.

Looked up as ``.agent-config-audit.toml`` in the audited root unless ``--config`` names a file::

    [allow]
    ids = ["PERM-011"]              # never report these rule ids
    paths = ["docs/**", "examples/*"]   # skip files matching these globs (relative to the root)

    [[suppress]]                    # drop one specific finding
    id = "MCP-003"
    path = ".mcp.json"              # glob, relative to the root
    evidence = "some-server"        # optional substring of the evidence
    reason = "pinned through the lockfile"
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import SEVERITIES
from .rules import RULES

CONFIG_NAME = ".agent-config-audit.toml"


class ConfigError(ValueError):
    pass


@dataclass
class Suppression:
    id: str
    path: str = "*"
    evidence: str = ""
    reason: str = ""

    def matches(self, finding_id: str, file: str, evidence: str) -> bool:
        if self.id != finding_id:
            return False
        if not (fnmatch.fnmatch(file, self.path) or fnmatch.fnmatch(file, "**/" + self.path)):
            return False
        return not self.evidence or self.evidence in evidence


@dataclass
class AuditConfig:
    ignore_ids: set[str] = field(default_factory=set)
    exclude_paths: list[str] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    source: str | None = None

    def path_excluded(self, rel: str) -> bool:
        parts = rel.split("/")
        for pat in self.exclude_paths:
            if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat) for p in parts):
                return True
            # "docs/**" should also match "docs/a.md"
            if pat.endswith("/**") and rel.startswith(pat[:-2]):
                return True
        return False

    def allows(self, finding_id: str, file: str, evidence: str) -> str | None:
        """Return a reason when the finding is allowlisted, else None."""
        if finding_id in self.ignore_ids:
            return f"rule {finding_id} ignored by configuration"
        for s in self.suppressions:
            if s.matches(finding_id, file, evidence):
                return s.reason or f"suppressed by configuration ({s.path})"
        return None


def _check_ids(ids: list[str], where: str) -> None:
    for fid in ids:
        if fid not in RULES:
            raise ConfigError(f"{where}: unknown rule id {fid!r}")


def parse_config(text: str, source: str | None = None) -> AuditConfig:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source or 'config'}: {exc}") from exc
    cfg = AuditConfig(source=source)
    allow = data.get("allow", {})
    if not isinstance(allow, dict):
        raise ConfigError("[allow] must be a table")
    ids = allow.get("ids", [])
    paths = allow.get("paths", [])
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise ConfigError("allow.ids must be a list of strings")
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise ConfigError("allow.paths must be a list of strings")
    _check_ids(ids, "allow.ids")
    cfg.ignore_ids = set(ids)
    cfg.exclude_paths = list(paths)
    for i, entry in enumerate(data.get("suppress", [])):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ConfigError(f"suppress[{i}] needs an 'id' string")
        _check_ids([entry["id"]], f"suppress[{i}]")
        cfg.suppressions.append(
            Suppression(
                id=entry["id"],
                path=str(entry.get("path", "*")),
                evidence=str(entry.get("evidence", "")),
                reason=str(entry.get("reason", "")),
            )
        )
    min_sev = data.get("min_severity")
    if min_sev is not None and min_sev not in SEVERITIES:
        raise ConfigError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    return cfg


def load_config(root: Path, explicit: Path | None = None) -> AuditConfig:
    path = explicit or (root / CONFIG_NAME)
    if explicit is None and not path.is_file():
        return AuditConfig()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    return parse_config(path.read_text(encoding="utf-8"), source=str(path))
