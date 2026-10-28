"""The `hooks:` block of skill and subagent front matter, read with a small YAML subset parser.

Claude Code reads hooks from SKILL.md and subagent front matter in the same shape as settings
hooks (https://code.claude.com/docs/en/hooks#hooks-in-skills-and-agents). This module reads
block mappings, block sequences (`- key: value` items included) and plain, single-quoted or
double-quoted scalars, which is what that shape needs. Flow collections (`[a, b]`, `{a: b}`)
are kept as plain strings. Anything it cannot read gives None instead of raising, and every
step consumes at least one line, so no input can make it loop.
"""

from __future__ import annotations

import json
import re

_KEY = re.compile(r"^([^\s:#'\"][^:#]*?|\"[^\"]*\"|'[^']*')\s*:(?:\s+(.*))?$")


def _scalar(raw: str):
    value = raw.strip()
    if value.startswith('"'):
        end = value.rfind('"')
        if end > 0:
            try:
                return json.loads(value[: end + 1])
            except ValueError:
                return value[1:end]
        return value[1:]
    if value.startswith("'"):
        end = value.rfind("'")
        return value[1:end].replace("''", "'") if end > 0 else value[1:]
    value = re.sub(r"\s+#.*$", "", value)
    if value in {"", "~", "null"}:
        return None
    if value in {"true", "false"}:
        return value == "true"
    return value


def _lines(block: str) -> list[tuple[int, str]]:
    out = []
    for raw in block.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        expanded = raw.replace("\t", "    ")
        out.append((len(expanded) - len(expanded.lstrip(" ")), expanded.strip()))
    return out


def _parse(lines: list[tuple[int, str]], i: int, indent: int, depth: int):
    """Parse the node starting at lines[i] with this indent; return (value, next index)."""
    if depth > 50 or i >= len(lines):
        return None, len(lines)
    if lines[i][1] == "-" or lines[i][1].startswith("- "):
        items = []
        while (
            i < len(lines)
            and lines[i][0] == indent
            and (lines[i][1] == "-" or lines[i][1].startswith("- "))
        ):
            rest = lines[i][1][1:].strip()
            if not rest:
                if i + 1 < len(lines) and lines[i + 1][0] > indent:
                    value, i = _parse(lines, i + 1, lines[i + 1][0], depth + 1)
                else:
                    value, i = None, i + 1
            elif _KEY.match(rest) and not rest.startswith(("- ", "-")):
                # "- key: value" starts a mapping indented to where "key" begins.
                inner = indent + (len(lines[i][1]) - len(rest))
                lines[i] = (inner, rest)
                value, i = _parse(lines, i, inner, depth + 1)
            elif rest == "-" or rest.startswith("- "):
                inner = indent + (len(lines[i][1]) - len(rest))
                lines[i] = (inner, rest)
                value, i = _parse(lines, i, inner, depth + 1)
            else:
                value, i = _scalar(rest), i + 1
            items.append(value)
        return items, i
    mapping: dict = {}
    while i < len(lines) and lines[i][0] == indent:
        m = _KEY.match(lines[i][1])
        if not m or lines[i][1].startswith("- "):
            return (mapping or None), i + (0 if mapping else 1)
        key = _scalar(m.group(1)) if m.group(1)[:1] in "\"'" else m.group(1).strip()
        rest = m.group(2)
        i += 1
        if rest is not None and rest.strip() and not rest.strip().startswith("#"):
            mapping[key] = _scalar(rest)
        elif i < len(lines) and (
            lines[i][0] > indent
            or (lines[i][0] == indent and (lines[i][1] == "-" or lines[i][1].startswith("- ")))
        ):
            mapping[key], i = _parse(lines, i, lines[i][0], depth + 1)
        else:
            mapping[key] = None
    return mapping, i


def front_matter_hooks(front_matter: str) -> dict | None:
    """The hooks mapping from front matter text (no --- fences), or None when there is none."""
    block: list[str] = []
    inside = False
    for raw in front_matter.splitlines():
        if not inside:
            if re.match(r"^hooks\s*:\s*(#.*)?$", raw):
                inside = True
            continue
        if raw.strip() and not raw[:1].isspace() and not raw.startswith("-"):
            break
        block.append(raw)
    if not inside:
        return None
    lines = _lines("\n".join(block))
    if not lines:
        return None
    value, _ = _parse(lines, 0, lines[0][0], 0)
    return value if isinstance(value, dict) else None
