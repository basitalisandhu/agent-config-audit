#!/usr/bin/env python3
"""Render the rule tables in docs/checks.md from agent_config_audit.rules.RULES.

Each table sits between ``<!-- rules:NAME -->`` and ``<!-- /rules:NAME -->`` markers; everything
outside the markers is hand-written prose and is kept as it is.

    python scripts/gen_checks_doc.py           # rewrite docs/checks.md
    python scripts/gen_checks_doc.py --check   # exit 1 when docs/checks.md is stale
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent_config_audit.rules import RULES  # noqa: E402

DOC = ROOT / "docs" / "checks.md"

# table name -> (rule categories in the table, whether it has a "Why it matters" column)
TABLES: dict[str, tuple[set[str], bool]] = {
    "permissions": ({"permissions"}, True),
    "hooks": ({"hooks"}, True),
    "mcp": ({"mcp"}, True),
    "secrets": ({"secret"}, False),
    "injection": ({"injection"}, False),
    "other": ({"skill", "plugin", "file", "config"}, False),
}


def render_table(name: str) -> str:
    categories, with_why = TABLES[name]
    lines = (
        ["| ID | Trigger | Why it matters |", "|---|---|---|"]
        if with_why
        else ["| ID | Trigger |", "|---|---|"]
    )
    for rid, rule in RULES.items():
        if rule["category"] not in categories:
            continue
        cell = f'<a id="{rid.lower()}"></a>{rid} [{rule["levels"]}]'
        if with_why:
            lines.append(
                f"| {cell} | {rule['trigger']} | {rule.get('why') or rule['description']} |"
            )
        else:
            lines.append(f"| {cell} | {rule['trigger']} |")
    return "\n".join(lines)


def render(text: str) -> str:
    for name in TABLES:
        pattern = re.compile(rf"(<!-- rules:{name} -->\n).*?(\n<!-- /rules:{name} -->)", re.S)
        if not pattern.search(text):
            raise SystemExit(
                f"docs/checks.md has no <!-- rules:{name} --> ... <!-- /rules:{name} --> block"
            )
        text = pattern.sub(lambda m, name=name: m.group(1) + render_table(name) + m.group(2), text)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 when docs/checks.md is out of date"
    )
    args = parser.parse_args(argv)
    current = DOC.read_text(encoding="utf-8")
    wanted = render(current)
    if args.check:
        if current != wanted:
            print("docs/checks.md is stale; run: python scripts/gen_checks_doc.py", file=sys.stderr)
            return 1
        return 0
    DOC.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
