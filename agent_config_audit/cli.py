"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .findings import at_or_above
from .patterns import SEVERITIES
from .report import FORMATS, render
from .scanner import Auditor

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-config-audit",
        description=(
            "Audit AI agent configuration files for security risks: risky permissions, leaked "
            "secrets, unpinned MCP servers, exfiltrating hooks and prompt-injection patterns in "
            "instruction files. Read-only, standard library only, no network."
        ),
    )
    p.add_argument(
        "root",
        nargs="?",
        default=".",
        help="project directory to audit (default: current directory)",
    )
    p.add_argument(
        "--extra",
        action="append",
        default=[],
        metavar="FILE",
        help="additional file to audit, for example a claude_desktop_config.json (repeatable)",
    )
    p.add_argument(
        "--include-home",
        action="store_true",
        help="also audit the user-level config files in the home directory",
    )
    p.add_argument(
        "--format", choices=FORMATS, default="table", help="report format (default: table)"
    )
    p.add_argument(
        "--output", "-o", metavar="FILE", help="write the report to this file instead of stdout"
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        metavar="SEVERITY",
        help=f"exit 1 when a finding of this severity or higher exists ({', '.join(SEVERITIES)})",
    )
    p.add_argument(
        "--config",
        metavar="FILE",
        help="allowlist file (default: .agent-config-audit.toml in the root, if present)",
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE",
        help="rule id to leave out of the report (repeatable)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="file or directory glob to skip, relative to the root (repeatable)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(root, Path(args.config) if args.config else None)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    config.ignore_ids |= set(args.ignore)
    config.exclude_paths += list(args.exclude)
    auditor = Auditor(
        root, include_home=args.include_home, extra=[Path(e) for e in args.extra], config=config
    )
    auditor.run()
    rep = auditor.report()
    text = render(rep, args.format)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output} ({rep['summary']['total']} findings)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.fail_on and any(at_or_above(f["severity"], args.fail_on) for f in rep["findings"]):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
