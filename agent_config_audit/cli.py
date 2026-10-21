"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .findings import at_or_above
from .patterns import SEVERITIES
from .report import FORMATS, render
from .rules import RULES
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
        type=str.lower,
        choices=SEVERITIES,
        metavar="SEVERITY",
        help=f"exit 1 when a finding of this severity or higher exists ({', '.join(SEVERITIES)})",
    )
    p.add_argument(
        "--baseline",
        metavar="FILE",
        help="JSON report from a previous run; omit findings already present in it",
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
    baseline_keys = None
    if args.baseline:
        try:
            baseline_report = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not load baseline {args.baseline}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        baseline_findings = (
            baseline_report.get("findings") if isinstance(baseline_report, dict) else None
        )
        if not isinstance(baseline_findings, list):
            print(
                f"error: baseline {args.baseline} must be a JSON report with a findings array",
                file=sys.stderr,
            )
            return EXIT_USAGE
        baseline_keys = set()
        for index, finding in enumerate(baseline_findings):
            if not isinstance(finding, dict) or not all(
                isinstance(finding.get(key), str) for key in ("id", "file", "evidence")
            ):
                print(
                    f"error: baseline {args.baseline} has an invalid finding at index {index}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            baseline_keys.add((finding["id"], finding["file"], finding["evidence"]))
    try:
        config = load_config(root, Path(args.config) if args.config else None)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    missing = [e for e in args.extra if not Path(e).is_file()]
    if missing:
        print(f"error: --extra {missing[0]} is not a file", file=sys.stderr)
        return EXIT_USAGE
    unknown = sorted({i for i in args.ignore if i not in RULES})
    if unknown:
        print(
            f"warning: --ignore {', '.join(unknown)}: no such rule id (see docs/checks.md)",
            file=sys.stderr,
        )
    config.ignore_ids |= set(args.ignore)
    config.exclude_paths += list(args.exclude)
    auditor = Auditor(
        root, include_home=args.include_home, extra=[Path(e) for e in args.extra], config=config
    )
    auditor.run()
    rep = auditor.report()
    remaining = [
        finding
        for finding in rep["findings"]
        if baseline_keys is None
        or (finding["id"], finding["file"], finding["evidence"]) not in baseline_keys
    ]
    rep["summary"]["baselined"] = len(rep["findings"]) - len(remaining)
    rep["findings"] = remaining
    for severity in SEVERITIES:
        rep["summary"][severity] = sum(
            1 for finding in remaining if finding["severity"] == severity
        )
    rep["summary"]["total"] = len(remaining)
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
