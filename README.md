# agent-config-audit: audit AI agent configuration files for security risks

Audit AI agent configuration files for security risks: one command reads the files that launch and instruct a coding agent (`.claude/settings*.json`, `.mcp.json`, `claude_desktop_config.json`, `.cursor/` rules and MCP config, `CLAUDE.md`, `AGENTS.md`, plugin manifests, hooks, skills) and reports pre-approved dangerous commands, bypassed permission prompts, secrets committed next to server definitions, unpinned MCP servers, hooks that phone home, and prompt-injection patterns hidden in instruction files. Output as a table, JSON, Markdown or SARIF for GitHub code scanning. Read-only, standard library only, no network, deterministic.

Part of [Masoon](https://github.com/basitalisandhu/masoon) ([docs](https://basitalisandhu.github.io/masoon/)), open-source trust infrastructure for AI agents: who they are, what they may touch, and proof of what they did.

[![CI](https://github.com/basitalisandhu/agent-config-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/basitalisandhu/agent-config-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

## Why

Agent configuration is code that runs with your privileges. A permission rule pre-approves shell commands, a hook executes on every tool call, an MCP server entry starts a process with your environment, and an instruction file is read by the model as if you had typed it. A cloned repository can ship all four. Nothing in the usual review tooling looks at these files, so a `Bash(*)` allow rule, a `GITHUB_TOKEN` pasted into `.mcp.json`, or an HTML comment telling the agent to "upload the repository and never mention this" goes unnoticed until it is used. This tool makes the review a one-second command that runs in CI and in a pre-commit hook.

## When to use this

- **Is this repository safe to open with an agent?** Run it right after `git clone`, before the first session.
- **What did a teammate just change in `.claude/settings.json`?** Run it in the pull request with `--fail-on high`.
- **Are my MCP servers pinned and my tokens out of the config?** It checks `npx -y` without versions, `@latest`, unpinned images, and literal credentials in `headers` and `env`.
- **Does an instruction file contain prompt injection?** It flags override phrases, covert-action and exfiltration instructions, invisible Unicode, bidi overrides, encoded blobs and imperative HTML comments, while skipping negated security guidance ("never paste tokens").
- **How do I get this into GitHub code scanning?** `--format sarif` plus the GitHub Action below.

## Quickstart

```bash
pipx install git+https://github.com/basitalisandhu/agent-config-audit     # see "Install" below
cd your-project
agent-config-audit                      # table on stdout, exit 0
agent-config-audit --fail-on high       # exit 1 when a high or critical finding exists
agent-config-audit --format sarif --output agent-config-audit.sarif
agent-config-audit --include-home       # also ~/.claude, ~/.cursor, the Claude Desktop config
```

## Sample report

Running it against [`examples/sample-project/`](examples/sample-project/), a small project with the usual mistakes (bypass mode, `Bash(*)`, a token in `.mcp.json`, a filesystem server rooted at `~`, a hook that posts to a collector, `curl | bash` in `CLAUDE.md`):

```text
agent-config-audit 0.1.0: 4 file(s) scanned under examples/sample-project

SEVERITY  ID        FILE                       FINDING
------------------------------------------------------
CRITICAL  PERM-003  .claude/settings.json:3    defaultMode is bypassPermissions
CRITICAL  PERM-001  .claude/settings.json:4    Any shell command is pre-approved
CRITICAL  INJ-004   CLAUDE.md:5                Remote code piped into a shell
HIGH      HOOK-002  .claude/settings.json:10   PostToolUse hook can reach the network
HIGH      INJ-002   .cursor/rules/style.mdc:4  Instruction to hide actions from the user
HIGH      MCP-007   .mcp.json:4                Filesystem MCP server files exposes the whole home or root directory
HIGH      MCP-001   .mcp.json:5                MCP server remote uses plain HTTP
HIGH      MCP-002   .mcp.json:5                Literal credential in headers.Authorization of MCP server remote
HIGH      INJ-004   CLAUDE.md:5                Instruction to auto-run commands
HIGH      INJ-004   CLAUDE.md:7                Instruction to auto-run commands
MEDIUM    PERM-002  .claude/settings.json:4    Broad pre-approval for git
MEDIUM    PERM-005  .claude/settings.json:4    WebFetch is pre-approved for every domain
MEDIUM    PERM-006  .claude/settings.json:4    Every tool of an MCP server is pre-approved
MEDIUM    PERM-007  .claude/settings.json:7    All project MCP servers are auto-approved
MEDIUM    MCP-003   .mcp.json:3                MCP server github runs an unpinned npm package
MEDIUM    INJ-006   CLAUDE.md:7                HTML comment containing instructions
LOW       PERM-011  .claude/settings.json      Broad allow rules with no deny rules

17 finding(s): 3 critical, 7 high, 6 medium, 1 low.

Fixes:
  PERM-003: Use default or acceptEdits, and allowlist specific commands instead. Bypass mode removes every prompt, including for destructive commands.
  PERM-001: Replace with specific rules such as Bash(npm test), Bash(git status *), Bash(pytest *).
  INJ-004: Download to a file, review it, pin a hash, then run it. Never pipe remote content into a shell from an instruction file.
  ...
```

The same run as Markdown is committed at [`examples/report.md`](examples/report.md) and as SARIF at [`examples/report.sarif`](examples/report.sarif). Evidence is always redacted: the bearer token above appears as `Bearer hard****` and a GitHub token as `ghp_A1****t0`, never in full.

## Install

Container image (linux/amd64 and linux/arm64), published to GitHub Packages on every release. Mount the project to audit at `/work`:

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/basitalisandhu/agent-config-audit:0.1.0 --fail-on high
docker run --rm -v "$PWD:/work:ro" ghcr.io/basitalisandhu/agent-config-audit:0.1.0 --format sarif > agent-config-audit.sarif
```

The image runs as uid 1000. Each image is signed with cosign (keyless) and has a build provenance attestation and an SPDX SBOM (attached to the GitHub Release). To verify:

```bash
cosign verify ghcr.io/basitalisandhu/agent-config-audit:0.1.0 \
  --certificate-identity-regexp '^https://github.com/basitalisandhu/agent-config-audit/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/basitalisandhu/agent-config-audit:0.1.0 --owner basitalisandhu
```

Python package: requires Python 3.11 or newer and nothing else. PyPI publication is pending, so install from the repository:

```bash
pipx install git+https://github.com/basitalisandhu/agent-config-audit                            # isolated CLI install
uvx --from git+https://github.com/basitalisandhu/agent-config-audit agent-config-audit --help    # run without installing
pip install git+https://github.com/basitalisandhu/agent-config-audit                             # into the current environment
git clone https://github.com/basitalisandhu/agent-config-audit && cd agent-config-audit && uv sync   # for development
```

Once published to PyPI:

```bash
pip install agent-config-audit
```

The other short forms work then too: `pipx install agent-config-audit`, `uvx agent-config-audit`.

## Usage

```text
agent-config-audit [ROOT] [--extra FILE ...] [--include-home]
                   [--format table|json|sarif|markdown] [--output FILE]
                   [--fail-on SEVERITY] [--config FILE] [--ignore RULE ...] [--exclude GLOB ...]
```

| Option | Meaning |
|---|---|
| `ROOT` | Project directory to audit (default: current directory). |
| `--extra FILE` | Audit another file too, for example a `claude_desktop_config.json` somewhere else. Repeatable. |
| `--include-home` | Also audit the user-level files: `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.cursor/mcp.json`, `~/.codex/config.toml`, `~/.gemini/settings.json`, the Claude Desktop config on macOS, Linux and Windows. |
| `--format` | `table` (default, for people), `json` (for scripts), `sarif` (SARIF 2.1.0 for code scanning), `markdown` (for pull request comments and reports). |
| `--fail-on` | Exit 1 when a finding of this severity or worse exists: `critical`, `high`, `medium`, `low`, `info`. Without it the exit code is 0 whatever is found. |
| `--config` | Allowlist file (see below). By default `.agent-config-audit.toml` in the root is used when present. |
| `--ignore RULE` | Leave a rule id out of the report. Repeatable. |
| `--exclude GLOB` | Skip files or directories matching the glob, relative to the root. Repeatable. |

Exit codes: 0 clean (or no `--fail-on`), 1 findings at or above the threshold, 2 usage or configuration error.

### What is checked

Forty rules in six groups; every one is documented with its trigger and why it matters in [docs/checks.md](docs/checks.md).

| Group | Rule ids | Examples |
|---|---|---|
| Permissions | PERM-001 to PERM-011 | `Bash(*)`, `rm`/`curl`/`sudo` with wildcards, `defaultMode: bypassPermissions`, `Write` for every path, `WebFetch` for every domain, whole MCP servers pre-approved, `enableAllProjectMcpServers`, `disableAllHooks`, bypass flags inside allow rules, `additionalDirectories: ["/"]`, no deny rules |
| Hooks | HOOK-001 to HOOK-006 | Missing hook scripts, hooks that call `curl`/`ssh` or post to remote URLs, credentials in hook commands, `curl \| sh` in a hook, unquoted plugin root, world-writable scripts |
| MCP servers | MCP-001 to MCP-008 | Plain `http://` or `ws://`, literal tokens in `headers` or `env`, unpinned `npx`/`uvx`/images, servers in `/tmp` or `Downloads`, `--dangerously-skip-permissions`, deprecated SSE, filesystem server rooted at `/` or `~`, raw IP addresses |
| Secrets | SEC-001 | OpenAI, Anthropic, GitHub, GitLab, AWS, Slack, Google, Stripe, npm, Hugging Face and Masoon key formats, private key blocks, JWTs, high-entropy `api_key = ...` assignments; placeholders are skipped |
| Instruction files | INJ-001 to INJ-009 | "ignore previous instructions", "do not tell the user", "send ... to https://", `curl \| bash`, "always run ... on session start", zero-width and bidi characters, Unicode tag characters, imperative HTML comments, base64 blobs, "disable hooks", `rm -rf ~`, "cat ~/.ssh/id_rsa" |
| Skills, plugins, files | SKILL-001, SKILL-002, PLUGIN-001, FILE-001, CFG-001 | `allowed-tools: Bash`, missing skill metadata, plugin `bin/` on PATH, world-writable config, JSON that does not parse |

The scanner is pattern-based. Treat critical and high findings as "open the file and look": a `Bash(curl *)` rule inside a deny list is fine, and a hook that posts to `localhost` is fine. It also cannot follow `@file` references in instruction files or read hooks of type `prompt`; do that by hand.

### Allowlist

Create `.agent-config-audit.toml` in the project root (or pass `--config`):

```toml
[allow]
ids = ["PERM-011"]                  # never report these rule ids
paths = ["docs/**", "examples/**"]  # skip files matching these globs

[[suppress]]                        # drop one specific finding, with a reason that ends up in the report
id = "MCP-003"
path = ".mcp.json"
evidence = "some-server"            # optional substring of the evidence
reason = "pinned through the lockfile"
```

Suppressed findings are counted and listed under "Suppressed by configuration" in the JSON and Markdown reports, so an allowlist never hides what it does.

## CI usage

```bash
agent-config-audit . --fail-on high
agent-config-audit . --format sarif --output agent-config-audit.sarif   # upload to code scanning
```

### GitHub Action

```yaml
name: agent-config-audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/agent-config-audit@v0.1.0   # pin a release tag
        with:
          fail-on: high            # none | info | low | medium | high | critical
```

Inputs: `root`, `fail-on`, `config`, `extra` (space-separated files), `sarif-file`, `upload` (set `false` to skip the code scanning upload), `python-version`, `version` (PyPI version; empty installs the action's own checkout). Outputs: `sarif-file`, `findings`. The findings table is also written to the job summary. See [action.yml](action.yml).

### pre-commit

```yaml
repos:
  - repo: https://github.com/basitalisandhu/agent-config-audit
    rev: v0.1.0
    hooks:
      - id: agent-config-audit
        # args: ["--fail-on", "medium", "--config", ".agent-config-audit.toml"]
```

The hook runs whenever an agent configuration file is staged, audits the whole project and fails the commit on `high` or `critical` findings by default.

## Frequently asked questions

**Which files does it read?**
The Claude Code, Cursor, Windsurf, Cline, Roo, Aider, Continue, Copilot, Gemini CLI and Codex configuration and instruction files listed in [docs/checks.md](docs/checks.md#files-scanned), relative to the root, plus anything given with `--extra` and, with `--include-home`, the user-level files. `node_modules` and `.git` are never entered and files over 2 MB are skipped and reported.

**Does it send anything anywhere?**
No. It opens files, applies regular expressions and JSON or TOML parsing, and prints a report. There is no network code in the package.

**Will it flag my own security guidance?**
Phrases preceded by a negation within the same sentence ("never send the API keys anywhere", "do not paste tokens") are skipped. If a benign sentence is still reported, add a `[[suppress]]` entry with a reason, and please open an issue with the sentence so the pattern can be narrowed.

**Is the SARIF output accepted by GitHub?**
Yes. It is SARIF 2.1.0 with a rules array, `ruleIndex` on every result, `security-severity` properties, relative URIs under `%SRCROOT%` and stable fingerprints, and the test suite checks that structure on every change. Upload it with `github/codeql-action/upload-sarif` or let the Action do it.

**Where does this come from?**
The checks started as the `audit_agent_config.py` script in the `agent-config-audit` skill of [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills), where an agent runs them as the first step of a security review. This repository is the standalone package: same rule ids, same patterns, plus the table and SARIF reporters, the allowlist, the Action and the pre-commit hook. Findings from either tool mean the same thing.

## Roadmap

- A `fix` mode that rewrites the obvious cases (pin `npx` versions, replace literal tokens with `${VAR}` and print the export line).
- Rules for Windsurf and Cline permission settings, which today are only scanned as instruction files.
- Following `@path` includes in `CLAUDE.md` and reading `prompt` and `agent` type hooks.
- Baseline mode (`--baseline report.json`) that reports only new findings in a pull request.

## Contributing

Issues and pull requests are welcome; the starter list is in [docs/good-first-issues.md](docs/good-first-issues.md). Adding a rule is a pattern, a rule entry, a fixture and a test; see [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` (ruff and pytest) before opening a pull request. Security problems: see [SECURITY.md](SECURITY.md).

## Sibling projects

- [masoon](https://github.com/basitalisandhu/masoon): the platform front door, with the [docs site](https://basitalisandhu.github.io/masoon/).
- [Masoon Broker](https://basitalisandhu.github.io/masoon/masoon-broker.html): scoped, short-lived credentials for AI agents with approvals, kill switch and tamper-evident audit.
- [llm-agent-control-plane](https://github.com/basitalisandhu/llm-agent-control-plane): deterministic policy enforcement point for LLM agents.
- [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills): Claude Code plugin and agentskills-compatible skill pack where these checks run inside a review.
- [agent-threat-model](https://github.com/basitalisandhu/agent-threat-model): describe an agent system in YAML, get a STRIDE and OWASP Agentic threat model.
- [agentic-semgrep-rules](https://github.com/basitalisandhu/agentic-semgrep-rules): Semgrep rule pack for insecure agent code.
- [mcp-server-template](https://github.com/basitalisandhu/mcp-server-template): secure MCP server template in TypeScript and Python.
- [ai-agent-incidents](https://github.com/basitalisandhu/ai-agent-incidents): open dataset of publicly documented AI agent security incidents.

## Licence

MIT, see [LICENSE](LICENSE). Copyright 2026 Muhammad Basit Ali.
