# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-28

### Added

- Hooks declared in skill (`SKILL.md`) and subagent front matter are checked with the same HOOK rules as settings hooks: remote code piped into a shell, network access, literal credentials, missing scripts, unknown event names. Claude Code registers these hooks when the skill runs and keeps them for the rest of the session ([hooks in skills and agents](https://code.claude.com/docs/en/hooks#hooks-in-skills-and-agents)). They were not read before.
- A Troubleshooting section in the README with real messages and fixes.
- Seeded fuzz tests (bad bytes and wrong value types in every fixture file, bad `--baseline`, `--config` and `--extra` files) with a time limit per run, a scaling test, and a CI job that installs with pipx and compares the README quick start output.
- `--baseline FILE` drops findings whose (id, file, evidence) is in an earlier JSON report; they are counted under `summary.baselined` and `--fail-on` applies to the rest (#12). Thanks @Aaqibhafeezkhan.

### Fixed

- A JSON config file nested too deeply ended the audit with a `RecursionError` traceback; it is now CFG-001. The same applied to `.claude-plugin/marketplace.json`, `--extra` files and `--baseline`.
- A `--baseline` or `--config` file that is not UTF-8, or a TOML allowlist nested too deeply, ended with a traceback; it now exits with code 2 and names the file. Allowlist errors such as an unknown rule id name the file too.
- A hook whose `type` was a list or object ended the audit with `TypeError: unhashable type`.
- Large instruction files took quadratic time because every finding counted newlines from the start of the file (a 20,000-line project: 10.9 s, now about 1 s).

## [0.3.0] - 2026-10-16

### Added

- `@path` imports in `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` and `.claude/rules/` are followed the way Claude Code expands them: relative to the importing file, up to four hops, skipping code spans, fenced blocks and quoted paths, each file once. Findings point at the imported file and line; imports outside the root are read only with `--include-home` (#11).
- `docs/checks.md` rule tables are generated from `RULES` by `scripts/gen_checks_doc.py`; `make docs` regenerates them and CI fails when they are stale (#14).
- PERM-013 reports permission rules that Claude Code skips or never matches: `mcp__` rules with parentheses, parameter rules on a primary field such as `Bash(command:rm *)`, `:*` in the middle of a pattern, and unanchored allow globs such as `*` or `mcp__*`. Medium in `deny` and `ask` (the restriction does not hold), info in `allow`.
- PERM-002 reports environment runners pre-approved with a wildcard (`npx *`, `docker exec *`, `devbox run *`, `direnv exec *`, `mise exec *`, `uv run *`, `xargs *`) and rules that start with `*`, at high.
- PowerShell rules are checked like Bash rules for PERM-001, PERM-002 and PERM-011.
- HOOK-007 reports hook events Claude Code does not know (for example `preToolUse`), which it ignores at runtime, with a suggestion when only the case is wrong.
- HOOK-008 reports credential helpers (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`) in project settings. Those helpers and `statusLine`, `fileSuggestion` and `subagentStatusLine` commands get the network, pipe-to-shell and credential checks.
- `prompt` and `agent` hooks are scanned with the injection rules; `http` hooks to loopback are reported at low and literal tokens in `http` hook headers as HOOK-003.
- PLUGIN-002 reports reserved plugin name prefixes and component paths that leave the plugin directory. Plugins without a manifest, plugins listed by relative `source` in `marketplace.json`, the files that `plugin.json` names in `hooks`, `mcpServers` and `lspServers`, `.lsp.json`, `monitors/monitors.json` and `experimental.monitors` commands are now scanned.
- Nested `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` files, `.claude/rules/`, `.claude/AGENTS.md` and output styles are scanned; `--include-home` adds `~/.claude.json` MCP servers and the user rules, agents, skills, commands and output styles.

### Changed

- README first screen: who the tool is for, a three-line quick start, a real run on the sample project, and links to the related tools.
- INJ-006 is low in `CLAUDE.md`, `CLAUDE.local.md` and `.claude/rules/`, because Claude Code strips block-level HTML comments from those files before loading them.
- An empty scan now says that no agent configuration files were found, instead of reporting a clean result; `--fail-on` accepts upper case; an unknown `--ignore` id prints a warning; the table header shows the root relative to the current directory.

### Fixed

- `--extra` with a file that does not exist was silently skipped; it is now a usage error (exit 2).
- Hook, MCP server and matcher entries with the wrong JSON types (a list as `command`, a string as `args` or `hooks`, a non-object `headers`) no longer crash the scan.
- `Bash(rm:*)`, `Bash(curl:*)` and other `:*` rules were not reported; Claude Code treats `:*` as a trailing ` *`. `rm*` and `git * main` count as wildcards too, and wrappers that Claude Code strips (`timeout 30`, `nice`, `VAR=value`) no longer hide the program.
- `defaultMode: dontAsk` and `permissionMode: dontAsk` were reported as bypassing prompts; that mode only denies, so it is no longer reported.
- `defaultMode` `bypassPermissions` and `auto` in project or local settings are reported at high and low, because Claude Code v2.1.257 and later ignore them there; in user settings they stay critical and medium.
- `permissionMode` in plugin agents is not reported (Claude Code ignores it), and agent `bypassPermissions` or `auto` is medium with a line number.
- PERM-006 no longer fires on `mcp__*` (skipped by Claude Code, now PERM-013) or on partial globs such as `mcp__github__get_*`.
- A `permissions` value that is not an object, or `allow`, `deny` or `additionalDirectories` values that are not lists, no longer crash the scan.

## [0.2.0] - 2026-10-09

### Added

- Add PERM-012 (medium) for explicit secret-bearing `Read(...)` allow paths, excluding ordinary project paths and `.env` templates ending in `.example`, `.sample` or `.template`.

## [0.1.1] - 2026-10-06

### Changed

- Removed the umbrella branding; this project stands alone and links its sibling repositories directly.

## [0.1.0] - 2026-10-04

### Added

- Container image `ghcr.io/basitalisandhu/agent-config-audit` for linux/amd64 and linux/arm64, published on each version tag with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The image runs as uid 1000 with `/work` as the working directory.
- `agent-config-audit` command with table, JSON, Markdown and SARIF 2.1.0 output, `--fail-on` thresholds, `--extra` files and `--include-home`.
- Forty rules across permissions, hooks, MCP servers, secrets, instruction files, skills, plugins and files, extracted from the `agent-config-audit` skill of agent-security-skills with the same rule ids.
- Allowlist file `.agent-config-audit.toml` with ignored rule ids, excluded paths and reasoned suppressions, plus `--ignore` and `--exclude` flags.
- Composite GitHub Action with SARIF upload, pre-commit hook, CI and release workflows, a sample project with committed reports, and rule documentation.

### Changed

- Renamed the umbrella project from Hisar to Masoon; links, names and identifiers updated.
- PyPI publishing (release.yml) is off until the repository variable `PYPI_PUBLISH` is set to `true`.

[Unreleased]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/agent-config-audit/releases/tag/v0.1.0
