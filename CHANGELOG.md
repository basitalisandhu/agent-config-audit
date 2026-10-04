# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Renamed the umbrella project from Hisar to Masoon; links, names and identifiers updated.

## [0.1.0] - 2026-10-03

### Added

- `agent-config-audit` command with table, JSON, Markdown and SARIF 2.1.0 output, `--fail-on` thresholds, `--extra` files and `--include-home`.
- Forty rules across permissions, hooks, MCP servers, secrets, instruction files, skills, plugins and files, extracted from the `agent-config-audit` skill of agent-security-skills with the same rule ids.
- Allowlist file `.agent-config-audit.toml` with ignored rule ids, excluded paths and reasoned suppressions, plus `--ignore` and `--exclude` flags.
- Composite GitHub Action with SARIF upload, pre-commit hook, CI and release workflows, a sample project with committed reports, and rule documentation.

[Unreleased]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/agent-config-audit/releases/tag/v0.1.0
