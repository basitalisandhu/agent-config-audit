# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- Add PERM-012 (medium) for explicit secret-bearing `Read(...)` allow paths, with ordinary project-path negatives.

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

[Unreleased]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/basitalisandhu/agent-config-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/agent-config-audit/releases/tag/v0.1.0
