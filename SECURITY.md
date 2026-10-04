# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, the command you ran and a minimal configuration that reproduces the problem. Do not include real credentials; a redacted example is enough.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Scope

agent-config-audit reads configuration files, applies regular expressions and JSON or TOML parsing, and writes a report. It never executes content from the files it reads, never follows a hook command, never starts an MCP server and never makes a network request. Files over 2 MB are skipped.

Issues of interest: a way to make the scanner print a secret in full (redaction bypass), path handling in `--output`, regular expressions with pathological running time on crafted input (every pattern is bounded, but please report any that are not), SARIF or Markdown output that could inject content into a viewer, and problems in the development tooling.

A missed finding (a risky configuration the tool does not report) is a normal issue, not a vulnerability; please open it publicly with a minimal fixture so a rule can be added.
