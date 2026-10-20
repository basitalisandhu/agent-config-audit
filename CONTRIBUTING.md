# Contributing

Thanks for considering a contribution. The project is small on purpose: pattern tables, one scanner class, four reporters. The most useful contributions are new rules with fixtures, narrower patterns when something benign is flagged, and support for configuration formats of other agent hosts.

## Set up

Requires Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/agent-config-audit
cd agent-config-audit
uv sync
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check      # ruff check, ruff format --check, pytest, docs/checks.md is current
make example    # regenerate examples/report.md and examples/report.sarif after rule changes
make docs       # regenerate the rule tables in docs/checks.md from rules.py
```

CI runs the same commands on Python 3.11 and 3.12, fails when the committed example report or `docs/checks.md` is stale, builds the wheel, and audits this repository's own configuration with `--fail-on low`.

## Adding a rule

1. Pick the next free id in the group (`PERM`, `HOOK`, `MCP`, `SEC`, `INJ`, `SKILL`, `PLUGIN`, `FILE`, `CFG`). Ids are shared with the `agent-config-audit` skill in [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills); do not reuse or renumber.
2. Add the entry to `RULES` in `agent_config_audit/rules.py`: name, category, default severity, a one-sentence description (used in SARIF), `levels` (every severity it can be reported at), `trigger` and, for the permissions, hooks and MCP groups, `why` (both Markdown). The SARIF reporter and `docs/checks.md` are built from it.
3. Add the check to the right method of `Auditor` in `agent_config_audit/scanner.py`, or the pattern to `agent_config_audit/patterns.py`. Every `add(...)` call passes the id, a severity, a category, a short title, the path, a line when one is known, the evidence (it is redacted automatically) and a recommendation that says what to do.
4. Add a fixture under `tests/fixtures/<case>/` and a test that asserts the id, the severity and, for secrets, that the value does not appear in the report. Add a negative case so benign input stays clean. A fixture that has to contain a credential-shaped value (a key in a known format, a token, a JWT) is not committed, because GitHub push protection rejects it: register it in `GENERATED_PROJECTS` in `tests/conftest.py`, assemble the value from parts with `secret(...)`, and build it in the test with the `project` fixture.
5. Run `make docs` to regenerate the tables in `docs/checks.md` (do not edit them by hand; the prose around them is hand-written) and, if the group is new, add it to the README table.
6. Run `make example check`.

## Style

- `ruff` formats and lints; line length 100 (pattern tables and finding messages are exempt).
- Standard library only at runtime. Development dependencies are fine.
- Deterministic output: findings sorted by severity, file, line and id; no timestamps in the report.
- Evidence is never printed in full when it could be a credential. Use `redact` and keep evidence under 300 characters.
- Plain language in titles and recommendations: say what is wrong and what to do.

## Reporting a false positive

If a benign sentence or configuration fragment is reported by a rule, use the [false-positive report form](https://github.com/basitalisandhu/agent-config-audit/issues/new?template=false-positive.yml). Include the rule ID and host, and redact credentials, tokens, personal data and other sensitive values before submitting. This helps narrow the pattern without exposing secrets.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
