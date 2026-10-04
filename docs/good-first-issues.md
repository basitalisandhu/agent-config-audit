# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so they
can be filed in one sitting. Each is self-contained and has acceptance criteria that `make check`
can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass, rule ids are
never reused, every rule change needs a fixture and a test, and `make example` must be run when
the committed sample report changes.

## 1. Report `Read(./.env)` style secrets exposure in allow rules

**Context.** `permissions.allow` can pre-approve `Read` on specific paths. Pre-approving reads of
`.env`, `~/.ssh/**`, `~/.aws/**` or `*.pem` hands secrets to the model without a prompt.

**Acceptance criteria.**

- New rule `PERM-012` (medium) fires for `Read(...)` rules whose path matches a secret-bearing
  location (`.env*`, `.ssh`, `.aws`, `.netrc`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`).
- Entry in `RULES`, row in `docs/checks.md`, fixture `tests/fixtures/risky-reads/`, test with a
  positive and a negative (`Read(./src/**)`) case.

## 2. Windsurf and Cline permission settings

**Context.** `.windsurfrules` and `.clinerules` are scanned as instruction files, but Windsurf's
and Cline's auto-approve settings are not inspected at all.

**Acceptance criteria.**

- Discover the settings files these hosts use for auto-approval (document the paths in
  `docs/checks.md` with a link to each host's documentation) and add them to `PROJECT_GLOBS` and
  `HOME_FILES`.
- Map "approve everything" style settings to `PERM-003` and tool-level blanket approvals to
  `PERM-002`/`PERM-006` with the same severities as the Claude Code equivalents.
- Fixtures and tests for one risky and one sane configuration per host.

## 3. Follow `@path` includes in instruction files

**Context.** `CLAUDE.md` can include other files with `@docs/rules.md`. Injected text in an
included file is read by the model but not by the scanner.

**Acceptance criteria.**

- `scan_instructions` collects `@relative/path` references, resolves them against the file's
  directory, and scans each included file once (depth limit 3, size limit as usual).
- Findings in included files report the included file's path and line.
- Test with a two-level include chain and a cycle.

## 4. `--baseline` mode for pull requests

**Context.** A repository that already has findings wants CI to fail only on new ones.

**Acceptance criteria.**

- `agent-config-audit --baseline old-report.json` loads a previous JSON report and drops findings
  whose `(id, file, evidence)` triple is present in it; dropped findings are counted under
  `summary.baselined`.
- `--fail-on` applies to the remaining findings only.
- Tests in `tests/test_cli.py`; README "Usage" table gains a row.

## 5. Issue form for false positives

**Context.** The injection rules are pattern-based and will sometimes flag benign prose. A form
that captures the sentence, the rule id and the file type makes narrowing a pattern a five-minute
job.

**Acceptance criteria.**

- `.github/ISSUE_TEMPLATE/false-positive.yml` with fields: rule id (dropdown over the ids in
  `rules.py`), the exact sentence or config fragment (redacted), the host (Claude Code, Cursor,
  other), and what you expected.
- `.github/ISSUE_TEMPLATE/config.yml` disabling blank issues and pointing vulnerabilities at
  SECURITY.md.
- Both parse as YAML; CONTRIBUTING links the form.

## 6. Generate `docs/checks.md` from `rules.py`

**Context.** The rule table in `docs/checks.md` is maintained by hand and can drift from `RULES`.

**Acceptance criteria.**

- `scripts/gen_checks_doc.py` renders the tables in `docs/checks.md` from `RULES` (keeping the
  prose sections), with a `--check` flag that exits 1 when the file is stale.
- CI runs `python scripts/gen_checks_doc.py --check`; `make docs` regenerates.
- A test asserts every id in `RULES` appears in `docs/checks.md`.
