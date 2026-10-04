# Check reference

Every finding has an id, a severity (`critical`, `high`, `medium`, `low`, `info`), the file and line, redacted evidence and a recommendation. The default severity is in brackets; the scanner lowers it when the context is narrower (for example a risky program pre-approved with a specific argument pattern).

The rule ids are shared with the `agent-config-audit` skill in [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills), so a finding from either tool means the same thing.

## Permissions (Claude Code settings.json, Codex config.toml)

| ID | Trigger | Why it matters |
|---|---|---|
| <a id="perm-001"></a>PERM-001 [critical] | `Bash`, `Bash(*)` in `permissions.allow` | Any shell command runs without a prompt |
| <a id="perm-002"></a>PERM-002 [high, medium, low] | A risky program pre-approved: `rm`, `sudo`, `curl`, `wget`, `nc`, `bash`, `eval`, `dd`, `python -c`, and others with a wildcard; package managers, cloud CLIs, `git`, `docker` with a wildcard | One injected instruction becomes an executed command |
| <a id="perm-003"></a>PERM-003 [critical, high, medium] | `defaultMode: bypassPermissions`; `dontAsk`/`auto`; `permissionMode` in agent front matter; Codex `approval_policy = never` | Removes the human from the loop |
| <a id="perm-004"></a>PERM-004 [medium] | `Write`, `Edit` allowed for every path | The agent can rewrite its own hooks and settings |
| <a id="perm-005"></a>PERM-005 [medium] | `WebFetch`, `WebSearch` allowed for every domain | Exfiltration channel under injection |
| <a id="perm-006"></a>PERM-006 [medium] | A whole MCP server allowed (`mcp__name`, `mcp__name__*`) | Write and delete tools run without a prompt |
| <a id="perm-007"></a>PERM-007 [medium] | `enableAllProjectMcpServers: true` | A cloned repo's `.mcp.json` starts processes automatically |
| <a id="perm-008"></a>PERM-008 [medium] | `disableAllHooks: true` | Guard hooks do not run |
| <a id="perm-009"></a>PERM-009 [high] | An allow rule carries `--dangerously-skip-permissions` or similar | Bypass flag baked into a pre-approval |
| <a id="perm-010"></a>PERM-010 [medium] | `additionalDirectories` includes `/`, `~` or the home directory | Whole-disk read and write scope |
| <a id="perm-011"></a>PERM-011 [low] | Broad allow rules and no deny rules | No backstop for the obvious disasters |

## Hooks (settings hooks, plugin hooks/hooks.json, plugin.json hooks)

| ID | Trigger | Why it matters |
|---|---|---|
| <a id="hook-001"></a>HOOK-001 [medium] | Command or first exec-form argument points at a script that does not exist | The control is absent; failure mode depends on the host |
| <a id="hook-002"></a>HOOK-002 [high, medium] | Hook command uses `curl`, `wget`, `ssh`, `nc`, an `http` hook to a non-loopback URL, or a hook script that can reach the network | Hook input contains commands, paths and prompts |
| <a id="hook-003"></a>HOOK-003 [critical] | A known credential format inside the hook command | Secret in a settings file |
| <a id="hook-004"></a>HOOK-004 [critical] | `curl ... \| sh` style in a hook | Remote code on every tool call |
| <a id="hook-005"></a>HOOK-005 [low] | Shell-form hook with unquoted `${CLAUDE_PLUGIN_ROOT}` | Breaks on paths with spaces |
| <a id="hook-006"></a>HOOK-006 [high] | Hook script is world-writable | Anyone local can change what runs on every tool call |

## MCP servers (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, plugin .mcp.json, Codex config.toml)

| ID | Trigger | Why it matters |
|---|---|---|
| <a id="mcp-001"></a>MCP-001 [high] | `http://` or `ws://` URL to a non-loopback host | Credentials and tool results in clear text |
| <a id="mcp-002"></a>MCP-002 [critical, high] | Literal token in `headers` or `env` (not `${VAR}`) | Secret committed with the config |
| <a id="mcp-003"></a>MCP-003 [medium] | `npx -y pkg` without a version, `uvx pkg` without `==`, `@latest`, unpinned container image, code run from a URL | Every start fetches whatever is latest |
| <a id="mcp-004"></a>MCP-004 [medium] | Server runs from `/tmp`, `Downloads`, `Desktop` | Unreviewed, easily replaced binary |
| <a id="mcp-005"></a>MCP-005 [medium, low] | `--dangerously-skip-permissions`, `--allow-all`, `--no-sandbox`, `--yolo`, shell `-c` launch | Server's own safety checks disabled |
| <a id="mcp-006"></a>MCP-006 [low] | `type: sse` | Deprecated transport |
| <a id="mcp-007"></a>MCP-007 [high] | Filesystem server rooted at `/`, `~` or the home directory | Whole-disk access for the model |
| <a id="mcp-008"></a>MCP-008 [medium] | Remote server addressed by raw IP | No name to pin, no certificate identity |

## Secrets (every scanned file)

| ID | Trigger |
|---|---|
| <a id="sec-001"></a>SEC-001 [critical, high] | OpenAI, Anthropic, GitHub, GitLab, AWS, Slack, Google, Stripe, npm, Hugging Face and credential broker key formats; private key blocks; JWTs; generic `api_key = "<high-entropy>"` assignments. Placeholders (`xxxx`, `your-`, `<...>`, `EXAMPLE`) are skipped. Evidence is redacted. |

## Instruction files (CLAUDE.md, AGENTS.md, .cursorrules, .mdc, SKILL.md, commands, agents, copilot-instructions)

| ID | Trigger |
|---|---|
| <a id="inj-001"></a>INJ-001 [high] | "ignore previous instructions", "you are now", "new instructions:", "developer mode" |
| <a id="inj-002"></a>INJ-002 [high] | "do not tell the user", "without asking the user", "silently run" |
| <a id="inj-003"></a>INJ-003 [high] | "send ... to https://...", "upload ... to a webhook", instructions that read or emit API keys, `.env`, SSH keys |
| <a id="inj-004"></a>INJ-004 [critical, high] | `curl ... \| sh`; "always run ...", "on every session start run ..." |
| <a id="inj-005"></a>INJ-005 [high, critical] | Zero-width characters, bidirectional overrides, Unicode tag characters |
| <a id="inj-006"></a>INJ-006 [medium] | HTML comment that contains imperative instructions |
| <a id="inj-007"></a>INJ-007 [medium] | Long high-entropy base64 blob |
| <a id="inj-008"></a>INJ-008 [high] | "--dangerously-skip-permissions", "disable hooks", "approve everything", `rm -rf ~`, `chmod 777`, force-push to main |
| <a id="inj-009"></a>INJ-009 [high] | "cat ~/.ssh/...", "read .aws/credentials", "/etc/shadow" |

Phrases preceded by a negation ("never send the API keys", "do not paste tokens") are not reported, so security guidance in an instruction file does not trigger the injection rules.

## Skills, commands, agents, plugins, files

| ID | Trigger |
|---|---|
| <a id="skill-001"></a>SKILL-001 [medium, low] | `allowed-tools` grants unrestricted `Bash` or `Write`/`Edit` |
| <a id="skill-002"></a>SKILL-002 [info] | SKILL.md without front matter, name or description |
| <a id="plugin-001"></a>PLUGIN-001 [low] | Plugin ships a `bin/` directory (on the Bash PATH while enabled) |
| <a id="file-001"></a>FILE-001 [medium] | Config file is world-writable |
| <a id="cfg-001"></a>CFG-001 [low] | JSON config does not parse (silently ignored by hosts) |

## Files scanned

Relative to the audited root:

- Claude Code: `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md`, `.claude/settings.json`, `.claude/settings.local.json`, `.claude/commands/**`, `.claude/skills/**/SKILL.md`, `.claude/agents/**`, `.claude/hooks/**`, `.mcp.json`
- Plugins: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `hooks/hooks.json`, `skills/*/SKILL.md`, `agents/**`, `commands/**`, `plugins/*/...`
- Cursor: `.cursorrules`, `.cursor/rules/**/*.mdc`, `.cursor/rules/**/*.md`, `.cursor/mcp.json`
- Others: `AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/**`, `.windsurfrules`, `.windsurf/rules/**`, `.clinerules`, `.vscode/mcp.json`, `.gemini/settings.json`, `GEMINI.md`, `.codex/config.toml`, `.roo/rules/**`, `.aider.conf.yml`, `.continue/config.json`, `.continue/config.yaml`
- With `--include-home`: `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.cursor/mcp.json`, `~/.codex/config.toml`, `~/.gemini/settings.json`, the Claude Desktop `claude_desktop_config.json` on macOS, Linux and Windows, `~/.continue/config.*`
- With `--extra FILE`: any other file

Files larger than 2 MB are skipped and reported under scan errors. `node_modules` and `.git` are never entered.
