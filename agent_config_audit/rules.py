"""Rule catalogue: one entry per finding id, used by the SARIF reporter and the docs."""

from __future__ import annotations

RULES: dict[str, dict[str, str]] = {
    "PERM-001": {"name": "Any shell command pre-approved", "category": "permissions", "severity": "critical", "description": "Bash or Bash(*) in permissions.allow lets every shell command run without a prompt."},
    "PERM-002": {"name": "Risky program pre-approved", "category": "permissions", "severity": "high", "description": "A program such as rm, sudo, curl, bash or a package manager is pre-approved with a wildcard, so one injected instruction becomes an executed command."},
    "PERM-003": {"name": "Permission prompts bypassed", "category": "permissions", "severity": "critical", "description": "defaultMode bypassPermissions, dontAsk or auto, permissionMode in agent front matter, or a Codex approval policy of never removes the human from the loop."},
    "PERM-004": {"name": "Write or Edit pre-approved for every path", "category": "permissions", "severity": "medium", "description": "The agent can rewrite its own hooks and settings."},
    "PERM-005": {"name": "Web access pre-approved for every domain", "category": "permissions", "severity": "medium", "description": "Unrestricted WebFetch or WebSearch is a data-exfiltration channel under prompt injection."},
    "PERM-006": {"name": "Whole MCP server pre-approved", "category": "permissions", "severity": "medium", "description": "Every tool of the server, including write and delete tools, runs without a prompt."},
    "PERM-007": {"name": "All project MCP servers auto-approved", "category": "permissions", "severity": "medium", "description": "A cloned repository's .mcp.json would start processes automatically."},
    "PERM-008": {"name": "All hooks disabled", "category": "permissions", "severity": "medium", "description": "Guard hooks such as secret-exposure blocking do not run."},
    "PERM-009": {"name": "Permission-bypass flag in an allow rule", "category": "permissions", "severity": "high", "description": "A pre-approved command carries a flag such as --dangerously-skip-permissions."},
    "PERM-010": {"name": "Whole home or root directory granted", "category": "permissions", "severity": "medium", "description": "additionalDirectories includes /, ~ or the home directory."},
    "PERM-011": {"name": "Broad allow rules with no deny rules", "category": "permissions", "severity": "low", "description": "There is no backstop for the obvious disasters."},
    "PERM-012": {"name": "Read allow covers a secret-bearing path", "category": "permissions", "severity": "medium", "description": "A Read allow rule covers environment files, credential stores or private-key paths."},
    "HOOK-001": {"name": "Hook script does not exist", "category": "hooks", "severity": "medium", "description": "The control the hook was meant to add is absent; failure mode depends on the host."},
    "HOOK-002": {"name": "Hook can reach the network", "category": "hooks", "severity": "high", "description": "Hook input contains commands, paths and prompts; a hook that calls curl, ssh or a remote URL can exfiltrate them."},
    "HOOK-003": {"name": "Credential inside a hook command", "category": "hooks", "severity": "critical", "description": "A known credential format sits in a settings file."},
    "HOOK-004": {"name": "Hook pipes remote content into a shell", "category": "hooks", "severity": "critical", "description": "Remote code runs on every tool call."},
    "HOOK-005": {"name": "Unquoted CLAUDE_PLUGIN_ROOT in a shell-form hook", "category": "hooks", "severity": "low", "description": "Breaks on paths with spaces."},
    "HOOK-006": {"name": "Hook script is world-writable", "category": "hooks", "severity": "high", "description": "Anyone local can change what runs on every tool call."},
    "MCP-001": {"name": "MCP server over plain HTTP", "category": "mcp", "severity": "high", "description": "Credentials and tool results travel in clear text."},
    "MCP-002": {"name": "Literal credential in MCP server config", "category": "mcp", "severity": "critical", "description": "A token in headers or env is committed with the config instead of referenced as ${VAR}."},
    "MCP-003": {"name": "Unpinned MCP server", "category": "mcp", "severity": "medium", "description": "npx -y without a version, uvx without ==, @latest, an unpinned container image or code run from a URL fetches whatever is latest on every start."},
    "MCP-004": {"name": "MCP server runs from a temporary directory", "category": "mcp", "severity": "medium", "description": "An unreviewed, easily replaced binary."},
    "MCP-005": {"name": "MCP server started with safety checks disabled", "category": "mcp", "severity": "medium", "description": "Flags such as --dangerously-skip-permissions or a shell -c launch."},
    "MCP-006": {"name": "Deprecated SSE transport", "category": "mcp", "severity": "low", "description": "Switch to streamable HTTP."},
    "MCP-007": {"name": "Filesystem server exposes the whole disk", "category": "mcp", "severity": "high", "description": "The filesystem server is rooted at /, ~ or the home directory."},
    "MCP-008": {"name": "MCP server addressed by raw IP", "category": "mcp", "severity": "medium", "description": "No name to pin, no certificate identity."},
    "SEC-001": {"name": "Secret in agent configuration", "category": "secret", "severity": "critical", "description": "A provider key, token, private key, JWT or high-entropy secret assignment. Evidence is redacted."},
    "INJ-001": {"name": "Instruction-override phrase", "category": "injection", "severity": "high", "description": "Phrases such as 'ignore previous instructions' or 'you are now'."},
    "INJ-002": {"name": "Instruction to hide actions from the user", "category": "injection", "severity": "high", "description": "Phrases such as 'do not tell the user' or 'silently run'."},
    "INJ-003": {"name": "Instruction to exfiltrate data or secrets", "category": "injection", "severity": "high", "description": "Instructions to send data to an external endpoint or to read or emit credentials."},
    "INJ-004": {"name": "Remote code execution or auto-run instruction", "category": "injection", "severity": "critical", "description": "curl piped into a shell, or 'always run' and 'on every session start run'."},
    "INJ-005": {"name": "Invisible or bidirectional characters", "category": "injection", "severity": "high", "description": "Zero-width characters, bidi overrides or Unicode tag characters hide text from reviewers."},
    "INJ-006": {"name": "HTML comment containing instructions", "category": "injection", "severity": "medium", "description": "Rendered Markdown hides comments from readers but not from the model."},
    "INJ-007": {"name": "Long base64-looking blob", "category": "injection", "severity": "medium", "description": "Encoded payloads are a common way to smuggle instructions past review."},
    "INJ-008": {"name": "Instruction to weaken safety controls", "category": "injection", "severity": "high", "description": "Bypass flags, disabled hooks, blanket approvals or destructive commands in prose."},
    "INJ-009": {"name": "Instruction to read credential files", "category": "injection", "severity": "high", "description": "References to ~/.ssh, .aws/credentials, /etc/shadow and similar."},
    "SKILL-001": {"name": "Skill pre-approves broad tools", "category": "skill", "severity": "medium", "description": "allowed-tools grants unrestricted Bash, Write or Edit."},
    "SKILL-002": {"name": "Skill metadata missing", "category": "skill", "severity": "info", "description": "SKILL.md without front matter, name or description."},
    "PLUGIN-001": {"name": "Plugin ships a bin directory", "category": "plugin", "severity": "low", "description": "Executables in bin/ are on the Bash PATH while the plugin is enabled."},
    "FILE-001": {"name": "Configuration file is world-writable", "category": "file", "severity": "medium", "description": "Anyone on the machine could add hooks, permissions or instructions."},
    "CFG-001": {"name": "JSON configuration does not parse", "category": "config", "severity": "low", "description": "Most hosts silently ignore a file that fails to parse, so its protections are not applied."},
}

HELP_URI = "https://github.com/basitalisandhu/agent-config-audit/blob/main/docs/checks.md"


def rule_ids() -> list[str]:
    return list(RULES)
