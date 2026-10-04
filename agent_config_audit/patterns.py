"""Regular expressions, program lists and rule texts shared by the checks.

The patterns are the same as those in the ``agent-config-audit`` skill of
https://github.com/basitalisandhu/agent-security-skills so that both tools report the same rule ids
for the same input.
"""

from __future__ import annotations

import re

SEVERITIES = ["critical", "high", "medium", "low", "info"]
MAX_FILE_BYTES = 2 * 1024 * 1024

PROJECT_GLOBS = [
    "CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json",
    ".claude/commands/**/*.md", ".claude/skills/**/SKILL.md", ".claude/agents/**/*.md", ".claude/hooks/**/*", ".mcp.json",
    ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "hooks/hooks.json", "skills/*/SKILL.md",
    "agents/**/*.md", "commands/**/*.md", "plugins/*/.claude-plugin/plugin.json", "plugins/*/hooks/hooks.json",
    "plugins/*/.mcp.json", "plugins/*/skills/*/SKILL.md", "plugins/*/agents/**/*.md", "plugins/*/commands/**/*.md",
    ".cursorrules", ".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md", ".cursor/mcp.json", "AGENTS.md",
    ".github/copilot-instructions.md", ".github/instructions/**/*.md", ".windsurfrules", ".windsurf/rules/**/*",
    ".clinerules", ".clinerules/**/*", ".vscode/mcp.json", ".gemini/settings.json", "GEMINI.md", ".codex/config.toml",
    ".roo/rules/**/*", ".aider.conf.yml", ".continue/config.json", ".continue/config.yaml",
]
HOME_FILES = [
    "~/.claude/settings.json", "~/.claude/CLAUDE.md", "~/.cursor/mcp.json", "~/.codex/config.toml",
    "~/.gemini/settings.json", "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json", "~/AppData/Roaming/Claude/claude_desktop_config.json",
    "~/.continue/config.json", "~/.continue/config.yaml",
]
INSTRUCTION_SUFFIXES = {".md", ".mdc", ".txt"}
INSTRUCTION_NAMES = {".cursorrules", ".windsurfrules", ".clinerules"}

HIGH_RISK_PROGRAMS = {"rm", "sudo", "su", "curl", "wget", "nc", "ncat", "netcat", "bash", "sh", "zsh", "eval", "dd", "mkfs",
                      "shred", "chmod", "chown", "base64", "xxd", "env", "printenv", "python", "python3", "node", "perl",
                      "ruby", "ssh", "scp", "sftp", "rsync", "telnet", "socat", "openssl", "gpg", "crontab", "systemctl",
                      "launchctl", "osascript", "powershell", "pwsh", "cmd"}
MEDIUM_RISK_PROGRAMS = {"git", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "uvx", "pipx", "docker", "podman",
                        "kubectl", "helm", "aws", "gcloud", "az", "terraform", "pulumi", "gh", "glab", "vercel", "fly",
                        "flyctl", "heroku", "railway", "make", "cargo", "go", "mvn", "gradle", "dotnet", "brew", "apt",
                        "apt-get", "yum", "dnf", "pacman", "snap", "find", "xargs"}
DANGEROUS_FLAGS = {"--dangerously-skip-permissions", "--allow-all", "--yolo", "--no-sandbox", "--unsafe", "--trust-all",
                   "--allow-all-tools", "--disable-sandbox", "--full-auto", "--approval-mode=yolo", "--permission-mode=bypassPermissions",
                   "-y", "--yes", "--dangerously-allow-browser"}
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|passwd|credential|private[_-]?key|auth|bearer|cookie|session)")
ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}?$|^\$\{user_config\.[A-Za-z0-9_]+\}$")
PLACEHOLDER_RE = re.compile(r"(?i)(xxxx|your[_-]|example|placeholder|redacted|changeme|change-me|<[^>]+>|\.\.\.|\*\*\*|dummy|sample|test-?key|fake|insert|replace|todo|tbd|\$\{)")

# (title, pattern, severity). The generic assignment pattern must stay last; several checks use
# SECRET_PATTERNS[:-1] to mean "known key formats only".
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b"), "critical"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"), "critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "critical"),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}\b"), "critical"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical"),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "critical"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical"),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "critical"),
    ("Hisar agent key", re.compile(r"\bhsk\.ag-[0-9a-f]{12}\.[A-Za-z0-9_-]{32}\b"), "critical"),
    ("Hisar operator token", re.compile(r"\bhop\.op-[0-9a-f]{12}\.[A-Za-z0-9_-]{32}\b"), "critical"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
    ("Generic secret assignment", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|password|passwd|secret)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?"), "high"),
]

# (id, severity, pattern, title, recommendation, negatable). A negatable pattern is skipped when the
# words just before it negate it ("never print a secret", "do not paste tokens"), so security
# guidance is not flagged as an attack.
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str, bool]] = [
    ("INJ-001", "high", re.compile(r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding|system|other)\s+(instructions?|rules?|prompts?|guidance|constraints?)"), "Instruction-override phrase", "Remove it. Instruction files should add guidance, never cancel the host's or user's rules.", False),
    ("INJ-001", "high", re.compile(r"(?i)\b(you are now (?:a|an|in|the)\b|new instructions?:|system override|(?:enter|enable|activate|switch to) developer mode)"), "Role or instruction override phrase", "Remove it. This is the signature of a prompt-injection payload.", False),
    ("INJ-002", "high", re.compile(r"(?i)\b(do not|don't|never|without)\s+(tell|inform|mention|show|notify|ask|alert|warn|reveal (?:this )?to)\s+(the\s+)?(user|human|operator|developer)"), "Instruction to hide actions from the user", "Remove it. Agents must not be told to act without the user's knowledge.", False),
    ("INJ-002", "high", re.compile(r"(?i)\b(silently|secretly|covertly|quietly)\s+(run|execute|send|upload|install|delete|modify|change|post|fetch|download|exfiltrate)"), "Covert action instruction", "Remove it.", True),
    ("INJ-003", "high", re.compile(r"(?i)\b(send|post|upload|transmit|forward|exfiltrate|copy|submit)\s+(?:the\s+|all\s+|every\s+|my\s+|your\s+|our\s+|this\s+|these\s+|it\s+|them\s+)?(?:full\s+|entire\s+|whole\s+|raw\s+)?(?:contents?\s+of\s+(?:the\s+)?)?(data|files?|inbox|emails?|messages?|repository|repo|code|source|logs?|results?|output|history|transcript|conversation|everything|secrets?|keys?|tokens?|credentials?|passwords?|\.env|[\w.-]+)\b[^.\n]{0,40}?\b(to|at)\s+(https?://|www\.|[\w.+-]+@[\w-]+\.[a-z]{2,}|[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(?:com|net|io|dev|ai|org|xyz|site|me|app)\b|a\s+webhook|my\s+server|this\s+url|the\s+url\s+below)"), "Instruction to send data to an external endpoint", "Remove it unless the destination is a documented, approved integration; agents should never be instructed to ship data outward from an instruction file.", True),
    ("INJ-003", "high", re.compile(r"(?i)\b(send|post|upload|include|paste|print|echo|output|share|read|cat|copy|forward|email|reveal|dump|expose)\s+(?:the\s+|all\s+|any\s+|every\s+|my\s+|your\s+|our\s+|its\s+|their\s+|a\s+|an\s+)?(?:contents?\s+of\s+(?:the\s+)?)?(api[_ ]?keys?|tokens?|credentials?|secrets?|passwords?|\.env\b|ssh keys?|private keys?|\.aws/credentials|environment variables?)"), "Instruction that touches secrets", "Remove it. No instruction file should direct an agent to read or emit credentials.", True),
    ("INJ-004", "critical", re.compile(r"(?i)(curl|wget)\b[^\n|]{0,120}\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b"), "Remote code piped into a shell", "Download to a file, review it, pin a hash, then run it. Never pipe remote content into a shell from an instruction file.", True),
    ("INJ-004", "high", re.compile(r"(?i)\b(always|automatically|on (every|each) (start|session|run)|before (anything|every))\b[^.\n]{0,60}\b(run|execute|install|npx|pip install|curl|wget|source)\b"), "Instruction to auto-run commands", "Instruction files that make the agent run commands on every session are a persistence mechanism; move the behaviour into a reviewed hook or remove it.", True),
    ("INJ-008", "high", re.compile(r"(?i)\b(use|set|enable|run|pass|add|start|launch|with|using)\s+(?:the\s+)?(?:flag\s+)?(--dangerously-skip-permissions|bypassPermissions|--yolo|--allow-all)|\b(disable|turn off|skip|bypass|remove)\s+(?:all\s+|the\s+|every\s+|any\s+)?(hooks?|permissions?(?:\s+prompts?| checks?)?|guardrails|sandbox(?:ing)?|safety(?:\s+checks?)?|security(?:\s+checks?)?|approvals?|confirmations?)\b|\bauto-?approve\s+(all|everything|every)\b|\bapprove\s+(all|everything)\s+(?:automatically|without)"), "Instruction to weaken safety controls", "Remove it. Permission and hook settings belong in reviewed settings files, not in prose the model reads.", True),
    ("INJ-008", "high", re.compile(r"(?i)\b(rm\s+-rf\s+[/~.*]|chmod\s+(-R\s+)?777|git\s+push\s+(-f|--force)\b[^\n]*\b(main|master)\b|mkfs\.|:\(\)\s*\{\s*:\|:&\s*\};:)"), "Destructive command in instruction file", "Remove it or make it an explicit, user-triggered step with confirmation.", True),
    ("INJ-009", "high", re.compile(r"(?i)\b(cat|read|open|print|echo|source|dump|copy|upload)\b[^.\n]{0,40}(~/\.ssh/|\.aws/credentials|/etc/shadow|~/\.netrc|id_rsa|id_ed25519|\.git-credentials|~/\.npmrc|~/\.config/gh)"), "Instruction to read credential files", "Remove it.", True),
]
NEGATION_RE = re.compile(r"(?i)\b(never|not|don't|do not|must not|should not|shouldn't|won't|cannot|can't|no|without|avoid|refuse|forbid|forbidden|prohibited|instead of|rather than|unless)\b[^.\n]{0,25}$")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
IMPERATIVE_RE = re.compile(r"(?i)\b(always|never|must|run|execute|send|ignore|do not|don't|install|curl|wget|delete|upload|post)\b")
ZERO_WIDTH_RE = re.compile("[​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎]")
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
NETWORK_TOOL_RE = re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?://")
PIPE_TO_SHELL_RE = re.compile(r"(?i)(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b")
