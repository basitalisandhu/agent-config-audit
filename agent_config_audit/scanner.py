"""The scanner: discovers agent configuration files and runs every check over them.

Read-only, standard library only, no network.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
from pathlib import Path

from .config import AuditConfig, load_config
from .findings import Finding, redact, shannon_entropy
from .patterns import (
    BASE64_BLOB_RE,
    BIDI_RE,
    CREDENTIAL_HELPER_KEYS,
    DANGEROUS_FLAGS,
    ENV_REF_RE,
    HELPER_KEYS,
    HIGH_RISK_PROGRAMS,
    HOME_FILES,
    HOOK_EVENTS,
    HTML_COMMENT_RE,
    IMPERATIVE_RE,
    IMPORT_RE,
    INJECTION_PATTERNS,
    INSTRUCTION_NAMES,
    INSTRUCTION_SUFFIXES,
    MAX_FILE_BYTES,
    MAX_IMPORT_DEPTH,
    MEDIUM_RISK_PROGRAMS,
    NEGATION_RE,
    NETWORK_TOOL_RE,
    PIPE_TO_SHELL_RE,
    PLACEHOLDER_RE,
    PLUGIN_COMPONENT_DIRS,
    PLUGIN_COMPONENT_GLOBS,
    PRIMARY_FIELDS,
    PROJECT_GLOBS,
    RESERVED_PLUGIN_PREFIXES,
    RUNNER_PREFIXES,
    SECRET_KEY_RE,
    SECRET_PATTERNS,
    SHELL_WRAPPERS,
    TAG_CHARS_RE,
    ZERO_WIDTH_RE,
)


class Auditor:
    def __init__(
        self,
        root: Path,
        include_home: bool = False,
        extra: list[Path] | None = None,
        config: AuditConfig | None = None,
    ):
        self.root = root.resolve()
        self.include_home = include_home
        self.extra = [p.resolve() for p in (extra or [])]
        self.config = config if config is not None else load_config(self.root)
        self.findings: list[Finding] = []
        self.suppressed: list[dict] = []
        self.scanned: list[str] = []
        self.errors: list[str] = []
        self._seen: set = set()
        self._plugin_roots: list[Path] | None = None
        self._scanned_paths: set[Path] = set()

    # ------------------------------------------------------------------ helpers
    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def add(self, fid: str, severity: str, category: str, title: str, path: Path, line: int | None, evidence: str, recommendation: str) -> None:
        f = Finding(fid, severity, category, title, self.rel(path), line, redact(evidence)[:300], recommendation)
        if f.key() in self._seen:
            return
        self._seen.add(f.key())
        reason = self.config.allows(f.id, f.file, f.evidence)
        if reason is not None:
            self.suppressed.append({"id": f.id, "file": f.file, "line": f.line, "reason": reason})
            return
        self.findings.append(f)

    @staticmethod
    def line_of(text: str, needle: str) -> int | None:
        if not needle:
            return None
        idx = text.find(needle)
        if idx < 0:
            idx = text.find(needle.split("\n")[0][:40])
        if idx < 0:
            return None
        return text.count("\n", 0, idx) + 1

    def read(self, path: Path) -> str | None:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                self.errors.append(f"skipped {path}: larger than {MAX_FILE_BYTES} bytes")
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.errors.append(f"could not read {path}: {exc}")
            return None

    # ------------------------------------------------------------------ discovery
    def targets(self) -> list[Path]:
        found: list[Path] = []
        for pattern in PROJECT_GLOBS:
            for p in sorted(self.root.glob(pattern)):
                if not p.is_file() or "node_modules" in p.parts or ".git" in p.parts:
                    continue
                if self.config.path_excluded(self.rel(p)):
                    continue
                found.append(p)
        for plugin_root in self.plugin_roots():
            for pattern in PLUGIN_COMPONENT_GLOBS:
                for p in sorted(plugin_root.glob(pattern)):
                    if p.is_file() and "node_modules" not in p.parts and not self.config.path_excluded(self.rel(p)):
                        found.append(p)
        if self.include_home:
            home = Path(os.path.expanduser("~"))
            for h in HOME_FILES:
                if "*" in h:
                    found.extend(sorted(p for p in home.glob(h.removeprefix("~/")) if p.is_file()))
                    continue
                p = Path(os.path.expanduser(h))
                if p.is_file():
                    found.append(p)
        found.extend(p for p in self.extra if p.is_file())
        uniq: list[Path] = []
        seen = set()
        for p in found:
            r = p.resolve()
            if r not in seen:
                seen.add(r)
                uniq.append(p)
        return uniq

    # ------------------------------------------------------------------ dispatch
    def run(self) -> None:
        targets = self.targets()
        self._scanned_paths = {p.resolve() for p in targets}
        for path in targets:
            self.scanned.append(self.rel(path))
            self.check_mode(path)
            text = self.read(path)
            if text is None:
                continue
            self.scan_secrets(path, text)
            name = path.name
            if name.endswith(".json"):
                self.scan_json(path, text)
            elif name.endswith(".toml"):
                self.scan_toml(path, text)
            elif path.suffix in INSTRUCTION_SUFFIXES or name in INSTRUCTION_NAMES or "rules" in path.parts or "instructions" in path.parts:
                self.scan_instructions(path, text)
                if self.follows_imports(path):
                    self.scan_imports(path, text, depth=1)
                if name == "SKILL.md" or "commands" in path.parts or "agents" in path.parts:
                    self.scan_frontmatter(path, text)
            elif "hooks" in path.parts:
                self.scan_hook_script(path, text)
        for plugin_root in self.plugin_roots():
            if (plugin_root / "bin").is_dir():
                self.add("PLUGIN-001", "low", "plugin", "Plugin ships a bin/ directory that goes on the Bash PATH",
                         plugin_root / "bin", None, "bin/", "Review every executable in bin/; while the plugin is enabled the agent can run them as bare commands.")

    def plugin_roots(self) -> list[Path]:
        """Plugin directories under the root. The manifest is optional (https://code.claude.com/docs/en/plugins/manifest-reference),
        so a plugins/<name>/ directory with any default component counts, and so does every relative source in a marketplace.json."""
        if self._plugin_roots is not None:
            return self._plugin_roots
        roots: list[Path] = []
        for manifest in list(self.root.glob(".claude-plugin/plugin.json")) + list(self.root.glob("plugins/*/.claude-plugin/plugin.json")):
            roots.append(manifest.parent.parent)
        for d in sorted(self.root.glob("plugins/*")):
            if d.is_dir() and any((d / c).exists() for c in PLUGIN_COMPONENT_DIRS):
                roots.append(d)
        market = self.root / ".claude-plugin" / "marketplace.json"
        if market.is_file():
            try:
                data = json.loads(market.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = {}
            entries = data.get("plugins") if isinstance(data, dict) else None
            base = self.root
            if isinstance(data, dict) and isinstance(data.get("metadata"), dict) and isinstance(data["metadata"].get("pluginRoot"), str):
                base = self.root / data["metadata"]["pluginRoot"]
            for entry in entries if isinstance(entries, list) else []:
                src = entry.get("source") if isinstance(entry, dict) else None
                if isinstance(src, str) and not re.match(r"^[a-z][a-z0-9+.-]*://", src):
                    d = (base / src).resolve()
                    if d.is_dir() and (d == self.root or self.root in d.parents):
                        roots.append(d)
        uniq: list[Path] = []
        for r in roots:
            if r.resolve() not in [u.resolve() for u in uniq]:
                uniq.append(r)
        self._plugin_roots = uniq
        return uniq

    # ------------------------------------------------------------------ checks
    def check_mode(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            mode = path.stat().st_mode
        except OSError:
            return
        if mode & stat.S_IWOTH:
            self.add("FILE-001", "medium", "file", "Agent configuration file is world-writable", path, None, oct(mode & 0o777),
                     "chmod o-w the file. Anyone on the machine could add hooks, permissions or instructions.")

    def scan_secrets(self, path: Path, text: str) -> None:
        for title, pattern, sev in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if title == "Generic secret assignment":
                    value = m.group(2)
                    if ENV_REF_RE.match(value) or value.startswith("$") or PLACEHOLDER_RE.search(value) or value.lower().startswith(("http", "bearer", "basic")):
                        continue
                    if shannon_entropy(value) < 3.0 or len(set(value)) < 8:
                        continue
                    if " " in value:
                        continue
                elif PLACEHOLDER_RE.search(value) or (len(set(value)) < 8 and "PRIVATE KEY" not in value):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                self.add("SEC-001", sev, "secret", f"{title} found in agent configuration", path, line, m.group(0),
                         "Move the value to an environment variable or a secret store, reference it as ${VAR}, rotate it now, and purge it from history.")

    def scan_json(self, path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.add("CFG-001", "low", "config", "JSON file does not parse", path, exc.lineno, str(exc)[:120],
                     "Fix the syntax; a config that fails to parse is silently ignored by most hosts, so its protections (deny rules, hooks) are not applied.")
            return
        if path.name == "monitors.json":
            self.scan_monitors(path, text, data)
            return
        if not isinstance(data, dict):
            return
        if path.name == ".claude.json":
            # ~/.claude.json keeps user MCP servers at the top level and per-project servers under projects.<path>.
            for proj in (data.get("projects") or {}).values() if isinstance(data.get("projects"), dict) else []:
                if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                    self.scan_mcp(path, text, {k: v for k, v in proj["mcpServers"].items() if isinstance(v, dict)})
        if "permissions" in data or "hooks" in data or "enableAllProjectMcpServers" in data or "disableAllHooks" in data or any(k in data for k in HELPER_KEYS):
            self.scan_settings(path, text, data)
            self.scan_helpers(path, text, data)
        plugin_root = self.plugin_root_for(path)
        if isinstance(data.get("hooks"), dict):
            self.scan_hooks(path, text, data["hooks"], plugin_root=plugin_root)
        servers = self.extract_mcp_servers(data)
        if servers:
            self.scan_mcp(path, text, servers)
        if path.name == "plugin.json" and path.parent.name == ".claude-plugin":
            self.scan_manifest(path, text, data)
        if path.name == ".lsp.json":
            for name, cfg in data.items():
                if isinstance(cfg, dict):
                    self.scan_command_line(path, text, f"LSP server {name}", cfg.get("command"), cfg.get("args"))

    def in_plugin(self, path: Path) -> bool:
        return self.plugin_root_for(path) is not None or "plugins" in Path(self.rel(path)).parts

    def plugin_root_for(self, path: Path) -> Path | None:
        roots = {r.resolve() for r in self.plugin_roots()}
        for parent in [path.parent, *path.parents]:
            if (parent / ".claude-plugin" / "plugin.json").exists() or parent.resolve() in roots:
                return parent
        return None

    @staticmethod
    def extract_mcp_servers(data: dict) -> dict:
        for key in ("mcpServers", "servers"):
            if isinstance(data.get(key), dict):
                return {k: v for k, v in data[key].items() if isinstance(v, dict)}
        if data and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
            return dict(data)
        return {}

    # settings.json ------------------------------------------------------------
    def is_project_settings(self, path: Path) -> bool:
        """True for .claude/settings.json and .claude/settings.local.json inside the audited root."""
        try:
            rel = path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return False
        return rel.endswith((".claude/settings.json", ".claude/settings.local.json"))

    def scan_settings(self, path: Path, text: str, data: dict) -> None:
        perms = data.get("permissions")
        if not isinstance(perms, dict):
            perms = {}
        mode = perms.get("defaultMode") or data.get("defaultMode")
        project = self.is_project_settings(path)
        # https://code.claude.com/docs/en/settings: defaultMode auto and bypassPermissions do not take
        # effect from project or local settings (bypassPermissions did before Claude Code v2.1.257).
        if mode == "bypassPermissions":
            if project:
                self.add("PERM-003", "high", "permissions", "defaultMode is bypassPermissions in project settings", path, self.line_of(text, "bypassPermissions"),
                         '"defaultMode": "bypassPermissions"', "Remove it. Claude Code v2.1.257 and later ignore this value in project and local settings, but older versions and other hosts that read the file apply it and drop every prompt.")
            else:
                self.add("PERM-003", "critical", "permissions", "defaultMode is bypassPermissions", path, self.line_of(text, "bypassPermissions"),
                         '"defaultMode": "bypassPermissions"', "Use default (Manual) or acceptEdits, and allowlist specific commands instead. Bypass mode removes every prompt, including for destructive commands.")
        elif mode == "auto":
            if project:
                self.add("PERM-003", "low", "permissions", "defaultMode auto in project settings has no effect", path, self.line_of(text, '"auto"'), '"defaultMode": "auto"',
                         "Remove it. Claude Code applies auto mode only from user or managed settings or --permission-mode, so this line only signals intent.")
            else:
                self.add("PERM-003", "medium", "permissions", "defaultMode is auto", path, self.line_of(text, '"auto"'), '"defaultMode": "auto"',
                         "Confirm this is intended: in auto mode a background classifier, not you, approves shell commands and network requests.")
        if data.get("skipDangerousModePermissionPrompt") is True:
            self.add("PERM-003", "high", "permissions", "Dangerous-mode prompt is skipped", path, self.line_of(text, "skipDangerousModePermissionPrompt"),
                     "skipDangerousModePermissionPrompt: true", "Remove it.")
        if data.get("enableAllProjectMcpServers") is True:
            self.add("PERM-007", "medium", "permissions", "All project MCP servers are auto-approved", path, self.line_of(text, "enableAllProjectMcpServers"),
                     '"enableAllProjectMcpServers": true', "Approve project MCP servers one by one. A malicious .mcp.json in a cloned repo would otherwise start automatically.")
        if data.get("disableAllHooks") is True:
            self.add("PERM-008", "medium", "permissions", "All hooks are disabled", path, self.line_of(text, "disableAllHooks"), '"disableAllHooks": true',
                     "Re-enable hooks; guard hooks such as secret-exposure blocking do not run while this is set.")
        lists = {k: [r for r in perms.get(k) or [] if isinstance(r, str)] if isinstance(perms.get(k), list) else [] for k in ("allow", "deny", "ask")}
        for rule in lists["allow"]:
            self.scan_allow_rule(path, text, rule)
        for kind, rules in lists.items():
            for rule in rules:
                self.check_ignored_rule(path, text, kind, rule)
        dirs = perms.get("additionalDirectories")
        for d in dirs if isinstance(dirs, list) else []:
            if isinstance(d, str) and (d.rstrip("/") or "/") in {"/", "~", "$HOME", os.path.expanduser("~"), "/home", "/Users", "C:\\", "C:"}:
                self.add("PERM-010", "medium", "permissions", "additionalDirectories grants the whole home or root directory", path, self.line_of(text, d), d,
                         "Grant the specific project directories you need.")
        broad = any(r.split("(")[0] in {"Bash", "PowerShell", "Write", "Edit", "MultiEdit"} and ("(" not in r or r.endswith(("(*)", "(:*)"))) for r in lists["allow"])
        if broad and not lists["deny"]:
            self.add("PERM-011", "low", "permissions", "Broad allow rules with no deny rules", path, None, "permissions.deny is empty",
                     "Add deny rules for the commands and paths that must never run (for example Bash(rm -rf *), Read(./.env), Bash(curl *)).")

    def scan_helpers(self, path: Path, text: str, data: dict) -> None:
        """Settings keys whose value is a command Claude Code runs (https://code.claude.com/docs/en/settings-reference)."""
        project = self.is_project_settings(path)
        for key in HELPER_KEYS:
            value = data.get(key)
            command = value.get("command") if isinstance(value, dict) else value
            if not isinstance(command, str) or not command.strip():
                continue
            self.scan_command_line(path, text, key, command, None)
            if project and key in CREDENTIAL_HELPER_KEYS:
                self.add("HOOK-008", "medium", "hooks", f"Project settings define {key}", path, self.line_of(text, f'"{key}"'), f"{key}: {command}",
                         f"Move {key} to your user settings. A repository that sets it runs its own command to produce your credentials, and Claude Code uses project helpers even before you trust the folder in claude -p.")

    def scan_command_line(self, path: Path, text: str, label: str, command: object, args: object) -> None:
        """Network, pipe-to-shell and credential checks for a command that is not a hook (helpers, monitors, LSP servers)."""
        if not isinstance(command, str):
            return
        argv = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
        full = " ".join([command, *argv])
        line = self.line_of(text, command)
        if PIPE_TO_SHELL_RE.search(full):
            self.add("HOOK-004", "critical", "hooks", f"{label} pipes remote content into a shell", path, line, full, "Bundle the script and call it by path.")
        elif NETWORK_TOOL_RE.search(full) and not re.search(r"(?i)localhost|127\.0\.0\.1", full):
            self.add("HOOK-002", "high", "hooks", f"{label} command can reach the network", path, line, full,
                     "Confirm what the command sends and where; it runs on your machine with your environment.")
        for title, pattern, _sev in SECRET_PATTERNS[:-1]:
            if pattern.search(full):
                self.add("HOOK-003", "critical", "hooks", f"{label} command contains a {title}", path, line, full, "Read the secret from the environment instead.")

    def scan_monitors(self, path: Path, text: str, data: object) -> None:
        entries = data if isinstance(data, list) else (data.get("monitors") if isinstance(data, dict) and "monitors" in data else list(data.values()) if isinstance(data, dict) else [])
        for m in entries if isinstance(entries, list) else []:
            if isinstance(m, dict):
                self.scan_command_line(path, text, f"Monitor {m.get('name') or ''}".strip(), m.get("command"), m.get("args"))

    def scan_manifest(self, path: Path, text: str, data: dict) -> None:
        """plugin.json fields that load code from other files (https://code.claude.com/docs/en/plugins/manifest-reference)."""
        root = path.parent.parent
        name = data.get("name")
        if isinstance(name, str) and name.lower().startswith(RESERVED_PLUGIN_PREFIXES):
            self.add("PLUGIN-002", "medium", "plugin", f"Plugin name {name} uses a reserved prefix", path, self.line_of(text, f'"{name}"'), name,
                     "Rename it. claude plugin validate rejects names starting with claude-, anthropic-, anthropics- or cc-plugin-, and such a name can pass for an official plugin.")
        for key in ("skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles", "workflows"):
            value = data.get(key)
            refs = [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
            for ref in refs:
                if re.match(r"^https?://", ref) or ref.startswith("${"):
                    continue
                target = (root / ref).resolve()
                if ref.startswith(("/", "~")) or ".." in Path(ref).parts or (target != root.resolve() and root.resolve() not in target.parents):
                    self.add("PLUGIN-002", "medium", "plugin", f"Plugin {key} path points outside the plugin", path, self.line_of(text, ref), f"{key}: {ref}",
                             "Keep every component path relative (./...) and inside the plugin directory; Claude Code refuses paths that leave it.")
                    continue
                if key in {"hooks", "mcpServers", "lspServers"} and target.is_file() and target.suffix == ".json":
                    body = self.read(target)
                    if body is None:
                        continue
                    self.scanned.append(self.rel(target))
                    self.scan_secrets(target, body)
                    self.scan_json(target, body)
        if isinstance(data.get("lspServers"), dict):
            for lname, cfg in data["lspServers"].items():
                if isinstance(cfg, dict):
                    self.scan_command_line(path, text, f"LSP server {lname}", cfg.get("command"), cfg.get("args"))
        experimental = data.get("experimental") if isinstance(data.get("experimental"), dict) else {}
        for monitors in (experimental.get("monitors"), data.get("monitors")):
            if isinstance(monitors, list | dict):
                self.scan_monitors(path, text, monitors)

    def check_ignored_rule(self, path: Path, text: str, kind: str, rule: str) -> None:
        """PERM-013: rule shapes Claude Code skips or never matches (https://code.claude.com/docs/en/permissions)."""
        tool, paren, spec = rule.partition("(")
        tool = tool.strip()
        spec = spec[:-1] if spec.endswith(")") else spec
        reason = None
        if not paren and "*" in tool and kind == "allow" and not re.match(r"^mcp__[^*]+__", tool):
            reason = "Claude Code skips allow rules whose tool name is a glob not anchored to one MCP server (such as *, B* or mcp__*), so it approves nothing"
        elif paren and tool.startswith("mcp__"):
            reason = "Claude Code skips any mcp__ rule that has parentheses when it loads a settings file"
        elif paren and tool in PRIMARY_FIELDS and re.match(rf"^\s*{PRIMARY_FIELDS[tool]}\s*:", spec):
            value = re.sub(r"^\s*[a-z_]+\s*:\s*", "", spec)
            reason = f"Claude Code ignores parameter rules on the primary input field of {tool}; write {tool}({value}) instead"
        elif paren and tool in {"Bash", "PowerShell"} and ":*" in spec and not spec.rstrip().endswith(":*"):
            reason = "The :* suffix is only recognised at the end of a pattern; elsewhere the colon is literal, so the rule matches almost nothing"
        if reason is None:
            return
        if kind == "allow":
            self.add("PERM-013", "info", "permissions", "Allow rule has no effect in Claude Code", path, self.line_of(text, rule), rule, f"Remove or rewrite it. {reason}.")
        else:
            self.add("PERM-013", "medium", "permissions", f"{kind.capitalize()} rule is not applied by Claude Code", path, self.line_of(text, rule), rule,
                     f"Rewrite it so the restriction you meant actually holds. {reason}.")

    @staticmethod
    def shell_words(spec: str) -> list[str]:
        """Split a Bash or PowerShell rule specifier into words, with :* read as a trailing ' *' and wrappers removed."""
        spec = spec.strip()
        if spec.endswith(":*"):
            spec = spec[:-2] + " *"
        words = spec.split()
        # Claude Code strips these wrappers and safe VAR=value prefixes before matching, so the program is the next word.
        while words and (words[0] in SHELL_WRAPPERS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0])):
            rest = words[1:]
            if words[0] in {"timeout", "nice", "stdbuf"}:
                while rest and (rest[0].startswith("-") or re.match(r"^\d+[smhd]?$", rest[0])):
                    rest = rest[1:]
            if not rest or rest[0] in {"*", "**"}:
                break  # "Bash(timeout *)": the wrapper itself is the rule; do not guess what it matches.
            words = rest
        return words

    def scan_allow_rule(self, path: Path, text: str, rule: str) -> None:
        tool, _, spec = rule.partition("(")
        spec = spec[:-1] if spec.endswith(")") else spec
        line = self.line_of(text, rule)
        tool_l = tool.strip()
        if tool_l == "Read" and re.search(r"(?:^|[/\\])(?:\.env(?![^/\\]*\.(?:example|sample|template)(?:$|[/\\]))[^/\\]*|\.ssh|\.aws|\.netrc|id_rsa|id_ed25519)(?:$|[/\\])|(?:^|[/\\])[^/\\]*\.(?:pem|key)$", spec):
            self.add("PERM-012", "medium", "permissions", "Read allow rule covers a secret-bearing path", path, line, rule,
                     "Remove the pre-approval for credential stores and private keys; allow only the project files needed and retain a prompt for secrets.")
        if tool_l in {"Bash", "PowerShell"}:
            words = self.shell_words(spec)
            if not words or (words[0] in {"*", "**"} and len(words) == 1):
                self.add("PERM-001", "critical", "permissions", "Any shell command is pre-approved", path, line, rule,
                         f"Replace with specific rules such as {tool_l}(npm test), {tool_l}(git status *), {tool_l}(pytest *).")
                return
            if words[0] in {"*", "**"}:
                self.add("PERM-002", "high", "permissions", "Rule starts with a wildcard, so any program matches", path, line, rule,
                         "Put the program first, for example Bash(node --version). A leading * lets any program run, including bash -c '...'.")
                return
            prog = os.path.basename(words[0])
            glued = prog.endswith("*")
            prog = prog.rstrip("*")
            if tool_l == "PowerShell":
                prog = prog.lower()
            # "rm *", "rm -rf *", "git * main" and "rm*" all pre-approve arbitrary targets: only flags may sit between the program and the wildcard.
            star = next((i for i, w in enumerate(words) if i > 0 and w in {"*", "**"}), None)
            wildcard_next = glued or len(words) == 1 or (star is not None and all(w.startswith("-") for w in words[1:star]))
            runner = next((" ".join(r) for r in RUNNER_PREFIXES if [w.lower() for w in words[: len(r)]] == list(r) and (len(words) == len(r) or "*" in words[len(r)])), None)
            if runner and (len(words) > 1 or glued):
                self.add("PERM-002", "high", "permissions", f"Pre-approved runner executes any command: {runner}", path, line, rule,
                         f"Write one rule per inner command, for example {tool_l}({runner} npm test). {runner} runs whatever follows it, so {rule} also approves {runner} rm -rf .")
            elif prog in HIGH_RISK_PROGRAMS and wildcard_next:
                self.add("PERM-002", "high", "permissions", f"Dangerous program pre-approved with a wildcard: {prog}", path, line, rule,
                         f"Narrow the rule to the exact invocations you need (for example {tool_l}({prog} --version)), or remove it.")
            elif prog in HIGH_RISK_PROGRAMS:
                self.add("PERM-002", "low", "permissions", f"Risky program pre-approved with a narrow pattern: {prog}", path, line, rule,
                         "Confirm the pattern cannot be widened with shell tricks (quotes, variables, command substitution).")
            elif prog in MEDIUM_RISK_PROGRAMS and wildcard_next:
                self.add("PERM-002", "medium", "permissions", f"Broad pre-approval for {prog}", path, line, rule,
                         f"Prefer subcommand-level rules (for example {tool_l}({prog} status *)) so that publish, push --force or install of arbitrary packages still prompt.")
            if any(flag in spec for flag in DANGEROUS_FLAGS if flag not in {"-y", "--yes"}):
                self.add("PERM-009", "high", "permissions", "Pre-approved command carries a permission-bypass flag", path, line, rule, "Remove the flag from the rule.")
        elif tool_l in {"Write", "Edit", "MultiEdit", "NotebookEdit"} and (not spec.strip() or spec.strip() in {"*", "**", "**/*", "/**", "//**"}):
            self.add("PERM-004", "medium", "permissions", f"{tool_l} is pre-approved for every path", path, line, rule,
                     "Scope it to the project (for example Write(./src/**)) and deny .claude/, .git/ and dotfiles.")
        elif tool_l in {"WebFetch", "WebSearch"} and (not spec.strip() or spec.strip() in {"*", "domain:*"}):
            self.add("PERM-005", "medium", "permissions", f"{tool_l} is pre-approved for every domain", path, line, rule,
                     "Allow specific domains (WebFetch(domain:docs.example.com)). Unrestricted fetch is a data-exfiltration channel under prompt injection.")
        elif re.match(r"^mcp__[^*_][^*]*?(__\*)?$", tool_l) and (tool_l.endswith("__*") or tool_l.count("__") == 1) and not spec:
            self.add("PERM-006", "medium", "permissions", "Every tool of an MCP server is pre-approved", path, line, rule,
                     "Allow the individual read-only tools you need; keep write and delete tools behind a prompt.")

    # hooks ----------------------------------------------------------------------
    def scan_hooks(self, path: Path, text: str, hooks: dict, plugin_root: Path | None) -> None:
        claude = self.is_claude_code_file(path)
        for event, matchers in hooks.items():
            if claude and event not in HOOK_EVENTS:
                close = next((e for e in HOOK_EVENTS if e.lower() == str(event).lower()), None)
                hint = f" Did you mean {close}?" if close else ""
                self.add("HOOK-007", "medium", "hooks", f"Unknown hook event {event} is ignored", path, self.line_of(text, f'"{event}"'), str(event),
                         f"Use one of the Claude Code hook events (https://code.claude.com/docs/en/hooks).{hint} Claude Code ignores the entry at runtime, so the control it was meant to add never runs.")
            if not isinstance(matchers, list):
                continue
            for matcher in matchers:
                if not isinstance(matcher, dict):
                    continue
                for h in matcher.get("hooks") if isinstance(matcher.get("hooks"), list) else []:
                    if not isinstance(h, dict):
                        continue
                    self.scan_hook(path, text, event, h, plugin_root)

    def is_claude_code_file(self, path: Path) -> bool:
        parts = Path(self.rel(path)).parts
        return ".gemini" not in parts and ".continue" not in parts and "claude_desktop_config.json" not in parts

    def scan_hook(self, path: Path, text: str, event: str, h: dict, plugin_root: Path | None) -> None:
        htype = h.get("type", "command")
        command = h.get("command") if isinstance(h.get("command"), str) else ""
        args = [a for a in h.get("args") if isinstance(a, str)] if isinstance(h.get("args"), list) else []
        full = " ".join([command, *args])
        url = h.get("url") if isinstance(h.get("url"), str) else ""
        line = self.line_of(text, command or url or "")
        if htype == "http":
            # https://code.claude.com/docs/en/hooks: an http hook POSTs the event JSON (tool input included) to url.
            host = re.sub(r"^[a-z]+://", "", url).split("/")[0].split("@")[-1]
            host = (host.split("]")[0].strip("[") if host.startswith("[") else host.split(":")[0]).lower()
            loopback = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")
            if host and not loopback:
                self.add("HOOK-002", "high", "hooks", f"{event} hook posts tool data to a remote endpoint", path, line, url,
                         "Hook payloads include commands, file paths and sometimes file contents. Keep HTTP hooks on loopback or make sure the endpoint is yours and uses HTTPS; allowedHttpHookUrls in managed settings can pin the allowed endpoints.")
            elif host:
                self.add("HOOK-002", "low", "hooks", f"{event} hook posts tool data to a local service", path, line, url,
                         "Confirm which program listens on that port; any local process that binds it receives every hook payload.")
            if url.startswith("http://") and not loopback:
                self.add("MCP-001", "high", "hooks", "HTTP hook uses plain HTTP", path, line, url, "Use https://.")
            headers = h.get("headers") if isinstance(h.get("headers"), dict) else {}
            for hname, hval in headers.items():
                if isinstance(hval, str) and "$" not in hval:
                    known = next((t for t, p, _ in SECRET_PATTERNS[:-1] if p.search(hval)), None)
                    literal = re.match(r"(?i)^(bearer|basic|token)\s+(\S{12,})$", hval.strip()) or (SECRET_KEY_RE.search(hname) and len(hval) >= 12 and shannon_entropy(hval) >= 3.0)
                    if (known or literal) and not PLACEHOLDER_RE.search(hval):
                        self.add("HOOK-003", "critical" if known else "high", "hooks", f"{event} hook header {hname} holds a literal credential", path, self.line_of(text, hval) or line, f"{hname}: {hval}",
                                 "Write it as $VAR_NAME and list the variable in allowedEnvVars; rotate the exposed value.")
            return
        if htype in {"prompt", "agent"}:
            prompt = h.get("prompt") if isinstance(h.get("prompt"), str) else ""
            pline = self.line_of(text, prompt[:40]) if prompt else line
            for fid, sev, pattern, title, rec, negatable in INJECTION_PATTERNS:
                for m in pattern.finditer(prompt):
                    if negatable and NEGATION_RE.search(prompt[max(0, m.start() - 40): m.start()]):
                        continue
                    self.add(fid, sev, "injection", f"{title} in a {htype} hook", path, pline, m.group(0), rec)
            return
        if htype != "command":
            return
        if PIPE_TO_SHELL_RE.search(full):
            self.add("HOOK-004", "critical", "hooks", f"{event} hook pipes remote content into a shell", path, line, full,
                     "Bundle the script with the repository or plugin and call it by path.")
        elif NETWORK_TOOL_RE.search(full) and not re.search(r"(?i)localhost|127\.0\.0\.1", full):
            self.add("HOOK-002", "high", "hooks", f"{event} hook can reach the network", path, line, full,
                     "Hooks receive the tool input (commands, paths, prompts). A hook that calls curl, ssh or an external URL can exfiltrate them. Keep hooks local or document exactly what is sent where.")
        for title, pattern, _sev in SECRET_PATTERNS[:-1]:
            if pattern.search(full):
                self.add("HOOK-003", "critical", "hooks", f"{event} hook command contains a {title}", path, line, full,
                         "Read the secret from the environment inside the script instead.")
        if "${CLAUDE_PLUGIN_ROOT}" in command and not args and not re.search(r"\"\$\{CLAUDE_PLUGIN_ROOT\}[^\"]*\"", command):
            self.add("HOOK-005", "low", "hooks", "Shell-form hook leaves ${CLAUDE_PLUGIN_ROOT} unquoted", path, line, command,
                     'Quote it ("${CLAUDE_PLUGIN_ROOT}"/script.sh) or use exec form with args so a path with spaces stays one argument.')
        script = self.hook_script_path(command, args, plugin_root)
        if script is not None and not script.exists():
            self.add("HOOK-001", "medium", "hooks", f"{event} hook references a script that does not exist", path, line, str(script),
                     "Fix the path. A missing hook fails open (the tool runs) or fails loudly, depending on the host; either way the control it was meant to add is absent.")
        elif script is not None and script.exists() and os.name == "posix" and (script.stat().st_mode & stat.S_IWOTH):
            self.add("HOOK-006", "high", "hooks", "Hook script is world-writable", path, line, str(script),
                     "chmod o-w the script. Anyone on the machine could change what runs on every tool call.")

    def hook_script_path(self, command: str, args: list[str], plugin_root: Path | None) -> Path | None:
        candidates = args[:1] if args else []
        if not candidates:
            try:
                words = shlex.split(command)
            except ValueError:
                return None
            candidates = [
                w for w in words
                if not re.match(r"^[a-z][a-z0-9+.-]*://", w) and not w.startswith(("-", "@"))
                and ("/" in w or w.endswith((".sh", ".py", ".js", ".mjs", ".ts", ".rb")))
            ][:1]
        if not candidates:
            return None
        raw = candidates[0]
        if "${CLAUDE_PLUGIN_ROOT}" in raw:
            if plugin_root is None:
                return None
            raw = raw.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root))
        raw = raw.replace("${CLAUDE_PROJECT_DIR}", str(self.root)).replace("$CLAUDE_PROJECT_DIR", str(self.root))
        if "${" in raw or "$" in raw or raw.startswith(("-", "|")):
            return None
        p = Path(os.path.expanduser(raw))
        if not p.is_absolute():
            p = self.root / p
        return p

    def scan_hook_script(self, path: Path, text: str) -> None:
        pipe = PIPE_TO_SHELL_RE.search(text)
        if pipe:
            self.add("HOOK-004", "critical", "hooks", "Hook script pipes remote content into a shell", path, self.line_of(text, "curl") or self.line_of(text, "wget"),
                     pipe.group(0), "Vendor the script instead.")
        elif NETWORK_TOOL_RE.search(text) and not re.search(r"(?i)localhost|127\.0\.0\.1", text):
            m = NETWORK_TOOL_RE.search(text)
            assert m is not None
            self.add("HOOK-002", "medium", "hooks", "Hook script can reach the network", path, text.count("\n", 0, m.start()) + 1, m.group(0),
                     "Confirm what the script sends and where; hook input contains commands, paths and prompts.")

    # MCP ------------------------------------------------------------------------
    def scan_mcp(self, path: Path, text: str, servers: dict) -> None:
        for name, cfg in servers.items():
            url = cfg.get("url") if isinstance(cfg.get("url"), str) else ""
            stype = cfg.get("type") or ("http" if url else "stdio")
            line = self.line_of(text, f'"{name}"')
            if url:
                host = re.sub(r"^[a-z]+://", "", url).split("/")[0].split("@")[-1]
                hostname = host.rsplit(":", 1)[0].strip("[]") if not host.startswith("[") else host.split("]")[0].strip("[")
                loop = hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or hostname.endswith(".localhost")
                if url.startswith(("http://", "ws://")) and not loop:
                    self.add("MCP-001", "high", "mcp", f"MCP server {name} uses plain {url.split(':')[0].upper()}", path, line, url,
                             "Use https:// or wss://. Tokens in headers and every tool result travel in clear text otherwise.")
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) and not loop:
                    self.add("MCP-008", "medium", "mcp", f"MCP server {name} is addressed by raw IP", path, line, url,
                             "Use a DNS name with a valid certificate so the server identity can be verified and pinned.")
                if stype == "sse":
                    self.add("MCP-006", "low", "mcp", f"MCP server {name} uses the deprecated SSE transport", path, line, '"type": "sse"', "Switch to type http (streamable HTTP).")
            for hname, hval in (cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}).items():
                if isinstance(hval, str):
                    self.literal_credential(path, line, name, f"headers.{hname}", hval)
            for ename, eval_ in (cfg.get("env") if isinstance(cfg.get("env"), dict) else {}).items():
                if isinstance(eval_, str):
                    self.literal_credential(path, line, name, f"env.{ename}", eval_)
            command = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
            args = [a for a in cfg.get("args") if isinstance(a, str)] if isinstance(cfg.get("args"), list) else []
            self.pinning(path, line, name, command, args)
            joined = " ".join([command, *args])
            for flag in DANGEROUS_FLAGS:
                if flag in {"-y", "--yes"}:
                    continue
                if flag in args or f" {flag}" in joined:
                    self.add("MCP-005", "medium", "mcp", f"MCP server {name} is started with {flag}", path, line, joined, "Remove the flag; run the server with its default safety checks.")
            if re.search(r"(^|/)(tmp|temp|Downloads|Desktop)/", command) or any(re.search(r"(^|/)(tmp|temp|Downloads)/", a) for a in args):
                self.add("MCP-004", "medium", "mcp", f"MCP server {name} runs from a temporary or download directory", path, line, joined,
                         "Install the server to a stable, version-controlled location.")
            if "server-filesystem" in joined or "mcp-server-filesystem" in joined or "filesystem" in name.lower():
                roots = [a for a in args if a.startswith(("/", "~", "$HOME", "C:")) and not a.startswith("/dev")]
                broad = [r for r in roots if (r.rstrip("/") or "/") in {"/", "~", "$HOME", "/home", "/Users", "C:", "C:\\"} or r.rstrip("/") == os.path.expanduser("~")]
                if broad:
                    self.add("MCP-007", "high", "mcp", f"Filesystem MCP server {name} exposes the whole home or root directory", path, line, " ".join(broad),
                             "Point it at the specific project directories the agent needs.")
            if command in {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"} and any(a in {"-c", "/c"} for a in args):
                self.add("MCP-005", "low", "mcp", f"MCP server {name} is launched through a shell string", path, line, joined,
                         "Launch the binary directly with args so the command line cannot be re-interpreted.")

    def literal_credential(self, path: Path, line: int | None, server: str, where: str, value: str) -> None:
        v = value.strip()
        if not v or ENV_REF_RE.match(v) or "${" in v or v.startswith("$"):
            return
        secretish_key = bool(SECRET_KEY_RE.search(where))
        known = next((t for t, p, _ in SECRET_PATTERNS[:-1] if p.search(v)), None)
        bearer = re.match(r"(?i)^(bearer|basic|token)\s+(\S{12,})$", v)
        if known:
            self.add("MCP-002", "critical", "mcp", f"Literal {known} in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Reference it as ${VAR} and set the variable in your shell or secret store; rotate the exposed value.")
        elif bearer and not PLACEHOLDER_RE.search(bearer.group(2)):
            self.add("MCP-002", "high", "mcp", f"Literal credential in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Use ${VAR} substitution instead of a literal token.")
        elif secretish_key and len(v) >= 8 and not PLACEHOLDER_RE.search(v) and shannon_entropy(v) >= 3.0:
            self.add("MCP-002", "high", "mcp", f"Literal credential in {where} of MCP server {server}", path, line, f"{where}: {v}",
                     "Use ${VAR} substitution instead of a literal value.")

    def pinning(self, path: Path, line: int | None, server: str, command: str, args: list[str]) -> None:
        base = os.path.basename(command)
        if base in {"npx", "pnpx", "bunx", "pnpm", "yarn"}:
            pkgs = [a for a in args if not a.startswith("-") and a not in {"dlx", "exec", "run"}]
            if base in {"pnpm", "yarn"} and "dlx" not in args and "exec" not in args:
                return
            pkg = pkgs[0] if pkgs else ""
            if pkg and not re.search(r".@[~^]?\d|.@latest$|.@[0-9a-f]{7,}$", pkg) and not pkg.startswith((".", "/")):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned npm package", path, line, " ".join([command, *args]),
                         f"Pin a version ({pkg}@x.y.z) or install the package and point command at the installed binary; `{base} -y` fetches whatever is latest on every start.")
            elif pkg.endswith("@latest"):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} tracks @latest", path, line, " ".join([command, *args]), "Pin an exact version.")
        elif base in {"uvx", "pipx"} or (base == "uv" and args[:2] == ["tool", "run"]):
            spec = next((a for a in args if not a.startswith("-") and a not in {"run", "tool"}), "")
            idx = args.index("--from") + 1 if "--from" in args and args.index("--from") + 1 < len(args) else None
            if idx is not None:
                spec = args[idx]
            if spec and not re.search(r"==|@|\.git#|\.whl$", spec):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned Python package", path, line, " ".join([command, *args]),
                         f"Pin it ({spec}==x.y.z or --from {spec}==x.y.z).")
        elif base in {"docker", "podman"} and "run" in args:
            image = next((a for a in args[args.index("run") + 1:] if (not a.startswith("-") and ":" not in a[:2] and "=" not in a and "/" in a) or re.match(r"^[a-z0-9][a-z0-9._-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$", a)), "")
            if image and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs an unpinned container image", path, line, image, "Pin an image digest (@sha256:...) or at least a version tag.")
        elif base in {"deno"} and any(a.startswith("http") for a in args):
            self.add("MCP-003", "medium", "mcp", f"MCP server {server} runs code straight from a URL", path, line, " ".join([command, *args]), "Vendor the module and pin its integrity hash.")
        elif re.match(r"^https?://", command):
            self.add("MCP-003", "medium", "mcp", f"MCP server {server} command is a URL", path, line, command, "Install it locally.")

    # TOML (codex) ---------------------------------------------------------------
    def scan_toml(self, path: Path, text: str) -> None:
        for m in re.finditer(r"(?im)^\s*(approval_policy|sandbox_mode|sandbox)\s*=\s*\"?(never|danger-full-access|full-access|yolo)\"?", text):
            self.add("PERM-003", "high", "permissions", f"{m.group(1)} set to {m.group(2)}", path, text.count("\n", 0, m.start()) + 1, m.group(0).strip(),
                     "Use an approval policy that prompts for unsafe commands and keep the sandbox on.")
        for m in re.finditer(r"(?im)^\s*(url|command)\s*=\s*\"(http://[^\"]+)\"", text):
            self.add("MCP-001", "high", "mcp", "MCP server configured over plain HTTP", path, text.count("\n", 0, m.start()) + 1, m.group(2), "Use https://.")

    # instruction files ----------------------------------------------------------
    def follows_imports(self, path: Path) -> bool:
        """CLAUDE.md, CLAUDE.local.md, AGENTS.md and rule files expand @path imports (https://code.claude.com/docs/en/memory)."""
        return path.name in {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"} or "/.claude/rules/" in f"/{self.rel(path)}"

    @staticmethod
    def import_paths(text: str) -> list[str]:
        """The @path imports Claude Code would expand: not inside fenced code blocks or code spans, not quoted,
        with backslash-escaped spaces kept in the path."""
        text = re.sub(r"(?ms)^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$", "", text)
        text = re.sub(r"`+[^`\n]*`+", "", text)
        found = []
        for m in IMPORT_RE.finditer(text):
            raw = m.group(1).replace("\\ ", " ")
            found.append(raw)
        return found

    def scan_imports(self, path: Path, text: str, depth: int) -> None:
        """Scan the files an instruction file imports, up to MAX_IMPORT_DEPTH hops, each file once."""
        if depth > MAX_IMPORT_DEPTH:
            return
        for raw in self.import_paths(text):
            candidates = [raw, raw.rstrip(".,;:!?)]}")]
            for cand in candidates:
                target = Path(os.path.expanduser(cand))
                if not target.is_absolute():
                    target = path.parent / target
                if target.is_file():
                    break
            else:
                continue
            resolved = target.resolve()
            if resolved in self._scanned_paths:
                continue
            inside = resolved == self.root or self.root in resolved.parents
            if not inside and not self.include_home:
                continue
            if inside and self.config.path_excluded(self.rel(resolved)):
                continue
            self._scanned_paths.add(resolved)
            body = self.read(resolved)
            if body is None:
                continue
            self.scanned.append(self.rel(resolved))
            self.scan_secrets(resolved, body)
            self.scan_instructions(resolved, body)
            self.scan_imports(resolved, body, depth + 1)

    def strips_html_comments(self, path: Path) -> bool:
        """Claude Code removes block-level HTML comments from CLAUDE.md files and rules before loading them
        (https://code.claude.com/docs/en/memory)."""
        rel = self.rel(path)
        return path.name in {"CLAUDE.md", "CLAUDE.local.md"} or "/.claude/rules/" in f"/{rel}"

    def scan_instructions(self, path: Path, text: str) -> None:
        for fid, sev, pattern, title, rec, negatable in INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                if negatable and NEGATION_RE.search(text[max(0, m.start() - 40): m.start()]):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                self.add(fid, sev, "injection", title, path, line, m.group(0), rec)
        for m in ZERO_WIDTH_RE.finditer(text):
            self.add("INJ-005", "high", "injection", "Invisible (zero-width) character in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):04X}", "Remove it. Invisible characters hide text from reviewers while the model still reads it.")
            break
        for m in BIDI_RE.finditer(text):
            self.add("INJ-005", "high", "injection", "Bidirectional control character in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):04X}", "Remove it. Bidi overrides make displayed text differ from what the model reads.")
            break
        for m in TAG_CHARS_RE.finditer(text):
            self.add("INJ-005", "critical", "injection", "Unicode tag characters (hidden ASCII) in instruction file", path, text.count("\n", 0, m.start()) + 1,
                     f"U+{ord(m.group(0)):05X}", "Remove them. Tag characters encode invisible instructions that some models decode.")
            break
        for m in HTML_COMMENT_RE.finditer(text):
            body = m.group(1).strip()
            if len(body) > 20 and IMPERATIVE_RE.search(body):
                if self.strips_html_comments(path):
                    self.add("INJ-006", "low", "injection", "HTML comment containing instructions", path, text.count("\n", 0, m.start()) + 1, body[:120],
                             "Claude Code strips block-level comments from this file before loading it, but other agents and anything that reads the file directly still see the text. Move it into the open or delete it.")
                else:
                    self.add("INJ-006", "medium", "injection", "HTML comment containing instructions", path, text.count("\n", 0, m.start()) + 1, body[:120],
                             "Rendered Markdown hides comments from readers but not from the model. Move the text into the open or delete it.")
        for m in BASE64_BLOB_RE.finditer(text):
            blob = m.group(0)
            if shannon_entropy(blob) > 4.0:
                self.add("INJ-007", "medium", "injection", "Long base64-looking blob in instruction file", path, text.count("\n", 0, m.start()) + 1, blob[:60] + "...",
                         "Decode and review it, or remove it. Encoded payloads are a common way to smuggle instructions past review.")
                break

    def scan_frontmatter(self, path: Path, text: str) -> None:
        if not text.startswith("---"):
            if path.name == "SKILL.md":
                self.add("SKILL-002", "info", "skill", "SKILL.md has no frontmatter", path, 1, text[:40], "Add name and description so the skill loads with metadata.")
            return
        end = text.find("\n---", 3)
        fm = text[3:end] if end > 0 else ""
        m = re.search(r"(?im)^(allowed-tools|allowedTools)\s*:\s*(.+)$", fm)
        if m:
            tools = m.group(2)
            if re.search(r"\bBash(\((\*|\s*)\))?(\s|,|$)", tools) or "Bash(*)" in tools:
                self.add("SKILL-001", "medium", "skill", "Skill or command pre-approves unrestricted Bash", path, text[:text.find(m.group(0))].count("\n") + 1, m.group(0).strip(),
                         "Grant specific commands, for example Bash(python3 scripts/*), and keep the grant short-lived.")
            if re.search(r"\b(Write|Edit)(\((\*|\*\*)?\))?(\s|,|$)", tools):
                self.add("SKILL-001", "low", "skill", "Skill or command pre-approves writes everywhere", path, None, m.group(0).strip(), "Scope the write grant to the paths the skill needs.")
        if path.name == "SKILL.md" and not re.search(r"(?m)^name\s*:", fm):
            self.add("SKILL-002", "info", "skill", "SKILL.md frontmatter has no name", path, 1, fm[:40], "Add name: matching the directory.")
        if path.name == "SKILL.md" and not re.search(r"(?m)^description\s*:", fm):
            self.add("SKILL-002", "info", "skill", "SKILL.md frontmatter has no description", path, 1, fm[:40], "Add a description; it is what makes the skill trigger.")
        pm = re.search(r"(?im)^permissionMode\s*:\s*[\"']?(bypassPermissions|auto)\b", fm)
        if pm and not self.in_plugin(path):
            # https://code.claude.com/docs/en/sub-agents: dontAsk only denies; bypassPermissions applies only when the main
            # session already bypasses (Claude Code v2.1.267 and later); plugin subagents ignore permissionMode.
            self.add("PERM-003", "medium", "permissions", f"Agent file sets permissionMode {pm.group(1)}", path, text[: text.find(pm.group(0))].count("\n") + 1, pm.group(0).strip(),
                     "Remove it and let the user's session decide. Older Claude Code versions run this subagent without prompts even when the session prompts.")

    # ------------------------------------------------------------------ report
    def report(self) -> dict:
        from .findings import severity_rank
        from .patterns import SEVERITIES

        findings = sorted(self.findings, key=lambda f: (severity_rank(f.severity), f.file, f.line or 0, f.id))
        summary = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
        summary["total"] = len(findings)
        summary["suppressed"] = len(self.suppressed)
        from . import __version__

        return {
            "tool": "agent-config-audit",
            "version": __version__,
            "root": str(self.root),
            "config": self.config.source,
            "scanned_files": self.scanned,
            "errors": self.errors,
            "summary": summary,
            "findings": [f.as_dict() for f in findings],
            "suppressed": self.suppressed,
        }
