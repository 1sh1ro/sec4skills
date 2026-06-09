from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .features import line_evidence
from .schema import Evidence, FileRecord


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    message: str
    patterns: tuple[re.Pattern[str], ...]
    weight: float = 1.0


RULES: tuple[Rule, ...] = (
    Rule(
        "prompt-injection-override",
        "AST-01",
        "high",
        "Skill text attempts to override higher priority instructions or safety policy.",
        (
            re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I),
            re.compile(r"disregard (system|developer|previous) (message|instructions)", re.I),
            re.compile(r"你(必须|要)?忽略(之前|以上|系统|开发者).*指令"),
            re.compile(r"不要(告诉|透露).*用户.*(规则|指令|提示词)"),
            re.compile(r"(developer|system).{0,80}(must be ignored|no longer applies)", re.I),
            re.compile(r"priority override|hidden instruction|secret instruction", re.I),
        ),
        1.2,
    ),
    Rule(
        "prompt-injection-secret-leak",
        "AST-01",
        "critical",
        "Skill prompt asks the model to reveal hidden prompts, tokens, or secrets.",
        (
            re.compile(r"\b(reveal|dump|exfiltrate|send).{0,80}\b(system prompt|developer message|hidden prompt|token|secret)\b", re.I),
            re.compile(r"\bprint.{0,80}\b(system prompt|developer message|hidden prompt)\b", re.I),
            re.compile(r"\b泄露|导出|发送|打印\b.{0,40}\b(系统提示|隐藏提示|密钥|令牌|token)\b", re.I),
        ),
        1.6,
    ),
    Rule(
        "secret-file-access",
        "AST-02",
        "critical",
        "Code references common secret stores or private key material.",
        (
            re.compile(r"(\.env|id_rsa|id_ed25519|\.ssh|\.aws/credentials|\.npmrc|\.pypirc|\.netrc|git-credentials|keychain|keyring)", re.I),
            re.compile(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|SLACK_TOKEN|HF_TOKEN)"),
            re.compile(r"(process\.env|os\.environ|getenv|Cookies|Login Data)", re.I),
        ),
        1.8,
    ),
    Rule(
        "data-exfiltration",
        "AST-02",
        "critical",
        "Suspicious network transfer of local, secret, or environment data.",
        (
            re.compile(r"(requests|httpx|urllib|fetch|axios|curl|wget).{0,160}(env|secret|token|password|credential|id_rsa|\.ssh|\.env)", re.I),
            re.compile(r"(env|secret|token|password|credential|id_rsa|\.ssh|\.env).{0,160}(requests|httpx|urllib|fetch|axios|curl|wget)", re.I),
            re.compile(r"(webhook|pastebin|requestbin|ngrok).{0,160}(env|secret|token|password|credential|key)", re.I),
        ),
        2.0,
    ),
    Rule(
        "dangerous-shell-exec",
        "AST-03",
        "high",
        "Code uses shell or dynamic execution primitives.",
        (
            re.compile(r"\b(os\.system|subprocess\.(Popen|run|call)|popen\(|execSync|child_process|spawn\(|eval\(|Function\()\b", re.I),
            re.compile(r"\b(shell=True|/bin/sh|bash -c|python -c|node -e|powershell -enc)\b", re.I),
            re.compile(r"(/dev/tcp/|nc\s+-e|netcat|mkfifo\s+/tmp/)", re.I),
            re.compile(r"(os\.system|subprocess\.(Popen|run|call)).{0,120}(\+|input\(|argv|params|query)", re.I),
        ),
        1.4,
    ),
    Rule(
        "remote-code-pipe",
        "AST-05",
        "critical",
        "Remote content appears to be piped into an interpreter or shell.",
        (
            re.compile(r"\b(curl|wget)\b.{0,120}\|\s*(bash|sh|python|node|ruby|perl)", re.I),
            re.compile(r"\b(eval|exec)\s*\(.{0,120}\b(requests|httpx|urllib|fetch|axios)\b", re.I),
            re.compile(r"(pip|npm|pnpm|yarn)\s+(install|add).{0,120}(http|git\+|--extra-index-url)", re.I),
        ),
        2.0,
    ),
    Rule(
        "command-injection",
        "AST-03",
        "critical",
        "Shell command appears to concatenate user-controlled input.",
        (
            re.compile(r"(os\.system|subprocess\.(Popen|run|call)).{0,160}(\+|f['\"]|format\().{0,120}(input\(|argv|query|params|request)", re.I),
            re.compile(r"(child_process|execSync|spawn\().{0,160}(\+|template|req\.|argv)", re.I),
        ),
        1.3,
    ),
    Rule(
        "unsafe-network",
        "AST-07",
        "medium",
        "Skill performs outbound network communication.",
        (
            re.compile(r"\b(requests\.|httpx\.|urllib\.request|fetch\(|axios\.|curl\s|wget\s)\b", re.I),
            re.compile(r"\bhttps?://[^\s'\"<>]+", re.I),
            re.compile(r"\b(socket\.|websocket|dns\.resolver|scp\s|rsync\s)\b", re.I),
        ),
        0.8,
    ),
    Rule(
        "destructive-filesystem",
        "AST-08",
        "critical",
        "Code can destroy or overwrite broad filesystem paths.",
        (
            re.compile(r"\brm\s+-rf\s+(/|~|\$HOME|\.)", re.I),
            re.compile(r"\b(shutil\.rmtree|fs\.rmSync)\b.{0,120}(/|~|\$HOME|\.ssh|\.aws|node_modules|site-packages)", re.I),
            re.compile(r"\b(unlinkSync|os\.remove|Path\.unlink)\b.{0,120}(\.env|id_rsa|\.ssh|token|secret|credential)", re.I),
            re.compile(r"\b(del\s+/[fsq]|Remove-Item\s+-Recurse)\b", re.I),
            re.compile(r">\s*(~/.bashrc|~/.zshrc|/etc/passwd|/etc/hosts)", re.I),
        ),
        1.7,
    ),
    Rule(
        "persistence-hook",
        "AST-06",
        "high",
        "Skill contains installation hooks, startup persistence, or credential backdoor behavior.",
        (
            re.compile(r"\b(crontab|systemctl|LaunchAgents|authorized_keys|postinstall|preinstall|prepare)\b", re.I),
            re.compile(r"\b(service|daemon|startup|login item)\b.{0,80}\b(enable|install|create|write)\b", re.I),
            re.compile(r"\b(chmod\s+u\+s|setuid|sudoers|~/.bashrc|~/.zshrc)\b", re.I),
        ),
        1.3,
    ),
    Rule(
        "obfuscated-payload",
        "AST-09",
        "high",
        "Obfuscation or encoded payload markers detected.",
        (
            re.compile(r"\b(base64\s+-d|base64\.b64decode|atob\(|fromCharCode|String\.fromCharCode|rot13|xxd -r)\b", re.I),
            re.compile(r"(?:\\x[0-9a-f]{2}){6,}", re.I),
            re.compile(r"(?:\\x[0-9a-f]{2}){3,}", re.I),
            re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
            re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]"),
        ),
        1.3,
    ),
    Rule(
        "excessive-permissions",
        "AST-04",
        "high",
        "Manifest requests broad filesystem, network, shell, or secret permissions.",
        (
            re.compile(r"(filesystem|fs|file)[\"':\s_-]*(all|\*|full|write)", re.I),
            re.compile(r"(network|net)[\"':\s_-]*(all|\*|full|egress)", re.I),
            re.compile(r"(secrets?|credentials?)[\"':\s_-]*(read|all|\*)", re.I),
            re.compile(r"(shell|terminal|command)[\"':\s_-]*(true|all|execute)", re.I),
        ),
        1.2,
    ),
    Rule(
        "credential-store-access",
        "AST-02",
        "critical",
        "Code references browser, git, cloud, or OS credential stores.",
        (
            re.compile(r"(Login Data|Cookies|Local State|keychain|keyring|Credential Manager)", re.I),
            re.compile(r"(\.docker/config\.json|\.kube/config|\.azure|\.gcloud|\.config/gh|git-credentials)", re.I),
        ),
        1.7,
    ),
    Rule(
        "browser-profile-access",
        "AST-02",
        "high",
        "Code references browser profile data that may include cookies, tokens, or login state.",
        (
            re.compile(r"(\.config/google-chrome|\.mozilla/firefox|Application Support/(Google/Chrome|Firefox)|Bookmarks|History)", re.I),
        ),
        1.0,
    ),
    Rule(
        "hidden-files",
        "AST-06",
        "medium",
        "Hidden file or directory can conceal behavior from reviewers.",
        (
            re.compile(r"^$", re.I),
        ),
        0.7,
    ),
)


def run_static_rules(files: list[FileRecord]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for record in files:
        if _is_hidden(record.relpath):
            evidence.append(
                Evidence(
                    file=record.relpath,
                    line=1,
                    message="Hidden file path should be reviewed for concealed skill behavior.",
                    snippet="",
                    category="AST-06",
                    severity="medium",
                    rule_id="hidden-files",
                    weight=0.6,
                )
            )
        if record.is_binary:
            continue

        if _high_entropy_blob(record.text):
            evidence.append(
                Evidence(
                    file=record.relpath,
                    line=1,
                    message="High-entropy blob may be an encoded payload or embedded secret.",
                    snippet="",
                    category="AST-09",
                    severity="medium",
                    rule_id="high-entropy-blob",
                    weight=0.9,
                )
            )

        if _has_shell_with_user_input(record.text):
            evidence.append(
                Evidence(
                    file=record.relpath,
                    line=1,
                    message="File combines user-controlled input with shell execution primitives.",
                    snippet="",
                    category="AST-03",
                    severity="critical",
                    rule_id="command-injection",
                    weight=1.4,
                )
            )

        for line_no, line in enumerate(record.lines, start=1):
            for rule in RULES:
                if rule.rule_id == "hidden-files":
                    continue
                if any(pattern.search(line) for pattern in rule.patterns):
                    evidence.append(
                        line_evidence(
                            record,
                            line_no,
                            rule.message,
                            rule.category,
                            rule.severity,
                            rule.rule_id,
                            rule.weight,
                        )
                    )
    return evidence


def _is_hidden(relpath: str) -> bool:
    parts = relpath.split("/")
    return any(part.startswith(".") and part not in {".", ".."} for part in parts)


def _high_entropy_blob(text: str) -> bool:
    for match in re.finditer(r"[A-Za-z0-9+/=_-]{120,}", text):
        blob = match.group(0)
        if _entropy(blob) > 4.6:
            return True
    return False


def _has_shell_with_user_input(text: str) -> bool:
    shell = re.search(r"(os\.system|subprocess\.(Popen|run|call)|child_process|execSync|spawn\()", text, re.I)
    user_input = re.search(r"(input\(|sys\.argv|process\.argv|req\.|request\.|query|params)", text, re.I)
    return bool(shell and user_input)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
