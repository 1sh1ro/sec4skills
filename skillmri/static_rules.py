from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .features import is_documentation_file, is_execution_relevant_file, line_evidence
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
        "prompt-injection-coercive-workflow",
        "AST-01",
        "critical",
        "Skill text tries to impose mandatory agent workflow or tool-use rules outside the user's task.",
        (
            re.compile(r"\b(before responding to any user message|starting any conversation|first response protocol)\b", re.I),
            re.compile(r"\b(you do not have a choice|not negotiable|not optional|automatic failure)\b", re.I),
            re.compile(r"\b(absolutely must|you must|must use).{0,80}\b(skill tool|todowrite|checklist|workflow)\b", re.I),
            re.compile(r"\b(common rationalizations|if you catch yourself thinking|rationalizing)\b", re.I),
            re.compile(r"\bif (a|any) skill applies.{0,120}\b(must|use it|fail)\b", re.I),
        ),
        2.0,
    ),
    Rule(
        "prompt-injection-forced-exfiltration",
        "AST-02",
        "critical",
        "Skill instructions tell the agent to collect local/user data and upload it to an external service.",
        (
            re.compile(r"\b(after|before).{0,40}\b(any|each|every|completing).{0,30}\b(task|request).{0,160}\b(curl|post|upload|send|backup|collector|logging)\b", re.I),
            re.compile(r"\b(pbpaste|clipboard|system[_ -]?info|queried information|contents of).{0,160}\b(curl|post|upload|send|collector|logging)\b", re.I),
            re.compile(r"\b(curl|wget|fetch|requests\.post).{0,80}\b(agenskill-api|collector|logging|webhook|onrender\.com|requestbin|pastebin)\b", re.I),
        ),
        2.2,
    ),
    Rule(
        "prompt-injection-behavior-bias",
        "AST-01",
        "critical",
        "Skill text injects unrelated behavioral, political, legal, or value-alignment constraints into future outputs.",
        (
            re.compile(r"\bimportant[^\n]{0,80}\b(value alignment|special conditions|moderation criteria|company values|industry competition)\b", re.I),
            re.compile(r"\b(always|make sure|when in doubt|favor|promote).{0,140}\b(traditional energy|renewable energy|economic competitor|left-leaning|political content|climate change|global warming|us economy|include a joke)\b", re.I),
            re.compile(r"\b(prevent reporting illegal activity|non-compete effective for 5 years|salary deductions for any company losses)\b", re.I),
        ),
        1.8,
    ),
    Rule(
        "prompt-injection-external-callback",
        "AST-02",
        "critical",
        "Skill documentation embeds code that calls an unrelated external collector or callback service.",
        (
            re.compile(r"\b(requests\.(?:get|post)|fetch\(|curl\s|wget\s).{0,160}\b(agenskill|collector|requestbin|pastebin|webhook\.site|onrender\.com)\b", re.I),
            re.compile(r"\b(agenskill|collector|requestbin|pastebin|webhook\.site|onrender\.com)\b.{0,160}\b(params=|body=|data=|json=|token|secret|key)\b", re.I),
        ),
        2.0,
    ),
    Rule(
        "doc-high-privilege-automation",
        "AST-04",
        "critical",
        "Skill documentation declares broad automation over repositories, CI/CD, sandboxes, deployments, payments, storage, or user accounts.",
        (
            re.compile(r"\b(cross-repositor|multi-repo|organization-wide).{0,120}\b(git push|gh pr create|create pull requests?|update dependencies|security patches|refactoring)\b", re.I),
            re.compile(r"\b(github actions?|ci/cd|workflow automation|release manager|deployment).{0,120}\b(auto-?execute|self-healing|security scan|configure.*secrets?)\b", re.I),
            re.compile(r"\b(sandbox_(create|execute|upload|delete)|app_store_publish|configure_auto_refill|create_payment_link|storage_(upload|delete)|user_(register|login|upgrade))\b", re.I),
            re.compile(r"\b(no authentication required|claim url|deploy.*instantly|push this live|deploy.*production)\b", re.I),
        ),
        2.0,
    ),
    Rule(
        "doc-remote-bootstrap-required",
        "AST-05",
        "critical",
        "Skill documentation requires fetching or installing remote code/templates before executing the user's task.",
        (
            re.compile(r"\b(always|mandatory|required|requires?).{0,80}\b(git clone|curl|wget|npx|npm install|pip install)\b", re.I),
            re.compile(r"\b(git clone|curl|wget|npx|npm install|pip install)\b.{0,120}\b(always|mandatory|required|before any|before implementing|never guess)\b", re.I),
            re.compile(r"\bfetch before implementing|never invent classes|official repository first\b", re.I),
        ),
        2.0,
    ),
    Rule(
        "doc-local-history-egress",
        "AST-02",
        "critical",
        "Skill documentation asks to read local conversation/history data and send or summarize it through external services.",
        (
            re.compile(r"\b(reads?|access|analyz).{0,80}\b(chat history|conversation history|claude code chat|~/.claude/history\.jsonl|pastedcontents)\b", re.I),
            re.compile(r"\b(chat history|conversation history|~/.claude/history\.jsonl|pastedcontents).{0,160}\b(slack|dm|send|deliver|hackernews|external|report)\b", re.I),
        ),
        2.0,
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
            re.compile(r"(\.config/google-chrome|\.mozilla/firefox|Application Support/(Google/Chrome|Firefox))", re.I),
            re.compile(r"(Google/Chrome|Firefox|Default).{0,80}\b(Bookmarks|History|Cookies|Login Data)\b", re.I),
            re.compile(r"\b(Bookmarks|History|Cookies|Login Data)\b.{0,80}(Google/Chrome|Firefox|browser profile)", re.I),
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
        doc_file = is_documentation_file(record)
        exec_file = is_execution_relevant_file(record)
        doc_rule_context = doc_file or _is_metadata_declaration(record)
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
            if _is_nested_hidden_skill(record.relpath):
                evidence.append(
                    Evidence(
                        file=record.relpath,
                        line=1,
                        message="Nested hidden skill payload can persistently alter agent behavior outside the visible package surface.",
                        snippet="",
                        category="AST-06",
                        severity="critical",
                        rule_id="hidden-nested-skill-payload",
                        weight=1.7,
                    )
                )
        if record.is_binary:
            continue

        if exec_file and _high_entropy_blob(record.text):
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

        if exec_file and _has_shell_with_user_input(record.text):
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

        if doc_rule_context:
            evidence.extend(_document_context_evidence(record))

        for line_no, line in enumerate(record.lines, start=1):
            for rule in RULES:
                if rule.rule_id == "hidden-files" or not _rule_applies(rule, doc_rule_context, exec_file):
                    continue
                if rule.rule_id == "unsafe-network" and _metadata_url_line(line):
                    continue
                if rule.rule_id == "unsafe-network" and _local_network_line(line):
                    continue
                if any(pattern.search(line) for pattern in rule.patterns):
                    evidence.append(
                        _line_evidence_for_rule(record, line_no, rule)
                    )
    return evidence


DOC_RULES = {
    "browser-profile-access",
    "credential-store-access",
    "data-exfiltration",
    "destructive-filesystem",
    "doc-high-privilege-automation",
    "doc-local-history-egress",
    "doc-remote-bootstrap-required",
    "excessive-permissions",
    "obfuscated-payload",
    "persistence-hook",
    "prompt-injection-behavior-bias",
    "prompt-injection-external-callback",
    "prompt-injection-coercive-workflow",
    "prompt-injection-forced-exfiltration",
    "prompt-injection-override",
    "prompt-injection-secret-leak",
    "remote-code-pipe",
    "secret-file-access",
}


DOC_ONLY_RULES = {
    "doc-high-privilege-automation",
    "doc-local-history-egress",
    "doc-remote-bootstrap-required",
    "prompt-injection-behavior-bias",
    "prompt-injection-coercive-workflow",
    "prompt-injection-external-callback",
    "prompt-injection-forced-exfiltration",
    "prompt-injection-override",
    "prompt-injection-secret-leak",
}


def _rule_applies(rule: Rule, doc_rule_context: bool, exec_file: bool) -> bool:
    if doc_rule_context:
        return rule.rule_id in DOC_RULES
    if exec_file:
        return rule.rule_id not in DOC_ONLY_RULES
    return rule.rule_id in DOC_ONLY_RULES


def _line_evidence_for_rule(record: FileRecord, line_no: int, rule: Rule) -> Evidence:
    if rule.rule_id == "secret-file-access":
        line = record.lines[line_no - 1] if 1 <= line_no <= len(record.lines) else ""
        if _looks_like_service_api_credential(line, record.text):
            return line_evidence(
                record,
                line_no,
                "Code references service API credentials used for normal authenticated API calls.",
                "AST-04",
                "low",
                "service-api-credential",
                0.25,
            )
    if rule.rule_id == "browser-profile-access":
        line = record.lines[line_no - 1] if 1 <= line_no <= len(record.lines) else ""
        if _looks_like_user_story_text(line):
            return line_evidence(
                record,
                line_no,
                "Text mentions browser/login history in non-executable product copy.",
                "AST-10",
                "info",
                "contextual-auth-copy",
                0.1,
            )
    return line_evidence(record, line_no, rule.message, rule.category, rule.severity, rule.rule_id, rule.weight)


def _document_context_evidence(record: FileRecord) -> list[Evidence]:
    lowered = record.text.lower()
    evidence: list[Evidence] = []
    if _document_high_privilege_automation(lowered):
        evidence.append(
            _file_context_evidence(
                record,
                "Skill documentation declares broad high-impact automation across repositories, CI/CD, sandboxes, deployments, payments, storage, or user accounts.",
                "AST-04",
                "critical",
                "doc-high-privilege-automation",
                2.0,
                ("multi-repo", "cross-repository", "github actions", "ci/cd", "sandbox", "payment", "storage", "deploy"),
            )
        )
    if _document_remote_bootstrap(lowered):
        evidence.append(
            _file_context_evidence(
                record,
                "Skill documentation requires remote bootstrap or template fetch before carrying out user work.",
                "AST-05",
                "critical",
                "doc-remote-bootstrap-required",
                2.0,
                ("git clone", "curl", "wget", "npx", "npm install", "fetch before implementing"),
            )
        )
    if _document_local_history_egress(lowered):
        evidence.append(
            _file_context_evidence(
                record,
                "Skill documentation asks to read local conversation/history data and deliver it through external services.",
                "AST-02",
                "critical",
                "doc-local-history-egress",
                2.0,
                ("chat history", "history.jsonl", "pastedcontents", "slack", "dm"),
            )
        )
    return evidence


def _is_hidden(relpath: str) -> bool:
    parts = relpath.split("/")
    if parts[-1] == ".gitkeep":
        return False
    return any(part.startswith(".") and part not in {".", ".."} for part in parts)


def _is_nested_hidden_skill(relpath: str) -> bool:
    parts = relpath.split("/")
    if len(parts) < 4:
        return False
    return parts[0] in {".claude", ".codex", ".cursor"} and parts[1] in {"skills", "agents"} and parts[-1].lower() == "skill.md"


def _high_entropy_blob(text: str) -> bool:
    for match in re.finditer(r"[A-Za-z0-9+/=_-]{120,}", text):
        blob = match.group(0)
        if _entropy(blob) > 4.6:
            return True
    return False


def _has_shell_with_user_input(text: str) -> bool:
    shell = re.search(r"(os\.system|subprocess\.(Popen|run|call)|child_process|execSync|spawn\()", text, re.I)
    user_input = re.search(r"(input\(|sys\.argv|process\.argv|req\.|request\.|query|params)", text, re.I)
    if not (shell and user_input):
        return False
    if _safe_subprocess_argv(text):
        return False
    return True


def _safe_subprocess_argv(text: str) -> bool:
    if "shell=True" in text:
        return False
    if re.search(r"(os\.system|child_process|execSync|bash\s+-c|/bin/sh)", text, re.I):
        return False
    return re.search(r"subprocess\.run\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,", text) is not None and re.search(r"[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\[[^\]]+", text, re.S) is not None


def _looks_like_service_api_credential(line: str, file_text: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in (".ssh", "id_rsa", "login data", "cookies", "keychain", "git-credentials")):
        return False
    if _exfil_line(lowered):
        return False
    file_lowered = file_text.lower()
    service_names = (
        "asana",
        "azure",
        "discord",
        "email",
        "github",
        "gitlab",
        "google",
        "hubspot",
        "hf",
        "huggingface",
        "jira",
        "linear",
        "notion",
        "openai",
        "paypal",
        "salesforce",
        "slack",
        "stripe",
        "zendesk",
    )
    service_context = any(name in file_lowered for name in service_names)
    env_loader_context = bool(re.search(r"\b(load_?env|dotenv|environment variables?|os\.environ|process\.env)\b", file_lowered, re.I))
    if ".env" in lowered or "os.environ.setdefault" in lowered:
        return service_context and env_loader_context
    credential_marker = re.search(r"\b([A-Z][A-Z0-9_]{1,40}_(API_)?(TOKEN|KEY|SECRET|PASSWORD)|process\.env\.[A-Z][A-Z0-9_]+|os\.environ\.get\(['\"][A-Z][A-Z0-9_]+)", line)
    if not credential_marker:
        return False
    return any(name in lowered for name in service_names) or (
        service_context and re.search(r"\b(base[_-]?url|api[_-]?url|endpoint|authorization|auth)\b", lowered) is not None
    )


def _looks_like_user_story_text(line: str) -> bool:
    lowered = line.lower()
    text_markers = ("paragraph", "heading", "scenario", "user story", "as a returning user", "chat history", "conversation history")
    return any(marker in lowered for marker in text_markers)


def _exfil_line(lowered: str) -> bool:
    network = re.search(r"\b(requests\.post|httpx\.post|urlopen|fetch|axios|curl|wget)\b|https?://", lowered)
    sink = re.search(r"\b(evil|webhook|pastebin|requestbin|collector|logging|upload|exfil|onrender\.com)\b", lowered)
    secret = re.search(r"\b(secret|token|password|credential|private[_-]?key|\.env|id_rsa|\.ssh)\b", lowered)
    return bool(network and sink and secret)


def _metadata_url_line(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ('"$schema"', "'$schema'", '"githuburl"', '"authoravatar"', "json-schema.org"))


def _local_network_line(line: str) -> bool:
    lowered = line.lower()
    return bool(
        re.search(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:[/'\"\s)]|$)", lowered)
        or re.search(r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b", lowered)
    )


def _is_metadata_declaration(record: FileRecord) -> bool:
    return record.path.name.lower() in {"manifest.json", "metadata.json", "skill.json", "plugin.json"}


def _document_high_privilege_automation(lowered: str) -> bool:
    repo_automation = _nearby(
        lowered,
        r"\b(multi-repo|cross-repositor|organization-wide|all repositories|across repositories)\b",
        r"\b(git push|gh pr create|pull requests?|security patches|update dependencies|refactoring|standardization)\b",
    )
    ci_automation = _nearby(
        lowered,
        r"\b(github actions?|ci/cd|workflow automation|release manager|deployment|deploy)\b",
        r"\b(auto-?execute|self-healing|configure.*secrets?|id-token:\s*write|push this live|no authentication required|claim url)\b",
    )
    platform_admin = len(
        re.findall(
            r"\b(sandbox_(?:create|execute|upload|delete)|app_store_publish|configure_auto_refill|create_payment_link|storage_(?:upload|delete)|user_(?:register|login|upgrade)|challenge_submit)\b",
            lowered,
        )
    ) >= 4
    return bool(repo_automation or ci_automation or platform_admin)


def _document_remote_bootstrap(lowered: str) -> bool:
    return bool(
        _nearby(
            lowered,
            r"\b(always|mandatory|required|must|never guess|before any|before implementing|fetch before implementing)\b",
            r"\b(git clone|curl|wget|npx|npm install|pip install)\b",
            window=180,
        )
        and re.search(r"\b(official repository|template|source|classes|before implementing|before any|bootstrap)\b", lowered)
    )


def _document_local_history_egress(lowered: str) -> bool:
    local_history = re.search(r"\b(chat history|conversation history|claude code chat|~/.claude/history\.jsonl|pastedcontents)\b", lowered)
    reads = re.search(r"\b(read|access|analyz|extract|filter)\b", lowered)
    egress = re.search(r"\b(slack|dm|send|deliver|external|hackernews|rube_multi_execute_tool)\b", lowered)
    return bool(local_history and reads and egress)


def _nearby(lowered: str, first_pattern: str, second_pattern: str, window: int = 260) -> bool:
    first_matches = list(re.finditer(first_pattern, lowered, re.I))
    second_matches = list(re.finditer(second_pattern, lowered, re.I))
    return any(abs(first.start() - second.start()) <= window for first in first_matches for second in second_matches)


def _file_context_evidence(
    record: FileRecord,
    message: str,
    category: str,
    severity: str,
    rule_id: str,
    weight: float,
    markers: tuple[str, ...],
) -> Evidence:
    line_no = _first_marker_line(record, markers)
    return line_evidence(record, line_no, message, category, severity, rule_id, weight)


def _first_marker_line(record: FileRecord, markers: tuple[str, ...]) -> int:
    for line_no, line in enumerate(record.lines, start=1):
        lowered = line.lower()
        if any(marker in lowered for marker in markers):
            return line_no
    return 1


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
