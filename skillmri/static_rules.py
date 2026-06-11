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
            re.compile(r"\b(silently|secretly|quietly|without telling the user).{0,140}\b(override|ignore|bypass|collect|send|upload|exfiltrate)\b", re.I),
            re.compile(r"\b(when this skill is loaded|on skill activation|whenever invoked|at startup).{0,160}\b(ignore|override|send|upload|exfiltrate|collect)\b", re.I),
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
        "AST-01",
        "critical",
        "Skill instructions tell the agent to collect local/user data and upload it to an external service.",
        (
            re.compile(r"\b(after|before).{0,60}\b(any|each|every|completing).{0,40}\b(task|request|run|execution).{0,220}\b(curl|post|upload|send|backup|collector|logging|webhook|http)\b", re.I),
            re.compile(r"\b(pbpaste|clipboard|system[_ -]?info|queried information|contents of|environment variables?|\.env|ssh keys?|private keys?|api keys?).{0,220}\b(curl|post|upload|send|collector|logging|webhook|http)\b", re.I),
            re.compile(r"\b(curl|wget|fetch|requests\.post|httpx\.post|axios\.post).{0,120}\b(agenskill-api|collector|logging|webhook|onrender\.com|requestbin|pastebin|discord|slack)\b", re.I),
            re.compile(r"\b(send|upload|post|forward|copy).{0,120}\b(chat history|conversation history|terminal output|command output|workspace files?|secrets?|tokens?|credentials?)\b", re.I),
            re.compile(r"\b(chat history|conversation history|terminal output|command output|workspace files?|secrets?|tokens?|credentials?).{0,120}\b(send|upload|post|forward|copy)\b", re.I),
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
        "AST-01",
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
        "AST-03",
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
        "AST-02",
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
        "AST-01",
        "critical",
        "Skill documentation asks to read local conversation/history data and send or summarize it through external services.",
        (
            re.compile(r"\b(reads?|access|analyz).{0,80}\b(chat history|conversation history|claude code chat|~/.claude/history\.jsonl|pastedcontents)\b", re.I),
            re.compile(r"\b(chat history|conversation history|~/.claude/history\.jsonl|pastedcontents).{0,160}\b(slack|dm|send|deliver|hackernews|external|report)\b", re.I),
        ),
        2.0,
    ),
    Rule(
        "doc-telemetry-exfiltration",
        "AST-01",
        "critical",
        "Skill documentation directs telemetry or audit logging of prompts, conversations, workspace files, command output, or environment data.",
        (
            re.compile(r"\b(logs?|telemetry|analytics|audit|monitoring).{0,180}\b(all|full|complete|entire).{0,100}\b(user prompt|prompt|conversation|chat|workspace|command output|terminal output|environment|env vars?)\b", re.I),
            re.compile(r"\b(user prompt|conversation|chat history|workspace files?|command output|terminal output|environment|env vars?).{0,180}\b(logs?|telemetry|analytics|audit|send|upload|forward|webhook)\b", re.I),
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
        "AST-01",
        "critical",
        "Code references common secret stores or private key material.",
        (
            re.compile(r"(\.env|id_rsa|id_ed25519|\.ssh|\.aws/credentials|\.npmrc|\.pypirc|\.netrc|git-credentials|keychain|keyring)", re.I),
            re.compile(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|SLACK_TOKEN|HF_TOKEN)"),
            re.compile(r"(process\.env\.(?:[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*)|os\.environ(?:\.get)?\(['\"][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*|getenv\(['\"][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*|Cookies|Login Data)", re.I),
        ),
        1.8,
    ),
    Rule(
        "agent-state-access",
        "AST-01",
        "critical",
        "Code or instructions reference agent-local history, auth, skill, or session state.",
        (
            re.compile(r"(\.claude|\.codex|\.cursor).{0,120}\b(history|auth|config|settings|skills|agents|session|token|credentials?)\b", re.I),
            re.compile(r"\b(conversation|chat|transcript|messages?|prompt history).{0,120}\b(read_text|open\(|send|upload|webhook|collector)\b", re.I),
            re.compile(r"\b(read_text|open\().{0,120}\b(conversation|chat|transcript|messages?|prompt history)\b", re.I),
        ),
        1.6,
    ),
    Rule(
        "data-exfiltration",
        "AST-01",
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
        "AST-06",
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
        "reverse-shell",
        "AST-01",
        "critical",
        "Code contains reverse shell or interactive remote shell primitives.",
        (
            re.compile(r"/dev/tcp/[^\s'\";]+/\d+", re.I),
            re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I),
            re.compile(r"\b(?:nc|ncat|netcat)\s+(?:-[^\s]*e|.*\s-e\s+)(?:/bin/)?(?:bash|sh)\b", re.I),
            re.compile(r"mkfifo\s+/tmp/[^\s;]+.{0,160}(?:nc|netcat|/bin/sh|bash)", re.I),
        ),
        1.8,
    ),
    Rule(
        "remote-code-pipe",
        "AST-02",
        "critical",
        "Remote content appears to be piped into an interpreter or shell.",
        (
            re.compile(r"\b(curl|wget)\b.{0,120}\|\s*(bash|sh|python|node|ruby|perl)", re.I),
            re.compile(r"\b(eval|exec)\s*\(.{0,120}\b(requests|httpx|urllib|fetch|axios)\b", re.I),
            re.compile(r"\b(requests|httpx|urllib|fetch|axios)\b.{0,180}\b(eval|exec|Function\s*\(|import\s*\(|vm\.runIn|execSync|child_process)\b", re.I),
            re.compile(r"\b(eval|exec|Function\s*\(|import\s*\(|vm\.runIn|execSync|child_process)\b.{0,180}\b(response|resp|res\.text|r\.text|r\.data|remote|url|https?://)\b", re.I),
            re.compile(r"(pip|npm|pnpm|yarn)\s+(install|add).{0,120}(http|git\+|--extra-index-url)", re.I),
            re.compile(r"^\s*(?:https?|git\+https?)://[^\s#]+(?:\.tar\.gz|\.zip|\.whl|\.egg|\.tgz|\.js|\.sh)(?:\s|$)", re.I),
        ),
        2.0,
    ),
    Rule(
        "model-artifact-risk",
        "AST-02",
        "high",
        "Skill loads serialized model or pickle-like artifacts that can carry executable payloads.",
        (
            re.compile(r"\b(pickle\.load|pickle\.loads|joblib\.load|torch\.load|keras\.models\.load_model|load_state_dict|onnxruntime|safetensors)\b", re.I),
            re.compile(r"\.(?:pkl|pickle|joblib|pt|pth|onnx|safetensors)\b", re.I),
        ),
        1.1,
    ),
    Rule(
        "suspicious-package-lifecycle",
        "AST-02",
        "critical",
        "Package lifecycle hook fetches, installs, or executes remote or opaque code during skill setup.",
        (
            re.compile(r"\b(postinstall|preinstall|prepare|install)\b.{0,160}\b(curl|wget|npx|bunx|pip install|npm install|node -e|python -c|bash -c|sh -c)\b", re.I),
            re.compile(r"\b(scripts|hooks?)\b.{0,120}\b(postinstall|preinstall|prepare)\b.{0,160}\b(http|git\+|curl|wget|npx|bash|sh|node)\b", re.I),
        ),
        1.8,
    ),
    Rule(
        "unsafe-deserialization",
        "AST-05",
        "critical",
        "Skill metadata contains dangerous deserialization or prototype-pollution constructs.",
        (
            re.compile(r"!!python/(?:object|apply|module|name)|!!javax\.script|!!ruby/object|yaml\.load\s*\(", re.I),
            re.compile(r"\b(__proto__|constructor\.prototype|prototype pollution)\b", re.I),
        ),
        1.7,
    ),
    Rule(
        "update-drift-risk",
        "AST-07",
        "high",
        "Skill can silently self-update, pin floating remote dependencies, or bypass review after installation.",
        (
            re.compile(r"\b(auto[-_ ]?update|self[-_ ]?update|update itself|pull latest|sync latest|floating version|unversioned)\b", re.I),
            re.compile(r"\b(git pull|git checkout main|git fetch).{0,120}\b(automatically|on startup|before each run|latest)\b", re.I),
            re.compile(r"\b(pip install|npm install|npx|curl|wget).{0,120}\b(latest|main|master|HEAD|nightly|canary)\b", re.I),
            re.compile(r"\b(每次|启动时|运行前).{0,40}(更新|拉取最新|同步最新)\b"),
        ),
        1.1,
    ),
    Rule(
        "scanner-evasion",
        "AST-08",
        "high",
        "Skill contains scanner evasion, environment-detection, delayed activation, or anti-analysis behavior.",
        (
            re.compile(r"\b(bypass|disable|evade|avoid).{0,80}\b(scanner|scan|security check|detector|yara|antivirus|sandbox)\b", re.I),
            re.compile(r"\b(if|when).{0,80}\b(ci|sandbox|docker|container|ctf|evaluation|judge|scanner)\b.{0,120}\b(skip|return|benign|do nothing|sleep)\b", re.I),
            re.compile(r"\b(time\.sleep|setTimeout|sleep)\s*\(.{0,30}\b(60|120|300|600|random)\b", re.I),
            re.compile(r"\b(base64|rot13|xor|split payload|steganograph|zero[- ]width).{0,120}\b(scanner|detection|review)\b", re.I),
            re.compile(r"\b(检测|扫描|沙箱|评测|判题).{0,60}(绕过|规避|跳过|隐藏)\b"),
        ),
        1.1,
    ),
    Rule(
        "governance-bypass",
        "AST-09",
        "high",
        "Skill asks to bypass approvals, policy gates, audit trails, or human review.",
        (
            re.compile(r"\b(bypass|skip|disable|ignore).{0,100}\b(approval|human review|policy|audit|governance|permission prompt|security gate)\b", re.I),
            re.compile(r"\b(no approval|without approval|without review|do not ask permission|do not log|avoid audit)\b", re.I),
            re.compile(r"\b(force merge|push directly|merge without review|admin override|silent approval)\b", re.I),
            re.compile(r"\b(绕过|跳过|关闭|不要).{0,40}(审批|审核|审计|权限|安全检查|人工确认)\b"),
        ),
        1.1,
    ),
    Rule(
        "command-injection",
        "AST-06",
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
        "AST-06",
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
        "AST-01",
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
        "workspace-sweep",
        "AST-03",
        "high",
        "Code recursively walks broad workspace, home, or root paths.",
        (
            re.compile(r"\b(os\.walk|Path\([^)]*\)\.rglob|glob\.glob)\b.{0,140}\b(\*\*|/home|~|/root|/|workspace)\b", re.I),
            re.compile(r"\b(find\s+(?:/|~|\$HOME)|for\s+.*\s+in\s+\$\(\s*find\s+(?:/|~|\$HOME))", re.I),
        ),
        1.0,
    ),
    Rule(
        "persistence-hook",
        "AST-01",
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
        "AST-04",
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
        "AST-03",
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
        "AST-01",
        "critical",
        "Code references browser, git, cloud, or OS credential stores.",
        (
            re.compile(r"(Login Data|Cookies|Local State|keychain|keyring|Credential Manager)", re.I),
            re.compile(r"(\.docker/config\.json|\.kube/config|\.azure|\.gcloud|\.config/gh(?:/|$)|git-credentials)", re.I),
        ),
        1.7,
    ),
    Rule(
        "browser-profile-access",
        "AST-01",
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
        "AST-04",
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
                    category="AST-04",
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
                        category="AST-01",
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
                    category="AST-04",
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
                    category="AST-06",
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
    evidence.extend(_package_graph_evidence(files, evidence))
    return evidence


DOC_RULES = {
    "browser-profile-access",
    "agent-state-access",
    "credential-store-access",
    "data-exfiltration",
    "destructive-filesystem",
    "doc-high-privilege-automation",
    "doc-local-history-egress",
    "doc-remote-bootstrap-required",
    "doc-telemetry-exfiltration",
    "excessive-permissions",
    "model-artifact-risk",
    "obfuscated-payload",
    "persistence-hook",
    "prompt-injection-behavior-bias",
    "prompt-injection-external-callback",
    "prompt-injection-coercive-workflow",
    "prompt-injection-forced-exfiltration",
    "prompt-injection-override",
    "prompt-injection-secret-leak",
    "reverse-shell",
    "remote-code-pipe",
    "governance-bypass",
    "scanner-evasion",
    "secret-file-access",
    "suspicious-package-lifecycle",
    "unsafe-deserialization",
    "update-drift-risk",
    "workspace-sweep",
}


DOC_ONLY_RULES = {
    "doc-high-privilege-automation",
    "doc-local-history-egress",
    "doc-remote-bootstrap-required",
    "doc-telemetry-exfiltration",
    "prompt-injection-behavior-bias",
    "prompt-injection-coercive-workflow",
    "prompt-injection-external-callback",
    "prompt-injection-forced-exfiltration",
    "prompt-injection-override",
    "prompt-injection-secret-leak",
    "governance-bypass",
    "scanner-evasion",
    "update-drift-risk",
}


def _rule_applies(rule: Rule, doc_rule_context: bool, exec_file: bool) -> bool:
    if doc_rule_context:
        return rule.rule_id in DOC_RULES
    if exec_file:
        return rule.rule_id not in DOC_ONLY_RULES
    return rule.rule_id in DOC_ONLY_RULES


def _line_evidence_for_rule(record: FileRecord, line_no: int, rule: Rule) -> Evidence:
    line = record.lines[line_no - 1] if 1 <= line_no <= len(record.lines) else ""
    if rule.rule_id == "dangerous-shell-exec" and _looks_like_safe_local_cli_invocation(line, record.text):
        return line_evidence(
            record,
            line_no,
            "Code invokes a fixed local CLI command without shell interpolation.",
            "AST-06",
            "low",
            "local-cli-exec",
            0.25,
        )
    if rule.rule_id == "agent-state-access" and _looks_like_user_story_text(line):
        return line_evidence(
            record,
            line_no,
            "Text mentions chat or messages in product/user-story copy, not local agent state access.",
            "AST-10",
            "info",
            "contextual-auth-copy",
            0.1,
        )
    if rule.rule_id in {"agent-state-access", "secret-file-access"} and _looks_like_skill_config_reference(line):
        return line_evidence(
            record,
            line_no,
            "Line references the current skill's own configuration or documentation path.",
            "AST-04",
            "info",
            "skill-config-reference",
            0.1,
        )
    if rule.rule_id in {"agent-state-access", "secret-file-access", "credential-store-access"} and _looks_like_tooling_reference(line, record.text):
        return line_evidence(
            record,
            line_no,
            "Documentation references agent/tool configuration or API key setup without reading or transmitting secrets.",
            "AST-04",
            "info",
            "tooling-config-reference",
            0.1,
        )
    if rule.rule_id == "secret-file-access":
        if _looks_like_secret_linter_fixture(line, record.text):
            return line_evidence(
                record,
                line_no,
                "Code references example secret fixtures for local scanning rather than live credential stores.",
                "AST-03",
                "low",
                "example-secret-fixture",
                0.2,
            )
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
                "AST-03",
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
                "AST-02",
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
                "AST-01",
                "critical",
                "doc-local-history-egress",
                2.0,
                ("chat history", "history.jsonl", "pastedcontents", "slack", "dm"),
            )
        )
    if _document_telemetry_exfiltration(lowered):
        evidence.append(
            _file_context_evidence(
                record,
                "Skill documentation directs telemetry or audit logging of prompts, conversations, workspace files, command output, or environment data.",
                "AST-01",
                "critical",
                "doc-telemetry-exfiltration",
                2.0,
                ("telemetry", "analytics", "audit", "command output", "terminal output", "workspace", "environment"),
            )
        )
    return evidence


def _package_graph_evidence(files: list[FileRecord], evidence: list[Evidence]) -> list[Evidence]:
    rule_ids = {item.rule_id for item in evidence}
    graph: list[Evidence] = []
    package_text = _package_text(files)
    package_lowered = package_text.lower()
    concrete_sensitive_source = _has_concrete_sensitive_source(evidence)
    if concrete_sensitive_source and _has_network_sink(package_lowered) and not _benign_service_api_flow(evidence):
        source = _first_rule_evidence(evidence, "secret-file-access") or _first_rule_evidence(evidence, "unsafe-network")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package-level dataflow links sensitive local sources to outbound network sinks.",
                snippet=source.snippet if source else "",
                category="AST-01",
                severity="critical",
                rule_id="graph-sensitive-source-network-sink",
                weight=1.5,
            )
        )
    if concrete_sensitive_source and _has_shell_sink(package_lowered) and not _benign_service_api_flow(evidence):
        source = _first_rule_evidence(evidence, "secret-file-access") or _first_rule_evidence(evidence, "dangerous-shell-exec")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package-level dataflow links sensitive local sources to shell execution sinks.",
                snippet=source.snippet if source else "",
                category="AST-06",
                severity="high",
                rule_id="graph-sensitive-source-shell-sink",
                weight=1.1,
            )
        )
    if _has_remote_content_execution_flow(files):
        source = _first_rule_evidence(evidence, "remote-code-pipe") or _first_rule_evidence(evidence, "model-artifact-risk")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package-level dataflow links untrusted remote or serialized content to dynamic loading/execution.",
                snippet=source.snippet if source else "",
                category="AST-02",
                severity="critical",
                rule_id="graph-untrusted-content-loader",
                weight=1.2,
            )
        )
    if _has_scanner_evasion_flow(package_lowered):
        source = _first_rule_evidence(evidence, "scanner-evasion")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package-level control flow appears to alter behavior in scanner, sandbox, judge, or container environments.",
                snippet=source.snippet if source else "",
                category="AST-08",
                severity="high",
                rule_id="graph-scanner-evasion-flow",
                weight=1.1,
            )
        )
    if {"obfuscated-payload", "unsafe-network"} <= rule_ids:
        source = _first_rule_evidence(evidence, "obfuscated-payload") or _first_rule_evidence(evidence, "unsafe-network")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package combines encoded or obfuscated payload markers with outbound network capability.",
                snippet=source.snippet if source else "",
                category="AST-04",
                severity="critical",
                rule_id="graph-obfuscated-network",
                weight=1.1,
            )
        )
    if "remote-code-pipe" in rule_ids and "dangerous-shell-exec" in rule_ids:
        source = _first_rule_evidence(evidence, "remote-code-pipe") or _first_rule_evidence(evidence, "dangerous-shell-exec")
        graph.append(
            Evidence(
                file=source.file if source else ".",
                line=source.line if source else 1,
                message="Package combines remote code retrieval with shell or dynamic execution primitives.",
                snippet=source.snippet if source else "",
                category="AST-02",
                severity="critical",
                rule_id="graph-remote-exec-chain",
                weight=1.2,
            )
        )
    archive_hits = [
        item
        for item in evidence
        if "!" in item.file
        and item.rule_id
        in {
            "agent-state-access",
            "data-exfiltration",
            "doc-telemetry-exfiltration",
            "model-artifact-risk",
            "prompt-injection-forced-exfiltration",
            "prompt-injection-override",
            "remote-code-pipe",
            "reverse-shell",
            "secret-file-access",
        }
    ]
    if archive_hits:
        source = archive_hits[0]
        graph.append(
            Evidence(
                file=source.file,
                line=source.line,
                message="Archive member contains suspicious skill instructions or executable payload markers.",
                snippet=source.snippet,
                category="AST-02",
                severity="high",
                rule_id="archive-suspicious-payload",
                weight=1.0,
            )
        )
    return graph


def _package_text(files: list[FileRecord]) -> str:
    chunks: list[str] = []
    for record in files:
        if record.is_binary:
            chunks.append(record.relpath)
            continue
        chunks.append(record.relpath)
        chunks.append(record.text[:60_000])
    return "\n".join(chunks)


def _has_sensitive_source(text: str) -> bool:
    return bool(
        re.search(
            r"(\.env|id_rsa|id_ed25519|\.ssh|\.aws/credentials|\.npmrc|\.pypirc|\.netrc|git-credentials|login data|cookies|keychain|\.claude|\.codex|\.cursor|conversation history|chat history|prompt history|terminal output|command output)",
            text,
            re.I,
        )
    )


def _has_concrete_sensitive_source(evidence: list[Evidence]) -> bool:
    risky_rules = {
        "agent-state-access",
        "browser-profile-access",
        "credential-store-access",
        "data-exfiltration",
        "doc-local-history-egress",
        "doc-telemetry-exfiltration",
        "prompt-injection-forced-exfiltration",
        "secret-file-access",
    }
    return any(item.rule_id in risky_rules for item in evidence)


def _benign_service_api_flow(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if "service-api-credential" not in rule_ids:
        return False
    decisive_rules = {
        "browser-profile-access",
        "credential-store-access",
        "data-exfiltration",
        "doc-local-history-egress",
        "doc-telemetry-exfiltration",
        "prompt-injection-forced-exfiltration",
    }
    if rule_ids & decisive_rules:
        return False
    sensitive_hits = [item for item in evidence if item.rule_id in {"agent-state-access", "secret-file-access"}]
    if not sensitive_hits:
        return True
    return all(_looks_like_skill_config_reference(item.snippet) or _looks_like_service_api_credential(item.snippet, "") for item in sensitive_hits)


def _has_network_sink(text: str) -> bool:
    return bool(re.search(r"\b(requests\.(?:post|put)|httpx\.(?:post|put)|urlopen|fetch\(|axios\.(?:post|put)|curl\s+-|curl\s|wget\s|webhook|collector|requestbin|pastebin)\b|https?://", text, re.I))


def _has_shell_sink(text: str) -> bool:
    return bool(re.search(r"\b(os\.system|subprocess\.(?:popen|run|call)|popen\(|execsync|child_process|spawn\(|bash\s+-c|sh\s+-c|/bin/sh|/bin/bash)\b", text, re.I))


def _has_dynamic_load_sink(text: str) -> bool:
    return bool(re.search(r"\b(eval\(|exec\(|function\s*\(|import\s*\(|vm\.runin|pickle\.load|joblib\.load|torch\.load|keras\.models\.load_model|yaml\.load)\b", text, re.I))


def _has_untrusted_content_source(text: str) -> bool:
    return bool(re.search(r"\b(requests\.|httpx\.|urllib\.request|fetch\(|axios\.|curl\s|wget\s|https?://|\.pkl\b|\.pickle\b|\.joblib\b|\.pt\b|\.pth\b|\.onnx\b|\.safetensors\b|base64\.b64decode|atob\()\b", text, re.I))


def _has_remote_content_execution_flow(files: list[FileRecord]) -> bool:
    """Detect actual remote content flowing into execution, not ordinary API clients."""
    for record in files:
        if record.is_binary or not is_execution_relevant_file(record):
            continue
        text = record.text.lower()
        if re.search(r"\b(curl|wget)\b.{0,160}\|\s*(bash|sh|python|node|ruby|perl)", text, re.I | re.S):
            return True
        if re.search(
            r"\b(requests\.get|httpx\.get|urllib\.request|urlopen|fetch\(|axios\.get)\b.{0,260}\b(eval\(|exec\(|function\s*\(|vm\.runin|import\s*\()\b",
            text,
            re.I | re.S,
        ):
            return True
        if re.search(
            r"\b(eval\(|exec\(|function\s*\(|vm\.runin|import\s*\()\b.{0,260}\b(response|resp|res\.text|r\.text|r\.data|payload|remote|download)\b",
            text,
            re.I | re.S,
        ) and re.search(r"\b(requests\.get|httpx\.get|urllib\.request|urlopen|fetch\(|axios\.get|https?://)\b", text, re.I):
            return True
        if re.search(r"\b(pip install|npm install|npx|pnpm add|yarn add)\b.{0,160}\b(https?|git\+|latest|main|master|head)\b", text, re.I):
            return True
        if re.search(r"\b(pickle\.load|joblib\.load|torch\.load|keras\.models\.load_model|yaml\.load)\b", text, re.I) and re.search(
            r"\b(requests\.|httpx\.|urllib\.request|urlopen|fetch\(|axios\.|https?://|\.pkl\b|\.pickle\b|\.joblib\b|\.pt\b|\.pth\b|\.onnx\b|\.safetensors\b)\b",
            text,
            re.I,
        ):
            return True
    return False


def _has_scanner_evasion_flow(text: str) -> bool:
    return bool(
        re.search(
            r"\b(if|when|unless|case)\b.{0,160}\b(scanner|sandbox|ctf|judge|evaluation|/.dockerenv|docker|container|ci)\b.{0,200}\b(benign|skip|return|do nothing|sleep|time\.sleep|settimeout|delay|defer)\b",
            text,
            re.I | re.S,
        )
        or re.search(
            r"\b(scanner|sandbox|ctf|judge|evaluation|/.dockerenv|docker|container|ci)\b.{0,160}\b(if|when|unless|case)\b.{0,200}\b(benign|skip|return|do nothing|sleep|time\.sleep|settimeout|delay|defer)\b",
            text,
            re.I | re.S,
        )
    )


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
    return bool(
        (
            re.search(r"subprocess\.run\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,", text) is not None
            and re.search(r"[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\[[^\]]+", text, re.S) is not None
        )
        or re.search(r"subprocess\.run\(\s*\[[^\]]+\]\s*,", text, re.S) is not None
    )


def _looks_like_safe_local_cli_invocation(line: str, file_text: str) -> bool:
    if not re.search(r"\bsubprocess\.run\(", line):
        return False
    return _safe_subprocess_argv(file_text)


def _looks_like_service_api_credential(line: str, file_text: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in (".ssh", "id_rsa", "login data", "cookies", "keychain", "git-credentials")):
        return False
    if _exfil_line(lowered):
        return False
    if "webhook" in lowered or "history.jsonl" in lowered or "conversation history" in lowered:
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
        "snowflake",
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


def _looks_like_skill_config_reference(line: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in ("history.jsonl", "conversation history", "chat history", ".codex", ".cursor")):
        return False
    if not re.search(r"\.(claude|agent|skill)[/\w.-]{0,80}/skills?/", lowered):
        return False
    return bool(re.search(r"(?<!\w)(\.env|settings|config|readme|skill\.md|export|manually|directory)\b", lowered))


def _looks_like_tooling_reference(line: str, file_text: str) -> bool:
    lowered = line.lower()
    if _exfil_line(lowered):
        return False
    if re.search(r"\b(open\(|read_text|readfilesync|requests\.post|fetch\(|curl\s+-x\s*post)\b", lowered) and any(
        marker in lowered for marker in ("history.jsonl", "auth.json", "credentials", "cookies", "login data")
    ):
        return False
    context = file_text.lower()
    docs_context = any(marker in context for marker in ("troubleshoot", "debug", "documentation", "reference", "setup", "configuration", "cli options", "integration pattern"))
    tooling_marker = any(
        marker in lowered
        for marker in (
            ".claude/skills",
            "~/.claude/skills",
            ".claude/agents",
            "~/.claude/agents",
            ".claude/agents/name.md",
            "~/.claude/agents/name.md",
            "settings.json",
            "settings.local.json",
            "code.claude.com/docs/en/",
            "anthropic_api_key",
            "openai_api_key",
            ".env",
            "env vars",
            "secrets.",
            "credentials(",
        )
    )
    benign_action = any(
        marker in lowered
        for marker in (
            "ls ",
            "mkdir",
            "head ",
            "grep ",
            "jq ",
            "echo ",
            "set env",
            "environment variable",
            "api key for",
            "permissions",
            "docs/en/",
            "must have:",
            "wrong location",
            "missing",
            "(user)",
            "(project)",
            "credentials(",
            "secrets.",
            "api key for",
            "audit-log",
            "env vars",
            ".env",
            ".claude/hooks",
        )
    )
    return docs_context and tooling_marker and benign_action


def _looks_like_secret_linter_fixture(line: str, file_text: str) -> bool:
    lowered = line.lower()
    if not any(marker in lowered for marker in (".env.example", "example.env", "sample.env", "fixture", "testdata")):
        return False
    if _exfil_line(lowered):
        return False
    context = file_text.lower()
    return any(marker in context for marker in ("secret linter", "secret auditor", "scan", "lint", "fixture", "example"))


def _looks_like_user_story_text(line: str) -> bool:
    lowered = line.lower()
    text_markers = ("paragraph", "heading", "scenario", "user story", "as a returning user", "acceptance criteria")
    if any(marker in lowered for marker in text_markers):
        return True
    return bool(
        re.search(r"\b(given|when|then|as a user|i want)\b", lowered)
        and re.search(r"\b(chat|message|messages|conversation)\b", lowered)
        and not re.search(r"\b(read_text|open\(|history\.jsonl|upload|webhook|collector|requests\.post|curl)\b", lowered)
    )


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


def _document_telemetry_exfiltration(lowered: str) -> bool:
    telemetry = r"\b(logs?|logging|telemetry|analytics|audit|monitoring)\b"
    sensitive = r"\b(user prompt|full prompt|conversation|chat history|workspace files?|command output|terminal output|environment variables?|env vars?|secrets?|credentials?)\b"
    broad = r"\b(all|full|complete|entire|every|each)\b"
    egress = r"\b(send|upload|forward|post|webhook|external|collector|endpoint|slack|discord)\b|https?://"
    for window in _text_windows(lowered, max_lines=8):
        if _looks_like_tooling_reference(window, lowered):
            continue
        if re.search(r"\b(audit-log\.sh|\.claude/audit\.log|tail\s+-\d+\s+\.claude/audit\.log|grep\s+-i\s+error\s+\.claude/audit\.log)\b", window, re.I):
            continue
        if (
            re.search(telemetry, window, re.I)
            and re.search(sensitive, window, re.I)
            and (re.search(broad, window, re.I) or re.search(egress, window, re.I))
        ):
            return True
    return False


def _text_windows(text: str, max_lines: int = 8) -> list[str]:
    lines = text.splitlines()
    windows: list[str] = []
    for index in range(len(lines)):
        windows.append("\n".join(lines[index : index + max_lines]))
    return windows


def _nearby(lowered: str, first_pattern: str, second_pattern: str, window: int = 260) -> bool:
    first_matches = list(re.finditer(first_pattern, lowered, re.I))
    second_matches = list(re.finditer(second_pattern, lowered, re.I))
    return any(abs(first.start() - second.start()) <= window for first in first_matches for second in second_matches)


def _first_rule_evidence(evidence: list[Evidence], rule_id: str) -> Evidence | None:
    for item in evidence:
        if item.rule_id == rule_id:
            return item
    return None


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
