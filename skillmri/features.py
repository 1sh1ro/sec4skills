from __future__ import annotations

import re
from collections.abc import Iterable

from .schema import Evidence, FileRecord


CAPABILITY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "network": [
        re.compile(r"\bhttps?://", re.I),
        re.compile(r"\b(fetch|requests\.|urllib\.request|httpx\.|axios\.|curl|wget|nc|netcat)\b", re.I),
        re.compile(r"(/dev/tcp/|webhook|pastebin|ngrok|requestbin)", re.I),
    ],
    "filesystem": [
        re.compile(r"\b(open|readFileSync|writeFileSync|Path\(|FileReader|fs\.)\b", re.I),
        re.compile(r"[/\\](home|root|tmp|etc|var|Users)[/\\]", re.I),
    ],
    "shell": [
        re.compile(r"\b(subprocess|os\.system|child_process|execSync|spawn|popen|eval\(|Function\()\b", re.I),
        re.compile(r"\b(bash|sh|powershell|cmd\.exe|python -c|node -e)\b", re.I),
    ],
    "secrets": [
        re.compile(r"\.env\b|id_rsa|\.ssh|\.aws|\.npmrc|\.pypirc|\.netrc|git-credentials", re.I),
        re.compile(r"(Cookies|Login Data|keychain|keyring)", re.I),
        re.compile(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|GITHUB_TOKEN|HF_TOKEN)", re.I),
    ],
    "delete": [
        re.compile(r"\b(rm\s+-rf|unlink|rmtree|remove\(|del\s+/[fsq]|shutil\.rmtree)\b", re.I),
    ],
    "persistence": [
        re.compile(r"\b(crontab|LaunchAgents|systemd|authorized_keys|postinstall|preinstall|prepare)\b", re.I),
    ],
    "obfuscation": [
        re.compile(r"\b(base64\s+-d|base64\.b64decode|atob|fromCharCode|rot13|xxd\s+-r|openssl enc)\b", re.I),
        re.compile(r"\\x[0-9a-f]{2}", re.I),
    ],
}


DETAILED_CAPABILITY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "network_egress": CAPABILITY_PATTERNS["network"],
    "remote_fetch": [
        re.compile(r"\b(curl|wget|requests\.get|httpx\.get|urllib\.request|fetch\(|axios\.get)\b", re.I),
        re.compile(r"\b(git clone|git fetch|git pull|pip install|npm install|npx|pnpm add|yarn add)\b.{0,120}\b(https?|git\+|latest|main|master|head)\b", re.I),
    ],
    "network_post": [
        re.compile(r"\b(requests\.post|httpx\.post|urllib\.request\.urlopen|fetch\(|axios\.post|curl\s+-X\s*POST|curl\s+--data)\b", re.I),
        re.compile(r"\b(webhook|collector|requestbin|pastebin|upload|telemetry|analytics)\b", re.I),
    ],
    "read_workspace": CAPABILITY_PATTERNS["filesystem"],
    "write_workspace": [
        re.compile(r"\b(write_text|write_bytes|open\([^)]*['\"]w|writeFileSync|Path\([^)]*\)\.write|fs\.write)\b", re.I),
        re.compile(r">\s*[\w./~$-]+", re.I),
    ],
    "delete_files": CAPABILITY_PATTERNS["delete"],
    "read_secret": CAPABILITY_PATTERNS["secrets"],
    "read_agent_state": [
        re.compile(r"(\.claude|\.codex|\.cursor).{0,120}\b(history|auth|config|settings|skills|agents|session|token|credentials?)\b", re.I),
        re.compile(r"\b(conversation|chat|transcript|messages?|prompt history).{0,120}\b(read_text|open\(|send|upload|webhook|collector)\b", re.I),
    ],
    "read_browser_profile": [
        re.compile(r"(\.config/google-chrome|\.mozilla/firefox|Application Support/(Google/Chrome|Firefox))", re.I),
        re.compile(r"(Login Data|Cookies|Local State)", re.I),
        re.compile(r"(Google/Chrome|Firefox|browser profile|browser).{0,80}\b(Bookmarks|History)\b", re.I),
        re.compile(r"\b(Bookmarks|History)\b.{0,80}(Google/Chrome|Firefox|browser profile|browser)", re.I),
    ],
    "shell_exec": CAPABILITY_PATTERNS["shell"],
    "dynamic_exec": [
        re.compile(r"\b(eval\(|exec\(|Function\s*\(|vm\.runIn|import\s*\(|pickle\.load|joblib\.load|torch\.load|yaml\.load)\b", re.I),
    ],
    "package_install": [
        re.compile(r"\b(pip install|npm install|pnpm add|yarn add|npx|postinstall|preinstall|prepare)\b", re.I),
    ],
    "persistence_hook": CAPABILITY_PATTERNS["persistence"],
    "obfuscation": CAPABILITY_PATTERNS["obfuscation"],
    "scanner_evasion": [
        re.compile(r"\b(scanner|scan|detector|sandbox|ctf|judge|evaluation|/.dockerenv|docker|container|ci)\b.{0,160}\b(skip|return|benign|sleep|do nothing|bypass|evade)\b", re.I),
        re.compile(r"\b(skip|return|benign|sleep|do nothing|bypass|evade)\b.{0,160}\b(scanner|scan|detector|sandbox|ctf|judge|evaluation|/.dockerenv|docker|container|ci)\b", re.I),
    ],
    "governance_bypass": [
        re.compile(r"\b(bypass|skip|disable|ignore).{0,100}\b(approval|human review|policy|audit|governance|permission prompt|security gate)\b", re.I),
        re.compile(r"\b(force merge|push directly|merge without review|admin override|silent approval)\b", re.I),
    ],
}


DETAILED_TO_COARSE = {
    "network_egress": "network",
    "remote_fetch": "network",
    "network_post": "network",
    "read_workspace": "filesystem",
    "write_workspace": "filesystem",
    "delete_files": "delete",
    "read_secret": "secrets",
    "read_agent_state": "secrets",
    "read_browser_profile": "secrets",
    "shell_exec": "shell",
    "dynamic_exec": "shell",
    "package_install": "persistence",
    "persistence_hook": "persistence",
    "obfuscation": "obfuscation",
    "scanner_evasion": "obfuscation",
    "governance_bypass": "shell",
}


DECLARED_ALLOW_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "network": [
        re.compile(r"\b(api|http|https|web|url|download|upload|network|request|fetch|crawl|scrape)\b", re.I),
        re.compile(r"\b(联网|网络|下载|上传|抓取|接口|请求|网页)\b"),
    ],
    "filesystem": [
        re.compile(r"\b(file|folder|directory|workspace|read|write|save|load|path|document)\b", re.I),
        re.compile(r"\b(文件|目录|读取|写入|保存|加载|工作区|文档)\b"),
    ],
    "shell": [
        re.compile(r"\b(shell|terminal|command|execute|run script|cli|subprocess|formatter|format|test runner|git status|git log)\b", re.I),
        re.compile(r"\b(命令|终端|脚本|执行|运行|格式化|测试|CLI)\b", re.I),
    ],
    "secrets": [
        re.compile(r"\b(secret|credential|token|api key|private key|env)\b", re.I),
        re.compile(r"\b(密钥|凭证|令牌|环境变量)\b"),
    ],
    "delete": [
        re.compile(r"\b(delete|remove|cleanup|clean up|cleaner|purge)\b", re.I),
        re.compile(r"\b(删除|清理|移除)\b"),
    ],
    "persistence": [
        re.compile(r"\b(hook|install|startup|daemon|service|cron|postinstall)\b", re.I),
        re.compile(r"\b(钩子|安装|启动项|服务|定时)\b"),
    ],
    "obfuscation": [
        re.compile(r"\b(base64|decode|decoder|encoding|hex)\b", re.I),
        re.compile(r"\b(解码|编码)\b"),
    ],
}


DECLARATION_FILES = {
    "agent.md",
    "agents.md",
    "codex.md",
    "manifest.json",
    "package.json",
    "plugin.json",
    "readme.md",
    "skill.json",
    "skill.md",
}

DOCUMENTATION_FILENAMES = {
    "agent.md",
    "agents.md",
    "codex.md",
    "contributing.md",
    "readme.md",
    "security.md",
    "skill.md",
}

EXECUTABLE_SUFFIXES = {
    ".bash",
    ".bat",
    ".cjs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".lua",
    ".mjs",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
    ".zsh",
}

CONFIG_SUFFIXES = {
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}

EXECUTABLE_FILENAMES = {
    "dockerfile",
    "makefile",
    "package.json",
    "pnpm-workspace.yaml",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "skill.json",
}


NEGATIVE_DECLARATION_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "network": [
        re.compile(r"\b(no|never|without|does not|offline|local only).{0,40}\b(network|internet|upload|send|request|telemetry)\b", re.I),
        re.compile(r"\b(does not|never).{0,40}\b(transmit|exfiltrate|contact)\b", re.I),
    ],
    "secrets": [
        re.compile(r"\b(no|never|without|does not).{0,40}\b(secret|credential|token|password|private key)\b", re.I),
    ],
}


def declaration_text(files: Iterable[FileRecord]) -> tuple[str, str]:
    declared: list[str] = []
    manifest: list[str] = []
    for record in files:
        name = record.path.name.lower()
        if name in DECLARATION_FILES:
            declared.append(record.text)
        if name.endswith(".json") and name in {"manifest.json", "package.json", "plugin.json", "skill.json"}:
            manifest.append(record.text)
    return "\n".join(declared), "\n".join(manifest)


def infer_declared_capabilities(text: str) -> set[str]:
    return {
        capability
        for capability, patterns in DECLARED_ALLOW_PATTERNS.items()
        if any(pattern.search(text) for pattern in patterns)
    }


def infer_negative_declarations(text: str) -> set[str]:
    return {
        capability
        for capability, patterns in NEGATIVE_DECLARATION_PATTERNS.items()
        if any(pattern.search(text) for pattern in patterns)
    }


def infer_actual_capabilities(files: Iterable[FileRecord]) -> set[str]:
    capabilities: set[str] = set()
    for record in files:
        if record.is_binary or not is_execution_relevant_file(record):
            continue
        capability_text = _capability_relevant_text(record)
        for capability, patterns in CAPABILITY_PATTERNS.items():
            if any(pattern.search(capability_text) for pattern in patterns):
                capabilities.add(capability)
    return capabilities


def infer_detailed_capabilities(files: Iterable[FileRecord]) -> set[str]:
    capabilities: set[str] = set()
    for record in files:
        if record.is_binary or not is_execution_relevant_file(record):
            continue
        capability_text = _capability_relevant_text(record)
        for capability, patterns in DETAILED_CAPABILITY_PATTERNS.items():
            if any(pattern.search(capability_text) for pattern in patterns):
                capabilities.add(capability)
    return capabilities


def _capability_relevant_text(record: FileRecord) -> str:
    text = "\n".join(
        line
        for line in record.lines
        if not _metadata_url_line(line)
        and not _low_risk_skill_config_line(line)
        and not _low_risk_service_api_line(line, record.text)
        and not _low_risk_user_story_line(line)
    )
    if _safe_subprocess_argv(record.text):
        text = re.sub(r"\bsubprocess\.run\s*\(", "subprocess_run_safe(", text)
    return text


def is_documentation_file(record: FileRecord) -> bool:
    name = record.path.name.lower()
    suffix = record.path.suffix.lower()
    return name in DOCUMENTATION_FILENAMES or suffix in {".md", ".mdx", ".rst", ".txt"}


def is_execution_relevant_file(record: FileRecord) -> bool:
    name = record.path.name.lower()
    suffix = record.path.suffix.lower()
    return name in EXECUTABLE_FILENAMES or suffix in EXECUTABLE_SUFFIXES or suffix in CONFIG_SUFFIXES


def _metadata_url_line(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ('"$schema"', "'$schema'", '"githuburl"', '"authoravatar"', "json-schema.org"))


def _low_risk_skill_config_line(line: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in ("history.jsonl", "conversation history", "chat history", ".codex", ".cursor")):
        return False
    if not re.search(r"\.(claude|agent|skill)[/\w.-]{0,80}/skills?/", lowered):
        return False
    return bool(re.search(r"(?<!\w)(\.env|settings|config|readme|skill\.md|export|manually|directory)\b", lowered))


def _low_risk_service_api_line(line: str, file_text: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in (".ssh", "id_rsa", "login data", "cookies", "keychain", "git-credentials")):
        return False
    if re.search(r"\b(requests\.post|httpx\.post|fetch\(|axios\.post|curl)\b.{0,120}\b(token|secret|password|credential|\.env)", lowered, re.I):
        return False
    service_names = (
        "asana",
        "atlassian",
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
    context = file_text.lower()
    service_context = any(name in context for name in service_names)
    env_loader_context = bool(re.search(r"\b(load_?env|dotenv|environment variables?|os\.environ|process\.env)\b", context, re.I))
    service_token = bool(
        re.search(
            r"\b[A-Z][A-Z0-9_]{1,40}_(?:API_)?(?:TOKEN|KEY|SECRET|PASSWORD|BASE_URL|PROJECT_KEY)\b|process\.env\.[A-Z][A-Z0-9_]+|os\.environ\.get\(['\"][A-Z][A-Z0-9_]+",
            line,
        )
    )
    if ".env" in lowered and service_context and env_loader_context:
        return True
    if "os.environ.setdefault" in lowered and service_context and env_loader_context:
        return True
    return service_context and env_loader_context and service_token


def _low_risk_user_story_line(line: str) -> bool:
    lowered = line.lower()
    return bool(
        re.search(r"\b(given|when|then|as a user|i want|scenario|user story|acceptance criteria)\b", lowered)
        and re.search(r"\b(chat|message|messages|conversation)\b", lowered)
        and not re.search(r"\b(read_text|open\(|history\.jsonl|upload|webhook|collector|requests\.post|curl)\b", lowered)
    )


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


def line_evidence(
    record: FileRecord,
    line_no: int,
    message: str,
    category: str,
    severity: str,
    rule_id: str,
    weight: float = 1.0,
) -> Evidence:
    snippet = ""
    if 1 <= line_no <= len(record.lines):
        snippet = record.lines[line_no - 1].strip()[:240]
    return Evidence(
        file=record.relpath,
        line=line_no,
        message=message,
        snippet=snippet,
        category=category,
        severity=severity,
        rule_id=rule_id,
        weight=weight,
    )
