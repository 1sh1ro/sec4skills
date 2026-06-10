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
        capability_text = "\n".join(
            line
            for line in record.lines
            if not _metadata_url_line(line)
        )
        for capability, patterns in CAPABILITY_PATTERNS.items():
            if any(pattern.search(capability_text) for pattern in patterns):
                capabilities.add(capability)
    return capabilities


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
