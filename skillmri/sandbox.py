from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .schema import Evidence, ScanContext


CANARY_SECRET = "SKILLMRI_CANARY_SECRET_DO_NOT_EXFILTRATE"


def run_canary_sandbox(ctx: ScanContext, mode: str) -> list[Evidence]:
    if mode == "off":
        return []
    if mode == "simulate":
        return _simulate_canary_hits(ctx)
    if mode == "run":
        return _run_entrypoints(ctx)
    raise ValueError(f"Unsupported sandbox mode: {mode}")


def _simulate_canary_hits(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    secret_markers = {"secrets", "filesystem"} <= ctx.actual_capabilities and _has_high_risk_secret_access(ctx)
    exfil_markers = "network" in ctx.actual_capabilities
    shell_markers = "shell" in ctx.actual_capabilities

    if secret_markers and exfil_markers:
        evidence.append(
            Evidence(
                file="canary://simulated",
                line=1,
                message="Canary simulation predicts that the skill can read local secrets and send them over the network.",
                snippet=CANARY_SECRET,
                category="AST-02",
                severity="critical",
                rule_id="canary-simulated-secret-egress",
                weight=1.6,
            )
        )
    if secret_markers and shell_markers:
        evidence.append(
            Evidence(
                file="canary://simulated",
                line=1,
                message="Canary simulation predicts shell-mediated access to sensitive local files.",
                snippet=CANARY_SECRET,
                category="AST-03",
                severity="high",
                rule_id="canary-simulated-shell-secret",
                weight=1.1,
            )
        )
    return evidence


def _has_high_risk_secret_access(ctx: ScanContext) -> bool:
    high_risk_rules = {
        "credential-store-access",
        "data-exfiltration",
        "prompt-injection-forced-exfiltration",
        "secret-file-access",
    }
    for item in ctx.evidence:
        if item.rule_id not in high_risk_rules:
            continue
        if item.rule_id == "secret-file-access" and _service_credential_only(item.snippet):
            continue
        return True
    return False


def _service_credential_only(snippet: str) -> bool:
    lowered = snippet.lower()
    if any(marker in lowered for marker in (".ssh", "id_rsa", ".aws", "login data", "cookies", "keychain", "git-credentials")):
        return False
    return any(name in lowered for name in ("jira", "stripe", "slack", "github", "paypal", "discord", "notion", "linear"))


def _run_entrypoints(ctx: ScanContext) -> list[Evidence]:
    entrypoint = _find_entrypoint(ctx)
    if entrypoint is None:
        return []

    with tempfile.TemporaryDirectory(prefix="skillmri-") as raw_tmp:
        tmp = Path(raw_tmp)
        workdir = tmp / "skill"
        shutil.copytree(ctx.target, workdir)
        canary = tmp / "home" / ".env"
        canary.parent.mkdir(parents=True, exist_ok=True)
        canary.write_text(f"API_KEY={CANARY_SECRET}\n", encoding="utf-8")

        env = {
            "HOME": str(canary.parent),
            "USERPROFILE": str(canary.parent),
            "SKILLMRI_CANARY": CANARY_SECRET,
            "NO_PROXY": "*",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
        }
        command = _entrypoint_command(workdir / entrypoint)
        if not command:
            return []

        try:
            completed = subprocess.run(
                command,
                cwd=workdir,
                env=env,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [
                Evidence(
                    file=entrypoint,
                    line=1,
                    message=f"Sandbox execution failed or timed out: {exc}",
                    category="AST-04",
                    severity="low",
                    rule_id="sandbox-run-failed",
                    weight=0.2,
                )
            ]

        combined = f"{completed.stdout}\n{completed.stderr}"
        evidence: list[Evidence] = []
        if CANARY_SECRET in combined:
            evidence.append(
                Evidence(
                    file=entrypoint,
                    line=1,
                    message="Dynamic canary secret appeared in process output.",
                    snippet=CANARY_SECRET,
                    category="AST-02",
                    severity="critical",
                    rule_id="sandbox-canary-leak-output",
                    weight=2.0,
                )
            )
        evidence_file = workdir / ".skillmri_evidence.json"
        if evidence_file.exists():
            try:
                payload = json.loads(evidence_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = None
            evidence.append(
                Evidence(
                    file=".skillmri_evidence.json",
                    line=1,
                    message=f"Skill wrote sandbox evidence file: {payload!r}",
                    category="AST-06",
                    severity="medium",
                    rule_id="sandbox-evidence-file-written",
                    weight=0.8,
                )
            )
        return evidence


def _find_entrypoint(ctx: ScanContext) -> str | None:
    candidates = [
        "run.py",
        "main.py",
        "scan.py",
        "index.js",
        "main.js",
    ]
    relpaths = {record.relpath for record in ctx.files}
    for candidate in candidates:
        if candidate in relpaths:
            return candidate
    return None


def _entrypoint_command(path: Path) -> list[str]:
    if path.suffix == ".py":
        return ["python", str(path)]
    if path.suffix == ".js":
        return ["node", str(path)]
    return []
