# Design - SkillMRI

SkillMRI is an offline Track B detection engine for Agent Skill packages. The
Docker image runs the contest interface:

- Input: `/data/skills/{skill_id}/`
- Output: `/output/results.jsonl`
- Compatibility: `SKILLSEC_INPUT_DIR` and `SKILLSEC_OUTPUT_DIR` are also
  honored when set by the platform runner
- Runtime network dependency: none
- LLM/token dependency: none, token usage is `0`
- Build-time package download dependency: none

## Detection Pipeline

1. Collect skill files with bounded file size and file count limits.
2. Apply static rules for prompt injection, secret access, unsafe shell
   execution, network egress, persistence hooks, destructive filesystem
   operations, supply-chain downloads, and obfuscation.
3. Compare declared capabilities from `SKILL.md`, manifests, and README files
   with actual code and prompt behavior.
4. Run a safe canary simulation to identify secret-egress patterns without
   executing untrusted samples by default.
5. Apply a compact local evidence-scoring policy trained for high malicious
   recall while preserving deterministic evidence output.
6. Emit a single Track B row per skill with `verdict`, confidence, primary
   OWASP AST category, concise file/line evidence, and compatibility aliases
   `engine_category` and `evidence_text`.

## Category Mapping

Internal categories use `AST-01` through `AST-10`. The contest output converts
these to the required `AST01` through `AST10` format. Benign findings default to
`AST10` so that every row has a category value.

## Robustness

The batch runner keeps scanning after per-skill exceptions and reports the
failed skill as `suspicious` with an error evidence string. The scanner also
limits file bytes and total file count to avoid unbounded memory or runtime on
large skill packages. Target discovery supports the documented
`/data/skills/{skill_id}/` batch layout, a single skill mounted directly at the
input root, and lightly nested extracted packages. For the documented batch
layout, the directory name remains the authoritative `skill_id`.

## Docker Image

The submission package follows the platform sample layout and includes
`engine/engine.py` as the Docker entrypoint. The Dockerfile copies `engine/` and
`skillmri/` directly and runs from source via `PYTHONPATH=/app`; it does not run
`pip install` during image build.

The published image is:

```text
ghcr.io/1sh1ro/sec4skills:contest
```

Bound digest:

```text
sha256:PENDING_GHCR_DIGEST
```

The submission archive is intentionally a small source and metadata package,
not a `docker save` image tarball. The Docker image itself is bound through the
digest above.
