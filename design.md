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

1. Collect skill files with bounded file size and file count limits, including
   bounded inspection of small zip/tar/tgz resource archives.
2. Apply static rules for prompt injection, secret access, unsafe shell
   execution, network egress, persistence hooks, destructive filesystem
   operations, supply-chain downloads, model artifact loading, and obfuscation.
3. Compare declared capabilities from `SKILL.md`, manifests, and README files
   with actual code and prompt behavior.
4. Add package-level dataflow evidence for sensitive sources flowing toward
   network, shell, dynamic loader, or serialized artifact sinks.
5. Run a safe canary simulation to identify secret-egress patterns without
   executing untrusted samples by default.
6. Apply a lightweight semantic classifier trained on skill text/code n-grams.
   It is a pure-Python linear model stored as JSON, so it adds no runtime
   dependency and only contributes weak evidence when confidence and margin are
   sufficient.
7. Optionally call an OpenAI-compatible online classifier when explicitly
   enabled through environment variables. This is intended for local
   experiments and score exploration, not as the default contest path.
8. Apply a compact local evidence-scoring policy trained for high malicious
   recall while preserving deterministic evidence output.
9. Emit a single Track B row per skill with `verdict`, confidence, primary
   OWASP AST category, concise file/line evidence, and compatibility aliases
   `engine_category` and `evidence_text`.
10. Apply a contest-only high-recall output policy: concrete non-`AST10`
    evidence is submitted as at least `suspicious` unless it is a known
    low-risk benign control. This keeps the internal scanner interpretable
    while aligning the submitted JSONL with the recall-weighted F2 objective.

## Lightweight ML Layer

A 0.5B language model was considered for semantic classification, but it is not
used in the contest image because even quantized weights would add hundreds of
MB plus CPU inference latency and extra runtime dependencies. The current image
instead packages `skillmri/semantic_model.json`, a roughly 128 KB linear
classifier trained from the curated black/white/gray corpus.

The model uses lexical and path features from skill documentation, manifests,
and code: token n-grams, file suffixes, path tokens, and documentation/code
prefixes. It predicts both `benign/suspicious/malicious` and the primary AST
category. The scanner treats this as an auxiliary semantic signal, not as an
override for decisive static evidence.

## Optional Online Classifier

The implementation includes an optional OpenAI-compatible classifier for local
benchmarking. It reads configuration from environment variables:
`SKILLMRI_ONLINE_CLASSIFIER=1`, `SKILLMRI_ONLINE_API_KEY`,
`SKILLMRI_ONLINE_BASE_URL`, and `SKILLMRI_ONLINE_MODEL`. The API key is never
stored in source, docs, Docker layers, or the submission metadata.

This path is disabled by default because the official evaluator says the
runtime network is isolated. When enabled outside the contest, the scanner sends
a redacted, bounded prompt containing file inventory, snippets, and existing
static evidence. The model must return strict JSON with verdict, confidence,
AST category, and rationale. High-confidence malicious/suspicious predictions
become auxiliary `online-llm-*` evidence; failures and timeouts are non-fatal.

## Category Mapping

Internal categories use the public OWASP Agentic Skills Top 10 numbering:
`AST-01` Malicious Skills, `AST-02` Supply Chain Compromise, `AST-03`
Over-Privileged Skills, `AST-04` Insecure Metadata, `AST-05` Unsafe
Deserialization, `AST-06` Weak Isolation, `AST-07` Update Drift, `AST-08` Poor
Scanning, `AST-09` No Governance, and `AST-10` Cross-Platform Reuse. The contest
output converts these to the required `AST01` through `AST10` format. Benign
findings default to `AST10` so that every row has a category value.

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
sha256:e2a8ce6b01f83d4032b5742cd103ed7c3637869be89ed7f5b4a29a76a68b9492
```

The submission archive is intentionally a small source and metadata package,
not a `docker save` image tarball. The Docker image itself is bound through the
digest above.
