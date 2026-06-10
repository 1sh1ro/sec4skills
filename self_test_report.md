# Self-test Report - SkillMRI

## Required Interface

- Docker entrypoint: `python /app/engine/engine.py`
- Source entrypoint in package: `engine/engine.py`
- Input path: `/data/skills/{skill_id}/`
- Output path: `/output/results.jsonl`
- Output fields: `skill_id`, `verdict`, `confidence`, `category`, `evidence`
- Compatibility fields: `engine_category`, `evidence_text`
- Compatibility env vars: `SKILLSEC_INPUT_DIR`, `SKILLSEC_OUTPUT_DIR`
- Runtime network: not required
- Build-time package downloads: not required
- LLM token usage: `0`

## Optimization Summary

This build keeps the high-performance static-only runtime path and improves
detection quality and evaluator compatibility with generalized changes:

- robust contest target discovery for documented batch layout, direct
  single-skill roots, file-only roots, and lightly nested extracted packages
- `skill_id` preservation for `/data/skills/{skill_id}/` so manifest display
  names do not replace evaluator IDs
- `SKILLSEC_INPUT_DIR`/`SKILLSEC_OUTPUT_DIR` support and compatibility aliases
  for the platform sample schema
- hidden nested skill payloads under `.claude/skills`, `.codex/skills`, or
  `.cursor/skills` map to `AST01`
- injected value-alignment, moderation, legal, or political output constraints
  map to `AST01`
- unrelated external callback/collector snippets embedded in skill docs,
  credential theft, persistence, and destructive operations map to `AST01`
- remote bootstrap, package lifecycle downloads, and remote code execution
  setup paths map to `AST02`
- bounded zip/tar/tgz archive inspection finds hidden payload files without
  unbounded extraction
- package-level dataflow links sensitive sources to network, shell, dynamic
  loader, or serialized artifact sinks
- SkillSieve-style offline triage adds explicit intent alignment, permission
  justification, covert behavior, cross-file consistency, and kill-chain
  evidence without online LLM calls
- contest JSONL output is more recall-oriented than the internal scanner:
  concrete non-`AST10` evidence is reported as at least `suspicious` unless it
  matches a low-risk benign control
- AST07/AST08/AST09 coverage was added for update drift, scanner evasion, and
  governance bypass patterns
- broad filesystem/network/secret/shell permission manifests map to `AST03`
- obfuscated metadata and hidden non-skill files map to `AST04`
- unsafe YAML/object/prototype deserialization markers map to `AST05`
- a lightweight semantic classifier (`skillmri/semantic_model.json`, about
  128 KB) adds weak ML evidence from skill text/code n-grams when confidence is
  sufficient
- tutorial-only bootstrap examples and normal service API credentials are
  downweighted to reduce clean-skill false positives
- static malicious verdicts are no longer downgraded by the local evidence
  scorer, preserving the recall-weighted F2 objective

No LLM, network call, package install, or heavy dependency was added. A 0.5B
model was considered, but not shipped because quantized weights and CPU
inference latency are a poor fit for the 16 MB package and performance-focused
contest path.

## Local Smoke Test

Command:

```bash
PYTHONPATH=. python3 -m skillmri contest \
  --input-dir /tmp/skillmri-contest/skills \
  --output-file /tmp/skillmri-contest/output/results.jsonl
```

Synthetic two-skill smoke result:

- `benign_001`: `benign`, category `AST10`
- `malicious_001`: `malicious`, category `AST01`
- env-var runner smoke: `SKILLSEC_INPUT_DIR` -> `SKILLSEC_OUTPUT_DIR/results.jsonl`
  produced `sample_001`, `malicious`, category `AST01`

## Submission Format And Packaging Validation

The archive `dist/sec4skills-track-b-submission.tar.gz` follows the platform
sample layout.

Required files present:

- `Dockerfile`
- `engine/engine.py`
- `submission.json`
- `design.md`
- `self_test_report.md`
- `results.example.jsonl`

Archive checks:

- Archive size: below the 16 MB upload limit
- Forbidden cache/archive entries: none found for `__pycache__`, `.pyc`, or
  historical `skillmri-contest` image tarballs
- Docker build from the archive completed successfully
- Container output matches the source-tree scanner output on the curated corpus

## Packaging Performance Validation

The same 74-sample curated corpus was scanned in two execution forms:

1. Source tree, `python3 -m skillmri contest`
2. Docker image built from the final source tree

Both forms produced identical `results.jsonl` rows. Verdict distribution:

- `benign`: 13
- `suspicious`: 25
- `malicious`: 36

Timing, with one warmup run and five measured runs:

| Execution form | Mean total time | Mean per-skill time | Output match |
| --- | ---: | ---: | --- |
| Source Python | `0.3276s` | `0.00443s` | yes |
| Docker image from final package | `1.8891s` | `0.02553s` | yes |
| Published GHCR Docker image | `1.7608s` | `0.02379s` | yes |

The Docker timing includes container startup overhead. The scanner itself stays
on the same static path as the source run.

## Internal Validation

The curated development corpus contains 74 samples: 23 benign, 20 suspicious,
and 31 malicious.

Full-corpus regression check after adding offline triage/kill-chain evidence:

- Accuracy: `0.8514`
- Malicious precision: `0.8611`
- Malicious recall: `1.0`
- Malicious F2: `0.9687`
- False negatives: `0`
- False positives: `5`
- Category accuracy: `0.8627`

Semantic classifier holdout check:

- Model size: `127,527 bytes`
- Validation samples: `19`
- Accuracy: `0.8421`
- Malicious precision: `1.0`
- Malicious recall: `1.0`
- Malicious F2: `1.0`
- False positives: `0`

Additional non-curated stress set:

- Samples: `14`
- Malicious precision: `1.0`
- Malicious recall: `1.0`
- Malicious F2: `1.0`
- False negatives: `0`
- False positives: `0`
- Benign strict malicious false-positive rate: `0.0`

This full-corpus score is treated only as a regression signal because it is a
curated development corpus, not an independent benchmark.

## External Benchmark Sanity Checks

Skill-Inject generated sandboxes:

- Samples: `122`
- Accuracy: `0.9098`
- Malicious precision: `0.8936`
- Malicious recall: `1.0`
- Malicious F2: `0.9767`
- False negatives: `0`
- False positives: `10`

MaliciousAgentSkillsBench sampled subset:

- Samples: `39`
- Malicious precision: `0.6000`
- Malicious recall: `1.0`
- Malicious F2: `0.8824`
- Benign strict malicious false-positive rate: `0.0`
- Benign non-benign rate: `0.0625`

These external checks indicate the current engine is recall-oriented, matching
the F2 scoring objective, while preserving the previous strong performance
profile.
