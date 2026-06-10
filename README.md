# SkillMRI

SkillMRI is an offline blue-team scanner for Agent Skill submissions. It is designed for the Skill CTF style evaluation where the submitted artifact is a Dockerized detection engine and the score rewards detection quality, performance, and explainability.

The scanner combines four layers:

1. Static rules for prompt injection, secret access, shell execution, network egress, persistence, destructive filesystem operations, supply-chain risk, and obfuscation.
2. Behavioral Integrity Verification: compares declared capabilities in `SKILL.md`, manifests, and README files against behavior found in code and prompts.
3. Canary sandbox probes: by default, a safe simulation that predicts secret-egress paths; optionally, a short local execution probe for known entrypoints.
4. Evidence graph output: each hit includes `file:line`, severity, rule id, snippet, and OWASP AST-style category.
5. RL-tuned evidence scoring: a compact offline policy can rank evidence combinations for F2-oriented recall while preserving the static evidence graph.

## Quick Start

```bash
cd tools/skillmri
python -m skillmri examples/malicious_skill --output summary
python -m skillmri examples/malicious_skill --output json
python -m skillmri examples/malicious_skill --no-rl-policy --output summary
```

Build the competition Docker image:

```bash
docker build -t skillmri:latest .
docker run --rm \
  -v /tmp/skillmri-contest/skills:/data/skills:ro \
  -v "$PWD/out:/output" \
  skillmri:latest
```

The scanner exits with code `2` when `--fail-on-malicious` is enabled and the verdict is malicious.

## Competition Docker Interface

The Docker image defaults to the required blue-team batch interface:

- Input: `/data/skills/{skill_id}/`
- Output: `/output/results.jsonl`
- One JSON object per line: `skill_id`, `verdict`, `confidence`, `category`, `evidence`
- Compatibility: also honors `SKILLSEC_INPUT_DIR` and `SKILLSEC_OUTPUT_DIR`, supports single-root and lightly nested skill packages, and emits `engine_category`/`evidence_text` aliases for the platform sample schema.

Local build and smoke run:

```bash
cd tools/skillmri
docker build -t skillmri:latest .
mkdir -p /tmp/skillmri-contest/skills /tmp/skillmri-contest/output
cp -R examples/benign_skill /tmp/skillmri-contest/skills/benign_001
cp -R examples/malicious_skill /tmp/skillmri-contest/skills/malicious_001
docker run --rm \
  -v /tmp/skillmri-contest/skills:/data/skills:ro \
  -v /tmp/skillmri-contest/output:/output \
  skillmri:latest
cat /tmp/skillmri-contest/output/results.jsonl
```

The image is fully offline at runtime and does not use an LLM or network access. To export it without pushing:

```bash
docker save skillmri:latest | gzip > skillmri-latest.tar.gz
```

If a registry is available:

```bash
docker tag skillmri:latest ghcr.io/<owner>/skillmri:latest
docker push ghcr.io/<owner>/skillmri:latest
```

## Track B Submission Package

The contest sample package is a small `.tar.gz` source and metadata archive,
not a `docker save` image archive. Docker is delivered through GitHub Container
Registry and bound by digest in `submission.json`.

Published contest image:

```text
ghcr.io/1sh1ro/sec4skills:contest
PENDING_GHCR_DIGEST
```

The repository `dist/sec4skills-track-b-submission.tar.gz` archive follows the
platform sample layout and contains:

- `submission.json`
- `design.md`
- `engine/engine.py`
- `self_test_report.md`
- `results.example.jsonl`
- complete SkillMRI source, Dockerfile, tests, and examples

It is kept below the 16 MB upload limit. The Dockerfile copies `engine/` and
`skillmri/` directly and does not run `pip install`, so image build does not
need package downloads. Do not use a compressed `docker save` tarball for that
upload limit; the local Docker image archive is larger because it includes the
Python base image layers.

## Training And Evaluation

Build the curated black/white/gray corpus, train the local evidence scorer, and evaluate the full scanner:

```bash
python -m skillmri build-dataset --output-dir examples/curated_corpus --jsonl examples/rl_curated_training.jsonl
python -m skillmri train-rl examples/rl_curated_training.jsonl --output-model skillmri/rl_policy.json
python -m skillmri eval-dataset examples/curated_corpus/manifest.json
python -m skillmri eval-dataset examples/curated_corpus/manifest.json --no-rl-policy
```

The curated corpus currently contains 74 samples: 23 benign, 20 suspicious, and 31 malicious. The templates are derived from threat models used in OWASP Agentic Skills Top 10, BIV declared-vs-actual checks, SkillSieve-style triage, Skill-Inject prompt/obfuscation variants, MaliciousAgentSkillsBench-style exfiltration, Cisco skill-scanner-inspired shell/network cases, and repo-aware false-positive controls.

Do not tune against the full-corpus score alone. `train-rl` now uses a deterministic stratified holdout by default (`--validation-ratio 0.25 --cv-folds 5 --seed 17`) and stores validation metadata in the packaged policy. The full-corpus `eval-dataset` command is useful as a regression check, but it is optimistic because those samples are also the curated development set.

Current full-corpus regression score with the packaged contest defaults:

- Accuracy: 0.8243
- Malicious precision: 0.9118
- Malicious recall: 1.0
- Malicious F2: 0.9810
- False negatives: 0
- False positives: 3
- Category accuracy: 0.8039

The v0.1.4 contest build also runs a separate 14-sample stress set that is not
part of the curated development corpus. It covers pure-document exfiltration,
unsafe YAML tags, package lifecycle bootstrap, broad permission manifests,
hidden nested skills, reverse shell patterns, browser credential access, and
benign controls for install docs, API clients, secret linters, and base64 tools.
That stress set scores malicious recall 1.0, malicious F2 1.0, strict benign
malicious false-positive rate 0.0, and benign non-benign rate 0.0.

Use `--no-rl-policy` when precision on known-benign internal tooling matters more than recall. For contest tuning, keep a separate private validation set of real black/white/gray submissions and only promote policy changes that improve held-out F2 without introducing avoidable benign false positives.

## External Benchmarks

Use `eval-paths` for external benchmark manifests:

```bash
python -m skillmri eval-paths /path/to/manifest.json --output json
```

The manifest is a JSON array. Each row needs `path` plus one of `label`, `classification`, or `expected`; labels such as `safe`, `clean`, and `benign` are normalized to `benign`.

The first paper-benchmark pass used:

- Skill-Inject: local clone of `aisa-group/skill-inject`, first task per injection, generated with its `scripts/build_sandbox.py`.
- MaliciousAgentSkillsBench: `ProtectSkills/MaliciousAgentSkillsBench` CSVs from Hugging Face; a small sampled subset of GitHub archives was downloaded and only successfully extracted skill directories were evaluated.

Latest measured SkillMRI results:

- Skill-Inject generated sandboxes: 122 samples, malicious recall 1.0, malicious F2 0.9767, false negatives 0, false positives 10.
- MaliciousAgentSkillsBench sampled subset: 39 samples, malicious recall 1.0, malicious F2 0.8824, benign strict malicious false-positive rate 0.0.

These numbers are not directly comparable to Skill-Inject's paper ASR because SkillMRI is doing pre-execution skill detection, not measuring whether an agent follows an injection. They do show a clear engineering target: recall is strong on injected Skill-Inject samples, but precision is poor on realistic clean skills because documentation, examples, plugin metadata, and API/token instructions are currently treated too much like executable malicious behavior.

## Output Schema

```json
{
  "label": "malicious",
  "malicious": true,
  "confidence": 0.96,
  "risk_score": 49,
  "primary_category": "AST-01",
  "evidence": [
    {
      "file": "run.py",
      "line": 4,
      "category": "AST-01",
      "severity": "critical",
      "rule_id": "secret-file-access",
      "message": "Code references common secret stores or private key material."
    }
  ]
}
```

## Sandbox Modes

- `--sandbox off`: static and contract checks only.
- `--sandbox simulate`: default. Does not execute the sample; infers canary risk from combined capabilities.
- `--sandbox run`: executes `run.py`, `main.py`, `scan.py`, `index.js`, or `main.js` for up to five seconds with fake secrets and proxy-blocked network variables. Use this only inside a disposable container or VM.

## Design Notes

The engine intentionally avoids online LLM dependencies. LLMs can be used before the contest to expand rules and generate adversarial regression data, but the submitted scanner remains deterministic, fast, and explainable.
