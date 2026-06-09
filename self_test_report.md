# Self-test Report - SkillMRI

## Required Interface

- Docker entrypoint: `python /app/engine/engine.py`
- Source entrypoint in package: `engine/engine.py`
- Input path: `/data/skills/{skill_id}/`
- Output path: `/output/results.jsonl`
- Output fields: `skill_id`, `verdict`, `confidence`, `category`, `evidence`
- Runtime network: not required
- Build-time package downloads: not required
- LLM token usage: `0`

## Local Smoke Test

Command:

```bash
PYTHONPATH=. python3 -m skillmri contest \
  --input-dir /tmp/skillmri-contest/skills \
  --output-file /tmp/skillmri-contest/output/results.jsonl
```

Synthetic two-skill smoke result:

- `benign_001`: `benign`, category `AST10`
- `malicious_001`: `malicious`, category `AST02`
- Local elapsed time for two skills: about `0.162s`
- Estimated per-skill detection time on this smoke run: about `0.081s`

## Internal Validation

The curated development corpus contains 74 samples: 23 benign, 20 suspicious,
and 31 malicious.

Packaged policy validation:

- Training split: 55 samples
- Held-out validation split: 19 samples
- Held-out malicious precision: `1.0`
- Held-out malicious recall: `0.875`
- Held-out malicious F2: `0.8974`
- 5-fold mean malicious F2: `0.9142`
- 5-fold mean malicious recall: `0.9333`

Full-corpus regression check:

- Accuracy: `0.9054`
- Malicious precision: `0.9394`
- Malicious recall: `1.0`
- Malicious F2: `0.9873`
- False negatives: `0`
- False positives: `2`

The full-corpus score is treated only as a regression signal because it is a
curated development corpus, not an independent benchmark.

## External Benchmark Sanity Checks

Skill-Inject generated sandboxes:

- Clean skills: 38 samples, strict false positive rate `0.5526`
- Obvious injections: strict recall `0.8611`, suspicious-or-worse recall `1.0`
- Contextual injections: strict recall `0.8958`, suspicious-or-worse recall
  `1.0`
- Combined malicious precision `0.7789`, recall `0.8810`, F2 `0.8585`

MaliciousAgentSkillsBench sampled subset:

- 39 extracted skills from 60 attempted rows
- Malicious strict recall: `0.7778`
- Safe samples showed high false positives in this small subset

This indicates the current engine is recall-oriented, which matches the F2
scoring objective, but precision tuning against realistic clean skills remains
the main improvement target.
