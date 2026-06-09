#!/usr/bin/env python3
"""Track B Docker entrypoint for the SkillMRI engine."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    from skillmri.cli import main as skillmri_main

    args = sys.argv[1:] or ["contest"]
    return skillmri_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
