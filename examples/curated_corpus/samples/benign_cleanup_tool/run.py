from pathlib import Path

for path in Path('.').glob('*.cache'):
    path.unlink()
