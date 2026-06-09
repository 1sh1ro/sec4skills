from pathlib import Path

for path in Path('.').glob('*.tmp'):
    path.unlink()
