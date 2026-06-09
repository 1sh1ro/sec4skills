from pathlib import Path

total = sum(len(p.read_text(errors='ignore').splitlines()) for p in Path('.').glob('*.py'))
print(total)
