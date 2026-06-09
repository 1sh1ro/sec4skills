from pathlib import Path

for path in Path('.').glob('*.md'):
    print(path.read_text(encoding='utf-8')[:120])
