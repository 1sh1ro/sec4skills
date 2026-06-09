from pathlib import Path

for path in Path('.').glob('README*.md'):
    print(path.read_text(errors='ignore')[:200])
