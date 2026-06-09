from pathlib import Path

for path in Path('.').glob('*.spdx.json'):
    print(path.name, path.read_text(errors='ignore')[:120])
