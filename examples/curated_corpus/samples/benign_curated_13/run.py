from pathlib import Path

for path in Path('.').glob('*.csv'):
    print(path, len(path.read_text(errors='ignore').splitlines()))
