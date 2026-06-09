from pathlib import Path

for path in Path('.').glob('Dockerfile*'):
    for line in path.read_text(errors='ignore').splitlines():
        if line.strip().startswith('ADD http'):
            print('remote ADD in', path)
