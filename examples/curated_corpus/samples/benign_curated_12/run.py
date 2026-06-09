from pathlib import Path

for path in Path('.').glob('*.md'):
    Path(path.stem + '.html').write_text('<pre>' + path.read_text(errors='ignore')[:1000] + '</pre>')
