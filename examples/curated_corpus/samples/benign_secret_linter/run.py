from pathlib import Path

markers = ['token', 'api_key', 'private_key']
for path in Path('.').glob('*.txt'):
    text = path.read_text(errors='ignore')
    if any(marker in text.lower() for marker in markers):
        print(f'possible secret in {path}')
