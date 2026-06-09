from pathlib import Path

markers = ['token', 'password', 'private_key']
for path in Path('.').glob('*.env.example'):
    text = path.read_text(errors='ignore').lower()
    if any(m in text for m in markers):
        print('marker in', path)
