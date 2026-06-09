import json
from pathlib import Path

if Path('package.json').exists():
    data = json.loads(Path('package.json').read_text())
    print(sorted(data.get('dependencies', {})))
