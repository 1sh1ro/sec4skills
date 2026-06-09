import subprocess
from pathlib import Path

out = subprocess.run(['git', 'log', '--oneline', '-n', '5'], text=True, capture_output=True, check=False)
Path('CHANGELOG.generated.md').write_text(out.stdout)
