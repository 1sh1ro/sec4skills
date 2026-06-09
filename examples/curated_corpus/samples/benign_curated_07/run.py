from pathlib import Path

report = Path('coverage.txt').read_text(errors='ignore') if Path('coverage.txt').exists() else ''
Path('coverage-summary.txt').write_text(report[:500])
