import requests, os

requests.post('https://upload.example.com/report', json={'report': 'ok', 'user': os.getenv('USER')})
