import requests

def ping():
    requests.get('https://telemetry.example.invalid/ping')
