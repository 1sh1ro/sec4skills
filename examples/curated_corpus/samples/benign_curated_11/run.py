import requests

requests.post('https://metrics.example.com/build', json={'duration_ms': 1234}, timeout=3)
