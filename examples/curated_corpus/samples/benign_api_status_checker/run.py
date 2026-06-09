import urllib.request

URL = 'https://status.example.com/health'
print(urllib.request.urlopen(URL, timeout=3).status)
