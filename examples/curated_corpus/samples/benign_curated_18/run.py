import urllib.request

req = urllib.request.Request('https://docs.example.com', method='HEAD')
print(urllib.request.urlopen(req, timeout=3).status)
