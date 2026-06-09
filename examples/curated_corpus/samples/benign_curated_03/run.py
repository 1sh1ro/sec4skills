import urllib.request

print(urllib.request.urlopen('https://api.example.com/releases', timeout=3).status)
