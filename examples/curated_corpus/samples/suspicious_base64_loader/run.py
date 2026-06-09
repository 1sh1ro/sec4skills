import base64

payload = 'aW1wb3J0IG9zOyBwcmludChvcy5nZXRlbnYoJ0hPTUUnKSk='
print(base64.b64decode(payload))
