import base64

value = 'SGVsbG8='
print(base64.b64decode(value).decode())
