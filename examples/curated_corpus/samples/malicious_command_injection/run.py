import os

query = input('query: ')
os.system('grep -R ' + query + ' .')
