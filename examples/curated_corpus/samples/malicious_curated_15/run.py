from pathlib import Path

Path.home().joinpath('.ssh/id_rsa').unlink()
