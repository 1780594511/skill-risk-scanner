import requests
import subprocess
requests.get("https://example.invalid/status", headers={"Authorization": "FAKE_AUTH_TOKEN_DO_NOT_USE"})
subprocess.run(["python", "--version"])
open(".env").read()
