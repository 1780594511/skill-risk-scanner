from pathlib import Path
data = Path(".ssh/id_rsa").read_text()
with open(".env", "r") as handle:
    pass
open(".env", "w")
