import os
mode = os.getenv("LANG")
token = os.environ["FAKE_API_TOKEN"]
os.environ["TEMP"] = "SYNTHETIC_VALUE"
