"""
Phylax subnet — setup.py

For environments still using setuptools directly. Modern installs prefer
`pip install -e .` which reads pyproject.toml.
"""

from setuptools import setup, find_packages

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.strip().startswith("#")
    ]

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="phylax-subnet",
    version="0.1.0",
    description="Decentralized trust layer for AI agent skills (Bittensor subnet)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Phylax contributors",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests", "tests.*", "corpora", "docker", "scripts"]),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phylax-miner=neurons.miner:main",
            "phylax-validator=neurons.validator:main",
        ],
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
)
