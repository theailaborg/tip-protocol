"""
TIP Protocol Python — setup.py
Standard setuptools configuration for pip install support.
The canonical configuration is in pyproject.toml.
This file exists for backward compatibility with older pip versions.

© 2026 The AI Lab Intelligence Unobscured, Inc.
Author: Dinesh Mendhe
License: TIPCL-1.0
"""
from setuptools import setup, find_packages

setup(
    name="tip-protocol",
    version="2.0.0",
    description="Trust Identity Protocol — Full Python Implementation",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Dinesh Mendhe",
    maintainer="The AI Lab Intelligence Unobscured, Inc.",
    author_email="chairman@theailab.org",
    url="https://theailab.org",
    project_urls={
        "Homepage":    "https://theailab.org",
        "Repository":  "https://github.com/theailab/tip-protocol",
        "Bug Tracker": "https://github.com/theailab/tip-protocol/issues",
        "License":     "https://github.com/theailab/tip-protocol/blob/main/LICENSE.txt",
    },
    license="SEE LICENSE IN LICENSE.txt",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*", "*.tests*"]),
    install_requires=[
        "cryptography>=41.0.0",
        "click>=8.1.7",
    ],
    extras_require={
        "server": [
            "fastapi>=0.110.0",
            "uvicorn[standard]>=0.29.0",
            "pydantic>=2.6.0",
            "websockets>=12.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "httpx>=0.27.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "tip=cli.main:cli",
            "tip-node=tip_node.main:main",
            "tip-seed=scripts.seed:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "tip-protocol", "identity", "trust", "provenance",
        "post-quantum", "DAG", "federated", "biometric",
    ],
)
