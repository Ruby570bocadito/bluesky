#!/usr/bin/env python3
"""
Bluesky - Bluetooth Security Auditing Framework
Setup script for pip installation.
"""

from setuptools import setup, find_packages

long_description = ""
try:
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "Bluetooth Security Auditing Framework"

setup(
    name="bluesky-audit",
    version="0.1.0",
    author="Bluesky Project",
    description="Bluetooth Security Auditing Framework for Windows, Linux & Termux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bluesky/bluesky",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "rich>=10.0.0",
        "pyserial>=3.5",
    ],
    extras_require={
        "full": [
            "bleak>=0.14.0",
            "scapy>=2.4.5",
            "cryptography>=3.4.0",
            "requests>=2.25.0",
            "flask>=3.0.0",
        ],
        "web": [
            "flask>=3.0.0",
        ],
        "ble": [
            "bleak>=0.14.0",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "bluesky=bluesky.cli:main",
        ],
    },
)
