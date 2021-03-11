#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", encoding='utf8') as readme:
    long_description = readme.read()

setup(
    name="naft",
    version="1.0.0b1",
    author="@digitalsleuth and @G-K7",
    license="None",
    url="https://github.com/digitalsleuth/naft",
    description="Network Appliance Forensic Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    keywords="naft",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_data={'': ['README.md']},
    entry_points={
        'console_scripts': [
            'naft=naft.naft:main',
            ],
    },
)
