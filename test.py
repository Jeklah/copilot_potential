# Take an executable file as input and find the libc version and the offset of the system call table.
# Query blukat.org with the offset and putf address to find the version of the libc.
# Download the version of libc given by blukat.org and put it in the current directory.

import sys
import subprocess
import re
import requests
import os
import shutil
import argparse
import urllib.request
import urllib.parse
import urllib.error


def get_system_call_table_offset(binary_path):
    """
    Get the offset of the system call table in the binary.
    """
    output = subprocess.check_output(["objdump", "-d", binary_path])
    output = output.decode("utf-8")
    for line in output.split("\n"):
        if "system_call_table" in line:
            return int(line.split(" ")[0], 16)


def get_libc_version(binary_path, system_call_table_offset):
    """
    Get the version of the libc from the binary.
    """
    output = subprocess.check_output(["objdump", "-d", binary_path])
    output = output.decode("utf-8")
    for line in output.split("\n"):
        if "libc" in line:
            return line.split(" ")[0]
    return None


def get_libc_version_from_blukat(system_call_table_offset, putf_address):
    """
    Get the version of the libc from blukat.org.
    """
    url = "https://blukat.org/api/v1/libc?offset={}&putf={}".format(system_call_table_offset, putf_address)
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()["libc"]["version"]
    return None


def download_libc(libc_version):
    """
    Download the libc from blukat.org.
    """
    url = "https://blukat.org/api/v1/libc/{}".format(libc_version)
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()["libc"]["path"]
    return None
