# iterate through ROP gadgets and find libc address and https://libc.blukat.me/ API to find the version

import requests
import re
import sys
import time
import argparse
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_rop_gadgets(libc_base_addr, libc_base_addr_end):
    # get the ROP gagets
    rop_gadgets = []
    for i in range(libc_base_addr, libc_base_addr_end):
        if i % 4096 == 0:
            print("[+] Current address: 0x{:x}".format(i))
        try:
            r = requests.get("https://libc.blukat.me/{:x}".format(i), verify=False)
            if r.status_code == 200 and "ROP" in r.text:
                rop_gadgets.append(i)
        except Exception as e:
            print(e)
    return rop_gadgets


def get_libc_base_addr(rop_gadgets):
    # get libc base address
    libc_base_addr = 0
    for i in rop_gadgets:
        try:
            r = requests.get("https://libc.blukat.me/{:x}".format(i), verify=False)
            if r.status_code == 200 and "libc" in r.text:
                libc_base_addr = i
                break
        except Exception as e:
            print(e)
    return libc_base_addr


def get_libc_base_addr_end(rop_gadgets):
    # get libc base adress end
    libc_base_addr_end = 0
    for i in rop_gadgets:
        try:
            r = requests.get("https://libc.blukat.me/{:x}".format(i), verify=False)
            if r.status_code == 200 and "libc" in r.text:
                libc_base_addr_end = i
                break
        except Exception as e:
            print(e)
    return libc_base_addr_end


def get_libc_version(libc_base_addr):
    # get libc version
    libc_version = ""
    try:
        r = requests.get("https://libc.blukat.me/{:x}".format(libc_base_addr), verify=False)

        if r.status_code == 200:
            libc_version = re.findall("libc-(.*?)-", r.text)[0]
    except Exception as e:
        print(e)
    return libc_version


def get_libc_version_end(libc_base_addr_end):
    # get libc version end
    libc_version_end = ""
    try:
        r = requests.get("https://libc.blukat.me/{:x}".format(libc_base_addr_end), verify=False)

        if r.status_code == 200:
            libc_version_end = re.findall("libc-(.*?)-", r.text)[0]
    except Exception as e:
        print(e)
    return libc_version_end


def get_libc_base_addr_end_from_version(libc_version):
    # get the libc base address end from version
    libc_base_addr_end = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version}", verify=False)
        if r.status_code == 200:
            libc_base_addr_end = int(re.findall("0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
    return libc_base_addr_end


def get_libc_base_addr_from_version(libc_version):
    # get the libc base address from version
    libc_base_addr = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version}", verify=False)
        if r.status_code == 200:
            libc_base_addr = int(re.findall("0x(.*?)</a>", r.text)[1], 16)
    except Exception as e:
        print(e)
    return libc_base_addr


def get_libc_base_addr_end_from_version_end(libc_version_end):
    # get the libc base address end from version end
    libc_base_addr_end = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr_end = int(re.findall("0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
    return libc_base_addr_end


def get_libc_base_addr_from_version_end(libc_version_end):
    # get the libc base address from version end
    libc_base_addr = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr = int(re.findall("0x(.*?)</a>", r.text)[1], 16)
    except Exception as e:
        print(e)
    return libc_base_addr


def get_libc_base_addr_end_from_version_end_and_version(libc_version_end):
    # get the libc base address end from version end and version
    libc_base_addr_end = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr_end = int(re.findall("0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
    return libc_base_addr_end


def get_libc_base_addr_from_version_end_and_version(libc_version_end):
    # get the libc base address from version end and version
    libc_base_addr = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr = int(re.findall("0x(.*?)</a>", r.text)[1], 16)
    except Exception as e:
        print(e)
    return libc_base_addr


def get_libc_base_addr_end_from_version_end_and_version_end(libc_version_end):
    # get the libc base address end from version end and version end
    libc_base_addr_end = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr_end = int(re.findall("0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
    return libc_base_addr_end


def get_libc_base_addr_from_version_end_and_version_end(libc_version_end):
    # get the libc base address from version end and version end
    libc_base_addr = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr = int(re.findall("0x(.*?)</a>", r.text)[1], 16)
    except Exception as e:
        print(e)
    return libc_base_addr


def get_libc_base_addr_end_from_version_end_and_version_end_and_version(libc_version_end):
    # get the libc base address end from version end and version end and version
    libc_base_addr_end = 0
    try:
        r = requests.get("https://libc.blukat.me/search/{}".format(libc_version_end), verify=False)
        if r.status_code == 200:
            libc_base_addr_end = int(re.findall(r"0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
        pass
    return libc_base_addr_end


def get_libc_base_addr_from_version_end_and_version_end_and_version(libc_version_end):
    # get the libc base address from version end and version end and version
    libc_base_addr = 0
    try:
        r = requests.get(f"https://libc.blukat.me/search/{libc_version_end}", verify=False)

        if r.status_code == 200:
            libc_base_addr = int(re.findall("0x(.*?)</a>", r.text)[1], 16)
    except Exception as e:
        print(e)
    return libc_base_addr


def get_libc_base_addr_end_from_version_end_and_version_end_and_version_end(libc_version_end):
    # get the libc base address end from version end and version end and version end
    libc_base_addr_end = 0
    try:
        r = requests.get("https://libc.blukat.me/search/{}".format(libc_version_end), verify=False)
        if r.status_code == 200:
            libc_base_addr_end = int(re.findall(r"0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
        pass
    return libc_base_addr_end


def get_libc_base_addr_end_from_version_end_and_version_end_and_version_end_and_version_and_version(libc_version_end):
    libc_base_addr_end = 0
    try:
        r = requests.get("https://libc.blukat.me/search/{}".format(libc_version_end), verify=False)
        if r.status_code == 200:
            libc_base_addr_end = int(re.findall(r"0x(.*?)</a>", r.text)[0], 16)
    except Exception as e:
        print(e)
        pass
    return libc_base_addr_end


def main(file):
    with open(file, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                continue
            libc_version = line.split(",")[0]
            libc_version_end = line.split(",")[1]
            libc_version_end_end = line.split(",")[2]
            libc_base_addr_end = get_libc_base_addr_end_from_version(libc_version)
            libc_base_addr = get_libc_base_addr_from_version(libc_version)
            libc_base_addr_end_end = get_libc_base_addr_end_from_version_end(libc_version_end_end)
            libc_base_addr_end_and_version = get_libc_base_addr_end_from_version_end_and_version(libc_version_end, libc_version)
            libc_base_addr_end_and_version_end = get_libc_base_addr_end_from_version_end_and_version_end(libc_version_end, libc_version_end_end)
            libc_base_addr_end_and_version_end_and_version = get_libc_base_addr_end_from_version_end_and_version_end_and_version(libc_version_end, libc_version_end_end, libc_version)
            libc_base_addr_end_and_version_end_and_version_end = get_libc_base_addr_end_from_version_end_and_version_end_and_version_end(libc_version_end, libc_version_end_end, libc_version_end_end)
            libc_base_addr_end_and_version_end_and_version_end_and_version = get_libc_base_addr_end_from_version_end_and_version_end_and_version_end(libc_version_end, libc_version_end_end)
            libc_base_addr_end_and_version_end_and_version_end_and_version_end = get_libc_base_addr_end_from_version_end_and_version_end_and_version_end_and_version(libc_version_end, libc_version_end_end, libc_version_end_end, libc_version)
            libc_base_addr_end_and_version_end_and_version_end_and_version_end_and_version = get_libc_base_addr_end_from_version_end_and_version_end_and_version_end_and_version_and_version(libc_version_end, libc_version_end_end, libc_version_end_end, libc_version_end_end, libc_version)
            print(f"{libc_version},{libc_version_end},{libc_version_end_end},{libc_base_addr_end},{libc_base_addr},{libc_base_addr_end_end},{libc_base_addr_end_and_version},{libc_base_addr_end_and_version_end},{libc_base_addr_end_and_version_end_and_version},{libc_base_addr_end_and_version_end_and_version_end},{libc_base_addr_end_and_version_end_and_version_end_and_version},{libc_base_addr_end_and_version_end_and_version_end_and_version_end}")
            print(f"{libc_base_addr_end_and_version_end_and_version_end_and_version_end_and_version}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <libc_version_list>")
        sys.exit(1)
    main(sys.argv[1])
    sys.exit(0)
