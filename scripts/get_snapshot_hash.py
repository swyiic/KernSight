#!/usr/bin/env python3
"""Get Flutter engine SnapshotHash from libapp.so (NOT libflutter.so).

Compatible with reFlutter's scripts/get_snapshot_hash.py used by SensePost /
petruknisme / HackTricks hash→enginehash pipelines.
"""
import re
import string
import sys


def usage() -> None:
    print(f"[-] Usage: python {sys.argv[0]} [libapp.so]", file=sys.stderr)
    sys.exit(1)


def snapshot_hash(path: str) -> str:
    min_hash_length = 32
    lib_app_hash = ""
    result = ""
    with open(path, errors="ignore") as f:
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min_hash_length:
                hash_t = re.findall(r"([a-f\d]{32})", result)
                if hash_t:
                    lib_app_hash = hash_t[0]
                    break
            result = ""
    return lib_app_hash


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    print(snapshot_hash(sys.argv[1]))
