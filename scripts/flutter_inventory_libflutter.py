#!/usr/bin/env python3
"""Inventory forensics/**/runtime-so/*libflutter* : build-id, size, keylog label presence.

Crash-safe helper for KernSight Flutter version-library pipeline.
Does NOT invent offsets — only reports facts for later ADRP+ADD xref pinning.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

LABELS = [
    b"CLIENT_TRAFFIC_SECRET_0",
    b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    b"CLIENT_RANDOM",
    b"EXPORTER_SECRET",
    b"SERVER_TRAFFIC_SECRET_0",
]


def build_id(path: Path) -> str | None:
    for tool in ("llvm-readelf", "readelf"):
        try:
            out = subprocess.check_output([tool, "-n", str(path)], stderr=subprocess.DEVNULL, text=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        for line in out.splitlines():
            if "Build ID:" in line:
                return line.split("Build ID:")[-1].strip()
    # GNU note fallback
    data = path.read_bytes()
    # NT_GNU_BUILD_ID = 3
    i = 0
    while True:
        j = data.find(b"GNU\x00", i)
        if j < 0:
            break
        # look back for note header rough
        # better: parse ELF notes via section
        i = j + 4
    try:
        out = subprocess.check_output(["file", str(path)], text=True)
        m = re.search(r"BuildID\[sha1\]=([0-9a-f]+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def label_hits(data: bytes) -> dict[str, list[str]]:
    hits = {}
    for lab in LABELS:
        idxs = []
        start = 0
        while True:
            k = data.find(lab, start)
            if k < 0:
                break
            idxs.append(hex(k))
            start = k + 1
            if len(idxs) > 3:
                break
        if idxs:
            hits[lab.decode()] = idxs
    return hits


def dart_hints(data: bytes) -> list[str]:
    # printable scan limited
    text = re.findall(rb"[\x20-\x7e]{8,80}", data)
    hints = []
    for t in text:
        s = t.decode("ascii", "ignore")
        if "Dart SDK" in s or s.startswith("Flutter "):
            hints.append(s[:80])
        if re.fullmatch(r"\d+\.\d+\.\d+", s) and s.startswith(("2.", "3.")):
            hints.append("ver=" + s)
    # dedupe preserve order
    seen = set()
    out = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:12]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", type=Path, help="KernSight repo root")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    samples = sorted(args.repo.glob("forensics/*/runtime-so/*libflutter*"))
    rows = []
    by_bid: dict[str, list] = defaultdict(list)
    for p in samples:
        data = p.read_bytes()
        bid = build_id(p)
        row = {
            "path": str(p.relative_to(args.repo)),
            "size": len(data),
            "build_id": bid,
            "labels": label_hits(data),
            "hints": dart_hints(data),
        }
        rows.append(row)
        by_bid[bid or f"NOBID:{p.name}"].append(row)
    report = {
        "sample_count": len(rows),
        "unique_build_ids": {k: len(v) for k, v in by_bid.items()},
        "samples": rows,
    }
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print(f"samples={len(rows)} unique_build_ids={len(by_bid)}")
        for bid, items in by_bid.items():
            print(f"\nbuild-id={bid} copies={len(items)} size={items[0]['size']}")
            print(f"  labels={list(items[0]['labels'])}")
            print(f"  hints={items[0]['hints']}")
            for it in items[:3]:
                print(f"  - {it['path']}")
            if len(items) > 3:
                print(f"  … +{len(items)-3} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
