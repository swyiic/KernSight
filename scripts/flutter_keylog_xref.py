#!/usr/bin/env python3
"""ADRP+ADD xref scan for BoringSSL keylog labels in stripped libflutter.so.

Finds candidate ssl_log_secret entry as the common BL target after label
materialization into a register (typically x1). Crash-safe: prints candidates;
only promote to stack_rules when multi-label evidence is clear AND pinned by
build-id. Never invent offsets for unmatched builds.
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

LABELS = [
    "CLIENT_TRAFFIC_SECRET_0",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_RANDOM",
    "EXPORTER_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
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
    return None


def pt_load_text(data: bytes):
    assert data[:4] == b"\x7fELF"
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and (p_flags & 1):  # PF_X
            loads.append((p_offset, p_vaddr, p_filesz))
    return loads[0] if loads else (0, 0, len(data))


def decode_adrp(insn: int, pc: int):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    page = (pc & ~0xFFF) + (imm << 12)
    return rd, page


def decode_add_imm(insn: int):
    if (insn & 0xFF800000) != 0x91000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm12 = (insn >> 10) & 0xFFF
    shift = (insn >> 22) & 0x3
    if shift == 1:
        imm12 <<= 12
    elif shift != 0:
        return None
    return rd, rn, imm12


def decode_bl(insn: int, pc: int):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libflutter", type=Path)
    args = ap.parse_args()
    data = args.libflutter.read_bytes()
    text_off, text_va, text_fs = pt_load_text(data)
    text = data[text_off : text_off + text_fs]
    label_va = {}
    for name in LABELS:
        fo = data.find(name.encode())
        if fo >= 0:
            # file offset → VA assuming identity for first load often true for ET_DYN
            label_va[name] = text_va + (fo - text_off) if text_off <= fo < text_off + text_fs else fo
    print(f"file={args.libflutter} size={len(data)} build-id={build_id(args.libflutter)}")
    print(f"text off={hex(text_off)} va={hex(text_va)} fs={hex(text_fs)}")
    print("label_va", {k: hex(v) for k, v in label_va.items()})
    if not label_va:
        print("No keylog labels — cannot xref (gap only).", file=sys.stderr)
        return 2

    hits = {k: [] for k in label_va}
    n = text_fs // 4
    for i in range(n):
        off = i * 4
        insn = struct.unpack_from("<I", text, off)[0]
        ad = decode_adrp(insn, text_va + off)
        if not ad:
            continue
        rd_adrp, page = ad
        for j in range(1, 12):
            if i + j >= n:
                break
            insn2 = struct.unpack_from("<I", text, off + j * 4)[0]
            ad2 = decode_add_imm(insn2)
            if not ad2:
                continue
            rd, rn, imm = ad2
            if rn != rd_adrp:
                continue
            va = page + imm
            for name, target in label_va.items():
                if va == target:
                    pc = text_va + off
                    # scan forward for BL
                    bls = []
                    for k in range(j, j + 16):
                        if i + k >= n:
                            break
                        pc2 = text_va + (i + k) * 4
                        insn3 = struct.unpack_from("<I", text, (i + k) * 4)[0]
                        tgt = decode_bl(insn3, pc2)
                        if tgt is not None:
                            bls.append(tgt)
                    hits[name].append({"adrp": hex(pc), "reg": f"x{rd}", "bls": [hex(b) for b in bls[:6]]})
                    break

    bl_counter: Counter[int] = Counter()
    for name, lst in hits.items():
        print(f"{name}: {len(lst)} xrefs")
        for h in lst[:8]:
            print(f"  {h}")
            for b in h["bls"]:
                bl_counter[int(b, 16)] += 1

    print("\nTop BL targets after label materialization:")
    for tgt, cnt in bl_counter.most_common(8):
        print(f"  {hex(tgt)} refs={cnt}")
    if bl_counter:
        best, cnt = bl_counter.most_common(1)[0]
        print(f"\nCANDIDATE ssl_log_secret={hex(best)} (decimal {best}) — promote ONLY with build-id pin + multi-label evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
