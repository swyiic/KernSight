#!/usr/bin/env python3
"""Scan ELF dynsym for TLS/BIO/QUIC names. Local files or adb range-reads."""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys

NEEDLES = (
    "SSL_write",
    "SSL_read",
    "SSL_peek",
    "SSL_write_ex",
    "SSL_read_ex",
    "BIO_write",
    "BIO_read",
    "SSL_quic",
    "quic",
    "ssl_log_secret",
)


class LocalFile:
    def __init__(self, path: str) -> None:
        self.path = path
        self._f = open(path, "rb")
        self.size = os.path.getsize(path)

    def read_at(self, offset: int, size: int) -> bytes:
        self._f.seek(offset)
        return self._f.read(size)

    def close(self) -> None:
        self._f.close()


class AdbFile:
    def __init__(self, serial: str, remote: str) -> None:
        self.serial = serial
        self.path = remote
        quoted = remote.replace("'", "'\\''")
        size_out = subprocess.check_output(
            ["adb", "-s", serial, "shell", "su", "-c", f"stat -c %s '{quoted}'"],
            text=True,
        ).strip()
        self.size = int(size_out.splitlines()[-1])

    def read_at(self, offset: int, size: int) -> bytes:
        quoted = self.path.replace("'", "'\\''")
        cmd = f"dd if='{quoted}' bs=4096 skip={offset // 4096} count={(size + (offset % 4096) + 4095) // 4096} 2>/dev/null"
        blob = subprocess.check_output(["adb", "-s", self.serial, "exec-out", "su", "-c", cmd])
        start = offset % 4096
        return blob[start : start + size]


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def cstr(buf: bytes, off: int) -> str:
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", "replace")


def parse_build_id(src, sh_off: int, sh_size: int) -> str | None:
    note = src.read_at(sh_off, min(sh_size, 256))
    if len(note) < 16:
        return None
    namesz = u32(note, 0)
    descsz = u32(note, 4)
    kind = u32(note, 8)
    name = note[12 : 12 + namesz]
    if kind != 3 or not name.startswith(b"GNU"):
        return None
    desc_off = (12 + namesz + 3) & ~3
    desc = note[desc_off : desc_off + descsz]
    return desc.hex()


def scan(src) -> dict:
    ident = src.read_at(0, 64)
    if ident[:4] != b"\x7fELF":
        raise SystemExit(f"not ELF: {src.path}")
    elf64 = ident[4] == 2
    if ident[5] != 1:
        raise SystemExit("big-endian ELF unsupported")
    if elf64:
        shoff = u64(ident, 40)
        shentsize = u16(ident, 58)
        shnum = u16(ident, 60)
        shstrndx = u16(ident, 62)
        phoff = u64(ident, 32)
        phentsize = u16(ident, 54)
        phnum = u16(ident, 56)
    else:
        shoff = u32(ident, 32)
        shentsize = u16(ident, 46)
        shnum = u16(ident, 48)
        shstrndx = u16(ident, 50)
        phoff = u32(ident, 28)
        phentsize = u16(ident, 42)
        phnum = u16(ident, 44)

    ph = src.read_at(phoff, phentsize * phnum)
    loads = []
    for i in range(phnum):
        ent = ph[i * phentsize : (i + 1) * phentsize]
        p_type = u32(ent, 0)
        if p_type != 1:
            continue
        if elf64:
            p_offset = u64(ent, 8)
            p_vaddr = u64(ent, 16)
            p_filesz = u64(ent, 32)
        else:
            p_offset = u32(ent, 4)
            p_vaddr = u32(ent, 8)
            p_filesz = u32(ent, 16)
        loads.append((p_offset, p_vaddr, p_filesz))

    def virt_to_file(virt: int) -> int | None:
        for off, vaddr, filesz in loads:
            if vaddr <= virt < vaddr + filesz:
                return off + (virt - vaddr)
        return None

    sh = src.read_at(shoff, shentsize * shnum)
    sections = []
    for i in range(shnum):
        ent = sh[i * shentsize : (i + 1) * shentsize]
        if elf64:
            sections.append(
                {
                    "name": u32(ent, 0),
                    "type": u32(ent, 4),
                    "addr": u64(ent, 16),
                    "off": u64(ent, 24),
                    "size": u64(ent, 32),
                    "link": u32(ent, 40),
                }
            )
        else:
            sections.append(
                {
                    "name": u32(ent, 0),
                    "type": u32(ent, 4),
                    "addr": u32(ent, 12),
                    "off": u32(ent, 16),
                    "size": u32(ent, 20),
                    "link": u32(ent, 24),
                }
            )

    shstr = sections[shstrndx]
    strtab = src.read_at(shstr["off"], shstr["size"])
    named = []
    for sec in sections:
        sec["strname"] = cstr(strtab, sec["name"])
        named.append(sec)

    build_id = None
    for sec in named:
        if sec["strname"] == ".note.gnu.build-id" or (
            sec["type"] == 7 and sec["size"] >= 16
        ):
            parsed = parse_build_id(src, sec["off"], sec["size"])
            if parsed:
                build_id = parsed
                if sec["strname"] == ".note.gnu.build-id":
                    break

    dynsym = next((s for s in named if s["strname"] == ".dynsym" or s["type"] == 11), None)
    hits: list[tuple[str, str, int | None]] = []
    if dynsym is not None:
        dynstr = named[dynsym["link"]] if dynsym["link"] < len(named) else None
        if dynstr is None:
            dynstr = next((s for s in named if s["strname"] == ".dynstr"), None)
        entsize = 24 if elf64 else 16
        count = dynsym["size"] // entsize
        blob = src.read_at(dynsym["off"], dynsym["size"])
        strings = src.read_at(dynstr["off"], dynstr["size"]) if dynstr else b""
        for i in range(count):
            ent = blob[i * entsize : (i + 1) * entsize]
            if elf64:
                name_off = u32(ent, 0)
                info = ent[4]
                shndx = u16(ent, 6)
                value = u64(ent, 8)
            else:
                name_off = u32(ent, 0)
                value = u32(ent, 4)
                info = ent[12]
                shndx = u16(ent, 14)
            name = cstr(strings, name_off)
            if not name or not any(n in name for n in NEEDLES):
                continue
            bind = info >> 4
            typ = info & 0xF
            if shndx == 0:
                kind = "UND"
                file_off = None
            elif typ == 2:
                kind = "DEFINED"
                file_off = virt_to_file(value)
            else:
                kind = f"OTHER t={typ} b={bind}"
                file_off = virt_to_file(value) if value else None
            hits.append((name, kind, file_off))

    return {
        "path": src.path,
        "size": src.size,
        "elf64": elf64,
        "build_id": build_id,
        "hits": hits,
    }


def format_report(info: dict) -> str:
    lines = [
        f"ELF {info['path']}",
        f"  size={info['size']} bits={64 if info['elf64'] else 32} build-id={info['build_id'] or '-'}",
    ]
    if not info["hits"]:
        lines.append("  (no SSL_*/BIO_*/quic dynsym needles)")
        return "\n".join(lines)
    for name, kind, off in info["hits"]:
        if off is None:
            lines.append(f"  {kind:8} {name}")
        else:
            lines.append(f"  {kind:8} {name} file_off={off:#x} ({off})")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--adb", metavar="SERIAL")
    parser.add_argument("--remote", action="append", default=[])
    args = parser.parse_args()
    reports = []
    for path in args.paths:
        src = LocalFile(path)
        try:
            reports.append(scan(src))
        finally:
            src.close()
    if args.adb:
        for remote in args.remote:
            src = AdbFile(args.adb, remote)
            reports.append(scan(src))
    for info in reports:
        print(format_report(info))
        print()


if __name__ == "__main__":
    main()
