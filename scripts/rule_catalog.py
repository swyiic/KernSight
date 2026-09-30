#!/usr/bin/env python3
"""Turn a scanned ELF into a *disabled* stack-rule candidate.

Library identity only: basename, size, build-id, DEFINED export names.
Never invents file offsets. Never enables plaintext_probes.
Optional --ai drafts notes from those facts (XAI_API_KEY + XAI_MODEL).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_dynsym_scan as elfscan  # noqa: E402

WRITE_NAMES = (
    "SSL_write",
    "SSL_write_ex",
    "SSL_write_ex2",
    "SSL_write_early_data",
    "sslWrite",
    "SLIGHT_SSL_write",
    "mbedtls_ssl_write",
    "wolfSSL_write",
    "quic_stream_write",
    "quic_stream_send",
    "xqc_stream_send",
    "lsquic_stream_write",
)
READ_NAMES = (
    "SSL_read",
    "SSL_read_ex",
    "SSL_read_ex2",
    "SSL_read_early_data",
    "SSL_peek",
    "SSL_peek_ex",
    "sslRead",
    "SLIGHT_SSL_read",
    "mbedtls_ssl_read",
    "wolfSSL_read",
    "quic_stream_read",
    "quic_stream_recv",
    "xqc_stream_recv",
    "lsquic_stream_read",
)
BANNED = ("BIO_write", "BIO_read", "SSL_quic_read_level", "SSL_quic_write_level")
KEYLOG_API = (
    "SSL_CTX_set_keylog_callback",
    "quic_conn_set_keylog",
    "quic_conn_set_keylog_fd",
)


def _base(name: str) -> str:
    return name.split("@@")[0].split("@")[0]


def defined_names(hits: list) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for name, kind, off in hits:
        if kind != "DEFINED":
            continue
        base = _base(name)
        if base in BANNED:
            continue
        out[base] = off
    return out


def catalog_from_scan(info: dict) -> dict:
    defined = defined_names(info.get("hits") or [])
    write = [n for n in WRITE_NAMES if n in defined]
    read = [n for n in READ_NAMES if n in defined]
    keylog_api = [n for n in KEYLOG_API if n in defined]
    basename = Path(info["path"]).name
    bid = (info.get("build_id") or "").lower()
    size = int(info.get("size") or 0)
    stem = bid[:8] if len(bid) >= 8 else basename.replace(".", "_")
    rule_id = f"{Path(basename).stem}_{stem}"
    plaintext = bool(write)
    kind = "stable" if plaintext else "gap"
    notes = (
        f"{basename} size={size} build-id={bid or '-'}. "
        f"DEFINED write={write or '[]'} read={read or '[]'} keylog_api={keylog_api or '[]'}. "
        "Candidate only: validation_state not enabled; no invented RVA."
    )
    engine = None
    for name, kind_hit, _ in info.get("hits") or []:
        if "OPENSSL_" in name:
            engine = _base(name).split("OPENSSL_")[-1] if "OPENSSL_" in name else None
            if "@@" in name:
                engine = name.split("@@", 1)[-1]
            break
    return {
        "id": rule_id,
        "class": "vendor-fork",
        "tier": 2,
        "match_rules": {
            "basename": basename,
            "size": size or None,
            "build_id": bid or None,
        },
        "symbols": {"write": write, "read": read},
        "coverage": {
            "plaintext_copy": plaintext,
            "keylog": bool(keylog_api) or None,
            "boundary_dump": False,
        },
        "plaintext_probes": [],
        "notes": notes,
        "version": {
            "kind": kind,
            "product": f"{basename} (size={size})",
            "engine_version": engine,
            "build_id": bid or None,
            "size": size or None,
            "verified_at": None,
            "upgrade_note": "re-scan dynsym on new build-id; export-name attach if SSL_write/quic_stream_* still DEFINED",
        },
    }


def draft_notes_with_ai(rule: dict) -> str:
    key = os.environ.get("XAI_API_KEY", "").strip()
    model = os.environ.get("XAI_MODEL", "").strip()
    if not key or not model:
        raise SystemExit("--ai requires XAI_API_KEY and XAI_MODEL")
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You catalog native TLS/QUIC libraries. "
                        "Use only the JSON facts. Never invent file offsets, RVAs, "
                        "or APK versionName. Library identity is size+build-id+DEFINED exports. "
                        "Reply with one paragraph of notes, no markdown."
                    ),
                },
                {"role": "user", "content": json.dumps(rule, ensure_ascii=False)},
            ],
            "temperature": 0,
        }
    ).encode()
    req = urllib.request.Request(
        "https://api.x.ai/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.URLError as error:
        raise SystemExit(f"xAI request failed: {error}") from error
    text = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        .strip()
    )
    if not text:
        raise SystemExit(f"xAI empty response: {body!r}"[:400])
    return text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--out-dir", default="-")
    parser.add_argument("--ai", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        fake = {
            "path": "/apex/lib64/stable_cronet_libssl.so",
            "size": 456088,
            "build_id": "0dceef1315310b5520aa046f7119d879",
            "hits": [
                ("SSL_write", "DEFINED", 0x4CDD0),
                ("BIO_write", "DEFINED", 0x80C90),
                ("SSL_quic_write_level", "DEFINED", 0x4C414),
            ],
        }
        rule = catalog_from_scan(fake)
        assert rule["coverage"]["plaintext_copy"] is True
        assert "SSL_write" in rule["symbols"]["write"]
        assert "BIO_write" not in rule["symbols"]["write"]
        assert rule["plaintext_probes"] == []
        assert rule["version"]["kind"] == "stable"
        gap = catalog_from_scan(
            {
                "path": "/data/app/x/libtquic.so",
                "size": 1833968,
                "build_id": "2916c4a0a606c37082127aacf169a9ff26fbd20e",
                "hits": [("quic_conn_set_keylog", "UND", None)],
            }
        )
        assert gap["coverage"]["plaintext_copy"] is False
        assert gap["version"]["kind"] == "gap"
        print("self-test ok")
        return
    if not args.paths:
        parser.error("ELF paths required")
    out_dir = None if args.out_dir == "-" else Path(args.out_dir)
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    for path in args.paths:
        src = elfscan.LocalFile(path)
        try:
            info = elfscan.scan(src)
        finally:
            src.close()
        rule = catalog_from_scan(info)
        if args.ai:
            rule["notes"] = draft_notes_with_ai(rule)
        text = json.dumps(rule, indent=2, ensure_ascii=False)
        if out_dir:
            dest = out_dir / f"{rule['id']}.json"
            dest.write_text(text + "\n", encoding="utf-8")
            print(dest)
        else:
            print(text)


if __name__ == "__main__":
    main()
