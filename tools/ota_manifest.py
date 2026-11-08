#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""The fleet's OTA owner key and the signed manifests nodes accept (docs/OTA.md).

    ota_manifest.py keygen <dir>
        A new Ed25519 owner key: <dir>/owner_key.pem (keep it offline) and the
        console line that provisions each node with its public key.
    ota_manifest.py provision --key <pem>
        That console line again, for a key made earlier.
    ota_manifest.py sign --key <pem> --board <name> <image.bin> [-o <out>]
        The manifest for a built image (default <image.bin>.ahot); its version
        is read from the image itself.
    ota_manifest.py verify --owner <hex> --board <name> <manifest> [<image.bin>]
        Check a manifest the way a node does, and against the image if given.

A wired node serves its own image once its manifest is flashed beside it:
    esptool write-flash 0x1a000 <image.bin>.ahot
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import sys
from pathlib import Path

from boards import boards
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b"AHOT"
FORMAT = 1
SIGN_CONTEXT = b"airhop-fw-v1"
BOARD_LEN = 16
FIELDS = struct.Struct(">4sBII32s16s")
SIGNATURE_LEN = 64
MANIFEST_LEN = FIELDS.size + SIGNATURE_LEN

# esp_app_desc_t follows the image header (24 bytes) and the first segment
# header (8 bytes); its version string sits 16 bytes in, 32 bytes long.
APP_DESC_OFFSET = 24 + 8
APP_DESC_MAGIC = 0xABCD5432
VERSION_OFFSET = APP_DESC_OFFSET + 16


def image_version(image: bytes) -> int:
    (magic,) = struct.unpack_from("<I", image, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        raise SystemExit("not an ESP-IDF application image (no app description)")
    text = image[VERSION_OFFSET : VERSION_OFFSET + 32].split(b"\0", 1)[0].decode()
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        raise SystemExit(f"image version {text!r} is not major.minor.patch")
    major, minor, patch = (int(x) for x in match.groups())
    if max(major, minor, patch) > 0xFF:
        raise SystemExit(f"image version {text!r} does not fit the announce's 0xB0 field")
    return major << 16 | minor << 8 | patch


def build_manifest(key: Ed25519PrivateKey, board: str, image: bytes) -> bytes:
    known = boards()
    if board not in known:
        raise SystemExit(f"unknown board {board!r}: one of {', '.join(known)}")
    fields = FIELDS.pack(
        MAGIC,
        FORMAT,
        image_version(image),
        len(image),
        hashlib.sha256(image).digest(),
        board.encode().ljust(BOARD_LEN, b"\0"),
    )
    return fields + key.sign(SIGN_CONTEXT + fields)


def check_manifest(owner: bytes, board: str, manifest: bytes, image: bytes | None) -> str:
    if len(manifest) != MANIFEST_LEN:
        raise SystemExit(f"manifest is {len(manifest)} bytes, not {MANIFEST_LEN}")
    fields, signature = manifest[: FIELDS.size], manifest[FIELDS.size :]
    magic, fmt, version, size, digest, board_field = FIELDS.unpack(fields)
    if magic != MAGIC or fmt != FORMAT:
        raise SystemExit("not an Airlink manifest")
    Ed25519PublicKey.from_public_bytes(owner).verify(signature, SIGN_CONTEXT + fields)
    named = board_field.rstrip(b"\0").decode()
    if named != board:
        raise SystemExit(f"manifest is for {named}, not {board}")
    if image is not None and (len(image) != size or hashlib.sha256(image).digest() != digest):
        raise SystemExit("image does not match the manifest")
    return f"{named} {version >> 16}.{(version >> 8) & 0xFF}.{version & 0xFF}, {size} bytes"


def keygen(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "owner_key.pem"
    if path.exists():
        raise SystemExit(f"{path} exists: an owner key is replaced only by re-provisioning every node")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"private key: {path} (back it up offline; losing it ends updates for this fleet)")
    print(f"provision each node with:  {provisioning(key)}")


def provisioning(key: Ed25519PrivateKey) -> str:
    """The console's `owner` line: the public key, then its fingerprint (the first 8 bytes of its SHA-256), which
    the node takes as proof the key was not mistyped."""
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"owner {public.hex()} {hashlib.sha256(public).digest()[:8].hex()}"


def load_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("the owner key must be Ed25519")
    return key


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("directory", type=Path)
    p = sub.add_parser("provision")
    p.add_argument("--key", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--key", type=Path, required=True)
    s.add_argument("--board", required=True)
    s.add_argument("image", type=Path)
    s.add_argument("-o", "--out", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("--owner", required=True, help="the owner public key, 64 hex digits")
    v.add_argument("--board", required=True)
    v.add_argument("manifest", type=Path)
    v.add_argument("image", type=Path, nargs="?")
    args = parser.parse_args(argv)

    if args.command == "keygen":
        keygen(args.directory)
    elif args.command == "provision":
        print(provisioning(load_key(args.key)))
    elif args.command == "sign":
        key = load_key(args.key)
        manifest = build_manifest(key, args.board, args.image.read_bytes())
        out = args.out or args.image.with_name(args.image.name + ".ahot")
        out.write_bytes(manifest)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print(f"{out}: {check_manifest(public, args.board, manifest, args.image.read_bytes())}")
    else:
        image = args.image.read_bytes() if args.image else None
        print(check_manifest(bytes.fromhex(args.owner), args.board, args.manifest.read_bytes(), image))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
