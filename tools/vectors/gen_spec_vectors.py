#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Spec-derived vectors, written from the specifications alone.

The sources are Airhop's PROTOCOLS.md, the Noise spec (rev 34), RFC 1951 (with
zlib's verdict) for the DEFLATE streams, docs/OTA.md for the update manifest
and, where PROTOCOLS defers to bitchat-ios (board posts, the bounds of a live
video packet), that client's rules as stated here in words. Independent of
the C code on purpose: it shares no source with the firmware, so a bug both
sides shared would have to be made twice. It writes
test/vectors/spec-vectors.json, which tools/vectors/gen_c_vectors.py turns into
C. Regenerate after a spec change, never by hand:

    python3 tools/vectors/gen_spec_vectors.py test/vectors/spec-vectors.json

Needs the `cryptography` package (in docker/requirements-dev.txt).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import zlib
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

BASE_TS = 1_780_000_000_000

FLAG_RECIPIENT = 0x01
FLAG_SIGNATURE = 0x02
FLAG_COMPRESSED = 0x04
FLAG_ROUTE = 0x08
FLAG_RSR = 0x10


def pad(data: bytes) -> bytes:
    """PKCS#7 to the smallest of 256/512/1024/2048 that holds len + 16 (section 2.1)."""
    for block in (256, 512, 1024, 2048):
        if len(data) + 16 <= block:
            need = block - len(data)
            return data + bytes([need]) * need if need <= 255 else data
    return data


def raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(level=9, wbits=-15)
    return c.compress(data) + c.flush()


def encode(
    version: int,
    ptype: int,
    ttl: int,
    ts: int,
    sender: bytes,
    payload: bytes,
    recipient: bytes | None = None,
    route: list[bytes] | None = None,
    compress: bool = False,
    rsr: bool = False,
    signature: bytes | None = None,
) -> bytes:
    """Encode exactly as section 2 lays the frame out."""
    flags = 0
    body = payload
    size_field = 4 if version == 2 else 2
    if compress:
        flags |= FLAG_COMPRESSED
        body = len(payload).to_bytes(size_field, "big") + raw_deflate(payload)
    if recipient is not None:
        flags |= FLAG_RECIPIENT
    if signature is not None:
        flags |= FLAG_SIGNATURE
    if route and version == 2:
        flags |= FLAG_ROUTE
    if rsr:
        flags |= FLAG_RSR
    out = bytes([version, ptype, ttl]) + ts.to_bytes(8, "big") + bytes([flags])
    out += len(body).to_bytes(size_field, "big") + sender
    if recipient is not None:
        out += recipient
    if route and version == 2:
        out += bytes([len(route)]) + b"".join(route)
    out += body
    if signature is not None:
        out += signature
    return out


def preimage(frame_no_sig: bytes) -> bytes:
    """TTL 0, IS_RSR and the signature flag cleared, no signature, padded (section 2)."""
    b = bytearray(frame_no_sig)
    b[2] = 0
    b[11] &= ~(FLAG_SIGNATURE | FLAG_RSR) & 0xFF
    return pad(bytes(b))


def signed(key: Ed25519PrivateKey, **fields: object) -> tuple[bytes, bytes]:
    unsigned = encode(**fields)  # type: ignore[arg-type]
    pre = preimage(unsigned)
    sig = key.sign(pre)
    # The signature flag is part of the frame, never of the preimage.
    frame = encode(**fields, signature=sig)  # type: ignore[arg-type]
    return frame, pre


def packet_id(ptype: int, sender: bytes, ts: int, payload: bytes) -> bytes:
    """SHA-256(type | sender | timestamp BE | decoded payload)[0:16] (section 2.3)."""
    return hashlib.sha256(bytes([ptype]) + sender + ts.to_bytes(8, "big") + payload).digest()[:16]


def gcs_hash(pid: bytes) -> int:
    return int.from_bytes(hashlib.sha256(pid).digest()[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF


def gcs_build(ids_newest_first: list[bytes], max_bytes: int = 400, p: int = 7) -> dict[str, object]:
    """bitchat-ios GCSFilter.buildFilter, from section 5's description. At most about 8 * bytes / (P + 2)
    values to start with, and never fewer than one (GCSFilter.estimateMaxElements, as Airhop's
    gossip-sync.ts estimates it too)."""
    if not ids_newest_first:
        return {"p": p, "m": 1, "data": "", "included": 0}
    n = min(len(ids_newest_first), max(1, max(8, max_bytes * 8) // max(3, p + 2)))
    m = min(n << p, 0xFFFFFFFF)

    def encode_first(count: int) -> bytes:
        vals = sorted({(gcs_hash(i) % m) or 1 for i in ids_newest_first[:count]})
        bits: list[int] = []
        prev = 0
        for v in vals:
            x = v - prev - 1
            prev = v
            bits += [1] * (x >> p) + [0]
            bits += [(x >> b) & 1 for b in range(p - 1, -1, -1)]
        out = bytearray((len(bits) + 7) // 8)
        for i, bit in enumerate(bits):
            if bit:
                out[i >> 3] |= 0x80 >> (i & 7)
        return bytes(out)

    data = encode_first(n)
    while len(data) > max_bytes and n > 1:
        n = max(1, n * 9 // 10)
        data = encode_first(n)
    if len(data) > max_bytes:
        return {"p": p, "m": m, "data": "", "included": 0}
    return {"p": p, "m": m, "data": data.hex(), "included": n}


class Symmetric:
    """Noise rev 34 section 5.2, for Noise_XX_25519_ChaChaPoly_SHA256 with an empty prologue."""

    def __init__(self) -> None:
        name = b"Noise_XX_25519_ChaChaPoly_SHA256"
        self.h = name
        self.ck = name
        self.k: bytes | None = None
        self.n = 0
        self.mix_hash(b"")

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, self.k = hkdf2(self.ck, ikm)
        self.n = 0

    def encrypt_and_hash(self, plain: bytes) -> bytes:
        if self.k is None:
            self.mix_hash(plain)
            return plain
        out = ChaCha20Poly1305(self.k).encrypt(nonce(self.n), plain, self.h)
        self.n += 1
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, data: bytes) -> bytes:
        if self.k is None:
            self.mix_hash(data)
            return data
        out = ChaCha20Poly1305(self.k).decrypt(nonce(self.n), data, self.h)
        self.n += 1
        self.mix_hash(data)
        return out


def hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    first = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    return first, hmac.new(temp, first + b"\x02", hashlib.sha256).digest()


def nonce(n: int) -> bytes:
    return b"\x00" * 4 + n.to_bytes(8, "little")


def x25519(secret: bytes, peer: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(peer))


def x25519_public(secret: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def noise_xx_transcript() -> dict[str, str]:
    """One XX handshake and a transport message each way, bitchat's framing."""
    si, ei, sr, er = (bytes([b]) * 32 for b in (0x10, 0x20, 0x30, 0x40))
    i, r = Symmetric(), Symmetric()
    # -> e
    msg1 = x25519_public(ei)
    i.mix_hash(msg1)
    msg1 += i.encrypt_and_hash(b"")
    r.mix_hash(msg1[:32])
    r.decrypt_and_hash(b"")
    # <- e, ee, s, es
    msg2 = x25519_public(er)
    r.mix_hash(msg2)
    r.mix_key(x25519(er, msg1[:32]))
    msg2 += r.encrypt_and_hash(x25519_public(sr))
    r.mix_key(x25519(sr, msg1[:32]))
    msg2 += r.encrypt_and_hash(b"")
    i.mix_hash(msg2[:32])
    i.mix_key(x25519(ei, msg2[:32]))
    rs = i.decrypt_and_hash(msg2[32:80])
    i.mix_key(x25519(ei, rs))
    i.decrypt_and_hash(msg2[80:])
    # -> s, se
    msg3 = i.encrypt_and_hash(x25519_public(si))
    i.mix_key(x25519(si, msg2[:32]))
    msg3 += i.encrypt_and_hash(b"")
    ris = r.decrypt_and_hash(msg3[:48])
    r.mix_key(x25519(er, ris))
    r.decrypt_and_hash(msg3[48:])
    k1, k2 = hkdf2(i.ck, b"")
    assert (k1, k2) == hkdf2(r.ck, b"")
    # Transport: [nonce u32 BE][ciphertext + tag], no associated data.
    to_responder = (0).to_bytes(4, "big") + ChaCha20Poly1305(k1).encrypt(nonce(0), b"hello relay", b"")
    to_initiator = (0).to_bytes(4, "big") + ChaCha20Poly1305(k2).encrypt(nonce(0), b"hello phone", b"")
    return {
        "msg1": msg1.hex(),
        "msg2": msg2.hex(),
        "msg3": msg3.hex(),
        "to_responder": to_responder.hex(),
        "to_initiator": to_initiator.hex(),
    }


def key_from(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ota_manifests() -> dict[str, object]:
    """Manifests as docs/OTA.md defines them, and the ways a node refuses one."""
    owner = key_from(0x0A)
    stranger = key_from(0x0B)
    image = bytes(range(256)) * 9
    digest = hashlib.sha256(image).digest()

    def fields(board: bytes = b"heltec_v3", version: int = 0x010100, fmt: int = 1, magic: bytes = b"AHOT") -> bytes:
        return (
            magic
            + bytes([fmt])
            + version.to_bytes(4, "big")
            + len(image).to_bytes(4, "big")
            + digest
            + board.ljust(16, b"\0")
        )

    def signed(body: bytes, key: Ed25519PrivateKey = owner) -> bytes:
        return body + key.sign(b"airhop-fw-v1" + body)

    good = signed(fields())
    tampered = bytearray(good)
    tampered[6] ^= 0x01
    cases = [
        ("accepted", good, True),
        ("other_board", signed(fields(board=b"heltec_v4")), False),
        ("other_fleet", signed(fields(), stranger), False),
        ("field_changed_after_signing", bytes(tampered), False),
        ("unknown_format", signed(fields(fmt=2)), False),
        ("foreign_magic", signed(fields(magic=b"BOTA")), False),
        ("truncated", good[:-1], False),
    ]
    return {
        "owner": public(owner).hex(),
        "board": "heltec_v3",
        "version": 0x010100,
        "size": len(image),
        "sha256": digest.hex(),
        "cases": [{"name": n, "manifest": m.hex(), "accept": a} for n, m, a in cases],
    }


def with_flag_bits(frame: bytes, bits: int) -> bytes:
    """The frame with flag bits a re-encode never reproduces set on the wire."""
    b = bytearray(frame)
    b[11] |= bits
    return bytes(b)


def with_empty_route(frame: bytes) -> bytes:
    """A v2 broadcast given HAS_ROUTE and a route of count 0, which bitchat decodes to no route."""
    b = bytearray(frame)
    b[11] |= FLAG_ROUTE
    at = 16 + 8
    return bytes(b[:at]) + b"\x00" + bytes(b[at:])


def tlv16(t: int, v: bytes) -> bytes:
    return bytes([t]) + len(v).to_bytes(2, "big") + v


BOARD_NOW = BASE_TS + 10 * 60 * 1000
DAY_MS = 24 * 60 * 60 * 1000
HOUR_MS = 60 * 60 * 1000


def board_post(
    key: Ed25519PrivateKey,
    content: bytes = b"water at the north gate",
    geohash: bytes = b"u4pru",
    nickname: bytes = b"alice",
    created: int = BOARD_NOW - 60_000,
    expires: int = BOARD_NOW + HOUR_MS,
    flags: int = 0x01,
    kind_prefix: bytes = b"",
    extra: bytes = b"",
) -> bytes:
    """A board post as bitchat-ios lays one out: TLVs of [type u8][len u16 BE], the
    author's Ed25519 signature over a 1-byte-length-prefixed context, the post ID, the
    u16-length-prefixed geohash and content, the key, the prefixed nickname, both u64
    BE timestamps and the flags byte."""
    post_id = bytes(range(16))
    author = public(key)

    def prefixed(v: bytes) -> bytes:
        return len(v).to_bytes(2, "big") + v

    context = b"bitchat-board-v1"
    signing = (
        bytes([len(context)])
        + context
        + post_id
        + prefixed(geohash)
        + prefixed(content)
        + author
        + prefixed(nickname)
        + created.to_bytes(8, "big")
        + expires.to_bytes(8, "big")
        + bytes([flags])
    )
    return (
        kind_prefix
        + tlv16(0x01, b"\x01")
        + tlv16(0x02, post_id)
        + tlv16(0x03, geohash)
        + tlv16(0x04, content)
        + tlv16(0x05, author)
        + tlv16(0x06, nickname)
        + tlv16(0x07, created.to_bytes(8, "big"))
        + tlv16(0x08, expires.to_bytes(8, "big"))
        + tlv16(0x09, bytes([flags]))
        + tlv16(0x0A, key.sign(signing))
        + extra
    )


def board_tombstone(key: Ed25519PrivateKey, deleted: int = BOARD_NOW) -> bytes:
    """A tombstone: the author's signature over the delete context, the post ID and the u64 BE deletion time."""
    post_id = bytes(range(16))
    context = b"bitchat-board-del-v1"
    signing = bytes([len(context)]) + context + post_id + deleted.to_bytes(8, "big")
    return (
        tlv16(0x01, b"\x02")
        + tlv16(0x02, post_id)
        + tlv16(0x05, public(key))
        + tlv16(0x0B, deleted.to_bytes(8, "big"))
        + tlv16(0x0A, key.sign(signing))
    )


def flip(data: bytes, at: int) -> bytes:
    b = bytearray(data)
    b[at] ^= 0x01
    return bytes(b)


def board_cases() -> dict[str, object]:
    """Posts and tombstones a node takes or refuses before relaying one (section 3.6)."""
    alice = key_from(0x41)
    post = board_post(alice)
    tomb = board_tombstone(alice)
    cases = [
        # (name, payload, decodes and verifies, live at BOARD_NOW, urgent)
        ("post", post, True, True, True),
        ("post_not_urgent", board_post(alice, flags=0x00), True, True, False),
        ("post_mesh_local", board_post(alice, geohash=b""), True, True, True),
        ("post_unknown_tlv_skipped", board_post(alice, extra=tlv16(0x7F, b"later")), True, True, True),
        ("tombstone", tomb, True, True, False),
        ("post_content_changed", flip(post, post.index(b"water")), False, False, False),
        ("tombstone_time_changed", flip(tomb, len(tomb) - 64 - 3 - 1), False, False, False),
        (
            "post_lifetime_over_7_days",
            board_post(alice, expires=BOARD_NOW - 60_000 + 7 * DAY_MS + 1),
            False,
            False,
            False,
        ),
        ("post_expires_before_created", board_post(alice, expires=BOARD_NOW - 120_000), False, False, False),
        ("post_empty_content", board_post(alice, content=b""), False, False, False),
        ("post_content_not_utf8", board_post(alice, content=b"\xc3\x28"), False, False, False),
        ("post_geohash_outside_alphabet", board_post(alice, geohash=b"u4pra"), False, False, False),
        # A wrong-length copy refuses the post even before a valid one.
        ("post_kind_wrong_length_first", board_post(alice, kind_prefix=tlv16(0x01, b"\x01\x01")), False, False, False),
        # Verifies, but is not live: long expired, or dated over an hour ahead.
        (
            "post_expired",
            board_post(alice, created=BOARD_NOW - 2 * DAY_MS, expires=BOARD_NOW - DAY_MS),
            True,
            False,
            True,
        ),
        (
            "post_dated_ahead",
            board_post(alice, created=BOARD_NOW + 2 * HOUR_MS, expires=BOARD_NOW + 3 * HOUR_MS),
            True,
            False,
            True,
        ),
    ]
    return {
        "now": BOARD_NOW,
        "cases": [{"name": n, "payload": p.hex(), "check": c, "live": li, "urgent": u} for n, p, c, li, u in cases],
    }


def video(kind: int, body: bytes, seq: int = 1) -> bytes:
    """[stream ID 8][seq u16 BE][kind u8][body], section 3.10."""
    return bytes([0x5A]) * 8 + seq.to_bytes(2, "big") + bytes([kind]) + body


def video_start(
    width: int = 240, height: int = 320, fps: int = 12, kbps: int = 56, audio: int = 1, version: int = 1
) -> bytes:
    return video(
        0x01,
        bytes([version, 0x01])
        + width.to_bytes(2, "big")
        + height.to_bytes(2, "big")
        + bytes([fps])
        + kbps.to_bytes(2, "big")
        + bytes([audio]),
        seq=0,
    )


def entry(data: bytes, flags: int = 0x04, frag_index: int = 0, frag_count: int = 1, length: int | None = None) -> bytes:
    """[flags][unitSeq u16][ptsMs u32][fragIndex][fragCount][len u16][bytes]."""
    n = len(data) if length is None else length
    return (
        bytes([flags])
        + (7).to_bytes(2, "big")
        + (640).to_bytes(4, "big")
        + bytes([frag_index, frag_count])
        + n.to_bytes(2, "big")
        + data
    )


def video_data(entries: bytes, index: int = 0) -> bytes:
    return video(0x00, (3).to_bytes(2, "big") + bytes([index]) + entries)


def video_parity(
    symbol: bytes, parity_index: int = 0, sources: int = 4, parity: int = 2, length: int | None = None
) -> bytes:
    n = len(symbol) if length is None else length
    return video(0x03, (3).to_bytes(2, "big") + bytes([parity_index, sources, parity]) + n.to_bytes(2, "big") + symbol)


def live_cases() -> list[dict[str, object]]:
    """Voice and video payloads a node relays or refuses (sections 3.1, 3.6 and 3.10).

    A relay checks only that a voice packet carries its 11-byte header. A video packet
    must decode as bitchat-ios decodes it: START is version 1, codec 1, an even width
    and height of 16 to 1920, 1 to 60 fps, a nonzero bitrate and an audio codec of 0
    or 1; DATA has a source index under 32 and 1 or more well-formed entries (flags of
    a track 0 or 1 and the keyframe bit, a keyframe only on video, a fragment index
    under a nonzero count, a nonzero length inside the region); PARITY has 1 to 32
    sources, 1 to 16 parity shards, an index under them and a symbol of 3 or more
    bytes that its length field names exactly; END is 10 bytes, CANCELED empty; and no
    packet exceeds 352 bytes.
    """
    unit = bytes(range(1, 41))
    voice_header = bytes([0x33]) * 8 + (5).to_bytes(2, "big") + b"\x00"
    cases: list[tuple[str, str, bytes, bool]] = [
        ("voice_header_only", "voice", voice_header, True),
        ("voice_frames", "voice", voice_header + (3).to_bytes(2, "big") + b"aac", True),
        ("voice_short", "voice", voice_header[:-1], False),
        ("video_start", "video", video_start(), True),
        ("video_start_no_audio", "video", video_start(audio=0), True),
        ("video_data_keyframe", "video", video_data(entry(unit)), True),
        ("video_data_video_and_audio", "video", video_data(entry(unit) + entry(b"aac", flags=0x01)), True),
        ("video_parity", "video", video_parity(bytes(range(20))), True),
        ("video_end", "video", video(0x02, bytes(10)), True),
        ("video_canceled", "video", video(0x04, b""), True),
        ("video_start_odd_width", "video", video_start(width=241), False),
        ("video_start_too_wide", "video", video_start(width=1922), False),
        ("video_start_61_fps", "video", video_start(fps=61), False),
        ("video_start_no_bitrate", "video", video_start(kbps=0), False),
        ("video_start_unknown_audio", "video", video_start(audio=2), False),
        ("video_start_version_2", "video", video_start(version=2), False),
        ("video_start_short", "video", video_start()[:-1], False),
        ("video_data_index_32", "video", video_data(entry(unit), index=32), False),
        ("video_data_no_entries", "video", video_data(b""), False),
        ("video_data_audio_keyframe", "video", video_data(entry(unit, flags=0x05)), False),
        ("video_data_unknown_flag", "video", video_data(entry(unit, flags=0x08)), False),
        ("video_data_track_2", "video", video_data(entry(unit, flags=0x02)), False),
        ("video_data_fragment_past_count", "video", video_data(entry(unit, frag_index=2, frag_count=2)), False),
        ("video_data_no_fragments", "video", video_data(entry(unit, frag_count=0)), False),
        ("video_data_entry_overrun", "video", video_data(entry(unit, length=41)), False),
        ("video_data_empty_entry", "video", video_data(entry(b"")), False),
        ("video_data_trailing_byte", "video", video_data(entry(unit) + b"\x00"), False),
        ("video_parity_no_parity", "video", video_parity(bytes(20), parity=0), False),
        ("video_parity_index_past", "video", video_parity(bytes(20), parity_index=2), False),
        ("video_parity_33_sources", "video", video_parity(bytes(20), sources=33), False),
        ("video_parity_symbol_short", "video", video_parity(bytes(2)), False),
        ("video_parity_length_mismatch", "video", video_parity(bytes(20), length=19), False),
        ("video_end_short", "video", video(0x02, bytes(9)), False),
        ("video_canceled_with_body", "video", video(0x04, b"\x00"), False),
        ("video_unknown_kind", "video", video(0x05, b""), False),
        ("video_over_352_bytes", "video", video_data(entry(bytes(330))), False),
        ("video_header_short", "video", video(0x04, b"")[:-1], False),
    ]
    return [{"name": n, "kind": k, "payload": p.hex(), "accept": a} for n, k, p, a in cases]


def length_code(length: int) -> tuple[int, int, int]:
    """RFC 1951 section 3.2.5: a match length as (code, extra value, extra bits)."""
    if length == 258:
        return 285, 0, 0
    base = 3
    for code in range(257, 285):
        bits = 0 if code < 265 else (code - 261) // 4
        if length < base + (1 << bits):
            return code, length - base, bits
        base += 1 << bits
    raise ValueError(length)


def distance_code(distance: int) -> tuple[int, int, int]:
    """RFC 1951 section 3.2.5: a match distance as (code, extra value, extra bits)."""
    base = 1
    for code in range(30):
        bits = 0 if code < 4 else (code - 2) // 2
        if distance < base + (1 << bits):
            return code, distance - base, bits
        base += 1 << bits
    raise ValueError(distance)


class FixedBlock:
    """One final fixed-Huffman DEFLATE block (RFC 1951 section 3.2.6), symbol by symbol, so a stream can
    say what no encoder writes: a match reaching before the output, or a distance code DEFLATE leaves
    undefined."""

    def __init__(self) -> None:
        self.acc = 0
        self.n = 0
        self.bits(1, 1)  # BFINAL
        self.bits(1, 2)  # BTYPE 01: fixed Huffman

    def bits(self, value: int, count: int) -> None:
        """Values go least significant bit first (section 3.1.1)."""
        self.acc |= value << self.n
        self.n += count

    def huffman(self, code: int, length: int) -> None:
        """Huffman codes go most significant bit first (section 3.1.1)."""
        self.bits(int(format(code, f"0{length}b")[::-1], 2), length)

    def symbol(self, value: int) -> None:
        if value < 144:
            self.huffman(0x30 + value, 8)
        elif value < 256:
            self.huffman(0x190 + value - 144, 9)
        elif value < 280:
            self.huffman(value - 256, 7)
        else:
            self.huffman(0xC0 + value - 280, 8)

    def literals(self, data: bytes) -> FixedBlock:
        for b in data:
            self.symbol(b)
        return self

    def match(self, length: int, distance: int = 0, raw_distance_code: int | None = None) -> FixedBlock:
        code, extra, bits = length_code(length)
        self.symbol(code)
        self.bits(extra, bits)
        if raw_distance_code is not None:
            self.huffman(raw_distance_code, 5)
        else:
            code, extra, bits = distance_code(distance)
            self.huffman(code, 5)
            self.bits(extra, bits)
        return self

    def end(self) -> bytes:
        self.symbol(256)
        return self.acc.to_bytes((self.n + 7) // 8, "little")


def inflate_cases() -> list[dict[str, object]]:
    """Raw DEFLATE streams as a compressed payload carries them (section 2.2), each with the size it
    declares and zlib's verdict, which pako (Airhop) shares: one inflates only when zlib inflates it to
    exactly that size. A match may never reach before the stream's first byte (RFC 1951 section 3.2), so
    a decoder whose window still holds an earlier packet's output must refuse it rather than read it."""

    def wrapping() -> FixedBlock:
        # 61 bytes, then copies of them that pass 32 KiB of output mid-match, then matches reaching
        # exactly 32 KiB back: all legal, and inflated byte for byte as zlib inflates them.
        pattern = bytes((i * 151 + 7) & 0xFF for i in range(61))
        block = FixedBlock().literals(pattern)
        for _ in range(127):
            block.match(258, 61)
        return block.literals(b"end")

    cases = [
        ("match_before_any_output", FixedBlock().match(258, 32768).end(), 258),
        ("match_past_the_output", FixedBlock().literals(b"a").match(3, 2).end(), 4),
        ("undefined_distance_code", FixedBlock().literals(b"a").match(3, raw_distance_code=30).end(), 4),
        ("match_inside_the_output", FixedBlock().literals(b"a").match(258, 1).end(), 259),
        ("window_wraps", wrapping().match(258, 32768).match(258, 32768).end(), 61 + 127 * 258 + 3 + 2 * 258),
    ]
    out = []
    for name, stream, size in cases:
        d = zlib.decompressobj(wbits=-15)
        try:
            plain = d.decompress(stream) + d.flush()
            accept = d.eof and len(plain) == size
        except zlib.error:
            plain, accept = b"", False
        out.append(
            {
                "name": name,
                "stream": stream.hex(),
                "size": size,
                "accept": accept,
                "sha256": hashlib.sha256(plain).hexdigest() if accept else "",
            }
        )
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    alice = key_from(0x41)
    noise = hashlib.sha256(b"spec-noise").digest()
    sender = hashlib.sha256(noise).digest()[:8]
    recipient = bytes.fromhex("0102030405060708")
    hop = [bytes.fromhex("1111111111111111"), bytes.fromhex("2222222222222222")]
    text = ("hello mesh " * 20).encode()

    announce_tlv = (
        bytes([0x01, 5])
        + b"alice"
        + bytes([0x02, 32])
        + noise
        + bytes([0x03, 32])
        + public(alice)
        + bytes([0xB0, 4])
        + (0x010200).to_bytes(4, "big")
        + bytes([0xB1, 1, 0x01])
    )
    cases = []

    def add(name: str, ptype: int, payload: bytes, wire: Callable[[bytes], bytes] | None = None, **kw: object) -> None:
        frame, pre = signed(alice, ptype=ptype, payload=payload, sender=sender, **kw)  # type: ignore[arg-type]
        if wire is not None:
            frame = wire(frame)
        cases.append(
            {
                "name": name,
                "frame": frame.hex(),
                "preimage": pre.hex(),
                "packet_id": packet_id(ptype, sender, int(kw["ts"]), payload).hex(),  # type: ignore[arg-type]
                "public_key": public(alice).hex(),
            }
        )

    add("v1_announce_with_relay_tlvs", 0x01, announce_tlv, version=1, ttl=7, ts=BASE_TS)
    add("v2_announce_with_relay_tlvs", 0x01, announce_tlv, version=2, ttl=7, ts=BASE_TS + 1)
    add("v1_message_compressed", 0x02, text, version=1, ttl=6, ts=BASE_TS + 2, compress=True)
    add("v2_message_compressed", 0x02, text, version=2, ttl=5, ts=BASE_TS + 3, compress=True)
    add(
        "v2_directed_routed",
        0x11,
        b"\x00\x00\x00\x01" + bytes(range(40)),
        version=2,
        ttl=7,
        ts=BASE_TS + 4,
        recipient=recipient,
        route=hop,
    )
    add("v2_rsr_tagged", 0x02, b"caught up", version=2, ttl=0, ts=BASE_TS + 5, rsr=True)
    add("v1_location_channel", 0x51, b"\x05#city\x02m1\x05u4pru" + b"hi", version=1, ttl=4, ts=BASE_TS + 6)
    # Frames carrying what bitchat's decoder drops and its re-encode never
    # writes back, so none of it is in the preimage: a route flag on a v1 frame,
    # a v2 route of count 0, and flag bits 5 to 7.
    add(
        "v1_route_flag_ignored",
        0x02,
        b"hi",
        wire=lambda f: with_flag_bits(f, FLAG_ROUTE),
        version=1,
        ttl=7,
        ts=BASE_TS + 7,
    )
    add("v2_route_count_0", 0x02, b"hi", wire=with_empty_route, version=2, ttl=7, ts=BASE_TS + 8)
    add(
        "v2_undefined_flag_bits",
        0x02,
        b"hi",
        wire=lambda f: with_flag_bits(f, 0xE0),
        version=2,
        ttl=7,
        ts=BASE_TS + 9,
    )
    for c in cases:
        if c["name"].startswith("v2_directed"):
            # Noise frames are padded on air; the relay forwards the padding too.
            c["frame"] = pad(bytes.fromhex(c["frame"])).hex()

    ids = [hashlib.sha256(f"id-{i}".encode()).digest()[:16] for i in range(600)]
    gcs = []
    # The node's 400-byte budget, and a 1-byte one that still holds one ID.
    for count, max_bytes in ((0, 400), (1, 400), (5, 400), (100, 400), (355, 400), (600, 400), (1, 1), (5, 1)):
        built = gcs_build(ids[:count], max_bytes)
        gcs.append({"count": count, "max_bytes": max_bytes, "ids": [i.hex() for i in ids[:count]], **built})

    out = {
        "packets": cases,
        "gcs": gcs,
        "noise_xx": noise_xx_transcript(),
        "ota_manifest": ota_manifests(),
        "board": board_cases(),
        "live": live_cases(),
        "inflate": inflate_cases(),
    }
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
