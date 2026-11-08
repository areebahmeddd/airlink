# Airlink: Agent Guide

> The rules and conventions for changing Airlink's code. Written for AI agents (Claude, GitHub Copilot, Codex and others), and binding on human contributors too. [`CONTRIBUTING.md`](CONTRIBUTING.md) covers the contributor workflow: setup, tests, commits and pull requests.

## What You're Working In

**Airlink** is Airhop's relay firmware, in C on ESP-IDF. It turns an ESP32-S3 or ESP32-C6 board into a fixed relay node for the [Airhop](https://github.com/areebahmeddd/airhop) app, bitchat-ios and bitchat-android. It relays their Bluetooth packets unchanged, keeps recent public messages for gossip sync, holds end-to-end encrypted courier mail, updates itself from neighboring nodes, and on boards with an SX1262 carries text between nodes over a LoRa trunk.

Airhop's `docs/spec/PROTOCOLS.md` is the specification the node implements. Where it is silent or the clients differ, bitchat-ios is the reference; bitchat-android is not authoritative. None of them is part of this repository: read them in their own checkouts, then write the conclusion in words. Shipped code and docs never cite another repository's file paths, pull requests or issue numbers.

## Read Before You Write Code

1. [`README.md`](README.md): what the node does, the boards, how to build
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the layers, the tasks and how a packet moves through the node
3. [`docs/PROTOCOL.md`](docs/PROTOCOL.md): each protocol rule the node follows, where it is implemented and its test
4. [`docs/DESIGN-REVIEW.md`](docs/DESIGN-REVIEW.md): the holes review closed, the decisions and what they set aside, and the risks kept on purpose

Then the document for the subsystem you are about to touch: [`LORA.md`](docs/LORA.md), [`OTA.md`](docs/OTA.md), [`BOARDS.md`](docs/BOARDS.md), [`MEMORY.md`](docs/MEMORY.md), [`TESTING.md`](docs/TESTING.md) or [`RELEASE.md`](docs/RELEASE.md).

## Where Things Live

| Thing                                                                                       | Location                                   |
| ------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Wire format: frames, payloads, announces, sync, courier, OTA manifests                      | `components/ah_proto/`                     |
| Ed25519, X25519, ChaCha20-Poly1305, SHA-256, randomness                                     | `components/ah_crypto/`                    |
| Noise XX                                                                                    | `components/ah_noise/`                     |
| The node: relaying, dedup, clock, peers, links, sync, mailbox, DMs                          | `components/ah_mesh/`                      |
| What may cross the LoRa trunk                                                               | `components/ah_mesh/src/ah_trunk_policy.c` |
| The LoRa trunk (pure) and its region profiles                                               | `components/ah_lora/core/`                 |
| The SX1262 driver and the LoRa task                                                         | `components/ah_lora/esp/`                  |
| The Bluetooth transport (NimBLE)                                                            | `components/ah_ble/`                       |
| Board wiring, the display and its status screen                                             | `components/ah_board/`                     |
| Boot, the mesh task, settings, mailbox storage, OTA, the console, Kconfig                   | `main/`                                    |
| Build configuration: shared, per target, per board, per profile                             | `sdkconfig.defaults*`, `config/`           |
| Flash layouts                                                                               | `partitions-*.csv`                         |
| Host tests and simulations, fuzz harnesses, on-device tests                                 | `test/host/`, `test/fuzz/`, `test/device/` |
| Test vectors: bitchat-ios's packets, Airhop's courier fixtures, the spec generator's output | `test/vectors/`                            |
| The board list, release signing, OTA and flasher manifests, vector generators, size gate    | `tools/`                                   |
| The checks, as CI runs them                                                                 | `scripts/`                                 |
| The pinned build image                                                                      | `docker/`                                  |
| The web flasher                                                                             | `flasher/`                                 |

## Rules Every Agent Must Follow

### Protocol Compatibility

- **Relay packets unchanged.** A relayed packet is the received buffer with only its TTL byte changed, never a re-encoding.
- Never change the BLE service or characteristic UUIDs, peer ID derivation (`SHA-256(noise static key)[0:8]`), or the packet layout. Phones on every client depend on them.
- Relay firmware owns only what Airhop's PROTOCOLS section 3 reserves for it: packet types `0xA0` to `0xA3` (OTA, link-local) and announce TLVs `0xB0` (firmware version) and `0xB1` (relay role). The node never emits TLV `0x04`, so it never lists the phones beside it.
- Unknown types are relayed, never dropped for being unknown.
- The LoRa trunk frame (version 1) is between nodes only, and every frame is tagged for the nodes it is for, under a key each pair of nodes shares ([`LORA.md`](docs/LORA.md)). A change to its layout bumps its version.
- A protocol change ships only after the hardware runbook's exchanges across Airhop, bitchat-ios and bitchat-android ([`TESTING.md`](docs/TESTING.md)).

### Layering

- The core (`ah_proto`, `ah_crypto`, `ah_noise`, `ah_mesh`, `ah_lora/core`) includes no ESP-IDF header and builds unchanged on the host, where every rule in it has a test. ESP-IDF appears only in `main/`, `ah_ble`, `ah_board`, `ah_lora/esp` and `ah_crypto_esp.c` ([`ARCHITECTURE.md`](docs/ARCHITECTURE.md)).
- The core allocates only in `ah_node_create`: every table has a fixed size from Kconfig and an eviction rule.
- One task owns the node: the mesh task. NimBLE's host task and the LoRa task only post events to it, and transports carry bytes, never decisions about them.
- The core reaches the device only through `ah_node_ops_t`.

### Crypto and Secrets

- Monocypher (vendored) for Ed25519, X25519 and ChaCha20-Poly1305; SHA-256 through PSA on the chip's peripheral. No other crypto library, and no primitive written here.
- Randomness from `ah_random`, which is `esp_fill_random` on the device. Never `rand()`.
- Compare secrets in constant time (Monocypher's `crypto_verify16`, `crypto_verify32`), and clear them with `ah_wipe`.
- Keys live in the settings store only (encrypted on a release build). The node holds no key it did not make.
- **Never log** a key, plaintext, or an envelope's contents. Logs carry packet types, lengths, short ID prefixes and counters.

### Radio

- There is no default LoRa region: the trunk transmits nothing until the console sets one.
- A region profile cites the rule it meets in [`LORA.md`](docs/LORA.md) before it is added, and is the strictest reading of that rule.
- Every emission is charged against the duty budget before it goes, retransmissions and acknowledgements included.

### Boards

A board is declared in `config/board.<name>` alone: its target, flash size, PSRAM, console port and the Kconfig choice for its wiring. Scripts and tools read the list from there (`tools/boards.py`); the CI and release matrices name each board, in the same order. [`BOARDS.md`](docs/BOARDS.md) says what else a new board needs.

### Pinned Artifacts

Each of these fails CI rather than drifting quietly, so a change to one is deliberate and said in its commit:

- `dependencies.lock.<target>`: ESP-IDF's version, as the component manager records it.
- `test/size-baseline.json`: image and static RAM per board. Update with `scripts/size-gate.sh <board> --write` only for growth you mean.
- `test/vectors/spec-vectors.json`: regenerated by `tools/vectors/gen_spec_vectors.py`, never edited. The other vectors are copies of their sources, refreshed, never edited.
- `docker/Dockerfile` (ESP-IDF image by digest, which the CodeQL workflow's container repeats) and `docker/requirements-dev.txt` (compiled with hashes from `requirements-dev.in`).
- `partitions-*.csv`: a deployed node is re-flashed by wire to change it.

## C Conventions

- Formatted by astyle with ESP-IDF's rules (pre-commit), 120 columns. Warnings are errors on first-party code (`cmake/ah_component.cmake`).
- Public symbols take the component's prefix (`ah_node_`, `ah_trunk_`), macros `AH_`, types end in `_t`. File-local functions and data are `static`, file-local data `s_`.
- A file is named after its primary export; a header guards with `#pragma once` and exposes only what callers use.
- One concern per module. `ah_node.c` and its `ah_node_*.c` siblings share `ah_node_priv.h`, which no other file includes.
- Fixed-width integers for anything on the wire, big-endian unless the protocol says otherwise, and every read bounded by the length checked before it.
- Time is `int64_t` milliseconds from boot, `uint64_t` for wall time. Never compare FreeRTOS ticks across a wrap.

## Python and Shell

- Python in `tools/` and `test/device/` targets 3.12 and is linted and formatted by ruff (`pyproject.toml`), 120 columns.
- Shell scripts are bash and open with `set -euo pipefail`. Each runs from the repository root, inside the tools image unless it says otherwise.
- Both start with the SPDX lines as `#` comments.

## Comments and Documentation

The bar for keeping a comment is that it says something the code cannot.

- **Why, not what.** Justify a magic number, name a platform quirk or erratum, state an invariant or an ordering rule.
- **No history.** No "previously", "now", "fixed"; the commit message holds the story.
- **`//` everywhere in C**, the SPDX lines included. Every first-party file starts with the two SPDX lines; a module's header then opens with one sentence on what it is, followed only by what a reader needs to change it safely.
- American English, no em dashes and no `--` standing in for one. Byte sizes in IEC units (`KiB`, `MiB`) when they are powers of two.
- Docs describe the system as it is, with no status or version text that goes stale, one line per paragraph.

## Checks

`scripts/check.sh` runs from the host and puts every check CI runs but coverage and CodeQL in the tools image; anything else runs there through `scripts/docker.sh '<command>'`. [`TESTING.md`](docs/TESTING.md) says what each covers.

```bash
scripts/check.sh                       # formatting, vectors, static analysis, host tests, fuzzing, every board, size gate
scripts/check.sh quick                 # the same without the board builds
scripts/docker.sh scripts/coverage.sh  # line and branch coverage of the core
```
