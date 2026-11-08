# Airlink

<p>
  <a href="https://github.com/areebahmeddd/airlink/releases"><img src="https://img.shields.io/github/v/release/areebahmeddd/airlink?style=flat-square" alt="release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="license" /></a>
  <a href="https://github.com/espressif/esp-idf/releases/tag/v6.1"><img src="https://img.shields.io/badge/ESP--IDF-v6.1-red?style=flat-square" alt="ESP-IDF" /></a>
  <a href="https://github.com/areebahmeddd/airlink/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/areebahmeddd/airlink/ci.yml?style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://codecov.io/gh/areebahmeddd/airlink"><img src="https://img.shields.io/codecov/c/github/areebahmeddd/airlink?style=flat-square" alt="coverage" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/areebahmeddd/airlink"><img src="https://api.securityscorecards.dev/projects/github.com/areebahmeddd/airlink/badge?style=flat-square" alt="OpenSSF Scorecard" /></a>
</p>

Relay node firmware for [Airhop](https://github.com/areebahmeddd/airhop), [bitchat-ios](https://github.com/permissionlesstech/bitchat) and [bitchat-android](https://github.com/permissionlesstech/bitchat-android). It turns an ESP32 board into a fixed node in a Bluetooth mesh of phones and forwards their packets unchanged and unread, so two phones out of each other's range still reach each other. A board with an SX1262 LoRa radio also links to another node kilometers away, with no phone in between.

It implements the bitchat protocol as Airhop's specification defines it ([docs/PROTOCOL.md](docs/PROTOCOL.md)). It cannot read the messages it carries, holds no key but its own, and does not advertise which phones are near it.

Read the [Airlink whitepaper](https://github.com/areebahmeddd/airhop/blob/main/docs/paper/airlink/airlink-whitepaper.pdf) for the full design.

## What It Does

| Feature    | Description                                                                                                                                                                                                                              |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Relay      | Forwards each packet once to every neighbor, with the same TTL and timing rules the phones use, and keeps live voice and video on time                                                                                                   |
| LoRa link  | Carries text between nodes kilometers apart, authenticated between each pair of nodes, sent to all neighbors in one transmission, acknowledged and retried, within each region's power and airtime limits ([docs/LORA.md](docs/LORA.md)) |
| Catch-up   | Keeps recent public, location channel, group and board messages, and sends a phone what it missed while away                                                                                                                             |
| Mailbox    | Holds end-to-end encrypted mail for a phone that is away, across reboots, and hands it over once that phone proves who it is                                                                                                             |
| Updates    | Takes a newer firmware image from a neighboring node, signed with the fleet's key, and keeps the old one until the new one runs ([docs/OTA.md](docs/OTA.md))                                                                             |
| In the app | Airhop lists the node as equipment, with a radio tower icon and no Message or Send ecash action; a bitchat user who messages it gets a reply saying it is a relay                                                                        |

## Boards

| Board                               | Chip     | LoRa   | Display | PSRAM |
| ----------------------------------- | -------- | ------ | ------- | ----- |
| Heltec WiFi LoRa 32 V4              | ESP32-S3 | SX1262 | OLED    | 2 MiB |
| Heltec WiFi LoRa 32 V4-R8           | ESP32-S3 | SX1262 | OLED    | 8 MiB |
| Heltec WiFi LoRa 32 V3              | ESP32-S3 | SX1262 | OLED    | None  |
| LilyGO T-Beam Supreme               | ESP32-S3 | SX1262 | OLED    | 8 MiB |
| Seeed XIAO ESP32-S3 with Wio-SX1262 | ESP32-S3 | SX1262 | None    | 8 MiB |
| ESP32-C6-DevKitC-1                  | ESP32-C6 | None   | None    | None  |
| Seeed XIAO ESP32-C6                 | ESP32-C6 | None   | None    | None  |

**Recommendation:** use the Heltec V4 for LoRa nodes, the V4 or the V4-R8 as its chip says (ESP32-S3R2 or ESP32-S3R8): each takes its own image. Its front end transmits up to 28 dBm where the region allows it, and its PSRAM holds the full tables; a board without PSRAM runs smaller ones and keeps less history and mail ([docs/MEMORY.md](docs/MEMORY.md)). Pin maps and per-board notes are in [docs/BOARDS.md](docs/BOARDS.md).

## Getting Started

1. **Flash** it from the [web flasher](https://areebahmeddd.github.io/airlink) in Chrome or Edge, or build it yourself (below). A board flashed from the web flasher then takes only signed updates, over the air ([docs/RELEASE.md](docs/RELEASE.md)).
2. **Set the LoRa region** at the serial console (115200 baud). The node does not transmit on LoRa until a region is set, since no single setting is legal everywhere:

   ```text
   region eu
   reboot
   status
   ```

   The regions are `us`, `eu`, `in`, `anz` and `sea`; [docs/LORA.md](docs/LORA.md) gives the rule behind each.

3. **Optionally** name it (`nickname relay-west`).
4. **Provision and lock it before it leaves your hands.** Give it the fleet's update key with the fingerprint the key tool printed for it (`owner <key> <fingerprint>`, [docs/OTA.md](docs/OTA.md); the web flasher gives the project's own), check `status`, then `lock yes`, which cannot be undone, and `reboot`. Until it is locked, anyone with a USB cable can set their own update key and lock the node to it.

## Building and Testing

Everything builds in one pinned Docker image with ESP-IDF and the host tools, so a build comes out the same on every machine:

```bash
scripts/docker.sh 'scripts/build.sh heltec_v4 dev'   # one board, in the dev or release profile
scripts/check.sh                                     # the checks CI runs
```

With ESP-IDF v6.1 installed locally, `scripts/build.sh heltec_v4 dev flash monitor` builds, flashes and opens the console. The protocol core is plain C with no ESP-IDF dependency, so its tests, simulations and fuzzers run on the host under AddressSanitizer and UndefinedBehaviorSanitizer ([docs/TESTING.md](docs/TESTING.md)). Releases, signing and the one-time eFuse changes a release image makes are in [docs/RELEASE.md](docs/RELEASE.md). To contribute, start with [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

| Document                                  | What it covers                                                               |
| ----------------------------------------- | ---------------------------------------------------------------------------- |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md)   | The layers, the tasks, how a packet moves through the node and what persists |
| [PROTOCOL.md](docs/PROTOCOL.md)           | Each protocol rule the node follows, where it is implemented and its test    |
| [LORA.md](docs/LORA.md)                   | The LoRa link layer, airtime and the region profiles with their rules        |
| [OTA.md](docs/OTA.md)                     | Node-to-node updates: the keys, the packets and publishing an update         |
| [BOARDS.md](docs/BOARDS.md)               | Pin maps, RF paths, per-board notes and adding a board                       |
| [MEMORY.md](docs/MEMORY.md)               | Flash layout, flash wear and the RAM tables per board                        |
| [TESTING.md](docs/TESTING.md)             | The host checks, the on-device tests and the hardware test plan              |
| [RELEASE.md](docs/RELEASE.md)             | Cutting a release, the two signing keys and what a release image burns in    |
| [DESIGN-REVIEW.md](docs/DESIGN-REVIEW.md) | What review found, the decisions taken and the risks kept on purpose         |
| [CONTRIBUTING.md](CONTRIBUTING.md)        | Setting up, testing, commits and pull requests                               |
| [AGENTS.md](AGENTS.md)                    | The rules and conventions for changing the code                              |

## Acknowledgments

- Forked from [Bitle](https://github.com/bitleproject/bitle) by Mark Soares, with the LoRa trunk frame, its reliability state machine and the Heltec V3 support by [callebtc](https://github.com/callebtc), and the optional LE Coded PHY link between nodes by [SHLOK333](https://github.com/SHLOK333), which this builds on.
- [bitchat](https://github.com/permissionlesstech/bitchat), public domain: the protocol, and the vectors the codec is tested against.
- [Monocypher](https://monocypher.org) and [miniz](https://github.com/richgel999/miniz), vendored with their licenses.
- The [Meshtastic](https://meshtastic.org) board variants, for cross-checking pin maps and the Heltec V4 front end.
