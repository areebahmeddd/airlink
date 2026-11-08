# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-08

The first release, v1.0.0: a relay node for the Airhop mesh, with a LoRa link between nodes.

### Added

- **Relay:** each packet forwarded once per neighbor, unchanged but for its TTL, under the phones' own TTL, jitter and priority rules, with signatures checked before relaying wherever the phones check them ([docs/PROTOCOL.md](docs/PROTOCOL.md)).
- **LoRa link:** neighbor nodes as mesh links carrying text, every frame tagged for the nodes it is for under a key each pair shares from X25519 between their static keys, a flood sent once to every neighbor with their answers in turn and answers held to a third of the budget, selective-repeat ARQ, a duty budget kept across resets and charged before every emission, and region profiles for the US, the EU, India, Australia and New Zealand, and Southeast Asia, with no default region ([docs/LORA.md](docs/LORA.md)).
- **Catch-up:** gossip sync of public, location channel, group and board messages for phones that were away; a reply that fails against its author's known key is dropped rather than declined, so a forged copy never hides the genuine message; sync is answered over Bluetooth only.
- **Mailbox:** end-to-end encrypted courier mail held across reboots and handed only to the phone that proves it is the recipient, within an hourly flash budget.
- **Updates:** node-to-node OTA with a per-fleet owner key, board-named manifests and a rollback trial that only a fault, or three power cuts or restarts, turns into a refusal, link-local so phones never carry it ([docs/OTA.md](docs/OTA.md)).
- **Clock:** wall time from the phones in reach, one vote per phone, slewed rather than stepped once confirmed, with a saved floor that never runs ahead of real time and that phones agreeing behind it overrule; mail expires only once two phones agree.
- **Hardening:** per-link shares of signature checks and inflation, signing keys pinned after a peer leaves the table, and a cap on what unverified LoRa neighbors can cost.
- **Security:** Secure Boot, flash and settings encryption on release builds, and a provisioning lock that also closes the serial loader ([docs/RELEASE.md](docs/RELEASE.md)).
- **Boards:** the Heltec WiFi LoRa 32 V4, V4-R8 and V3, the LilyGO T-Beam Supreme, the Seeed XIAO ESP32-S3 with Wio-SX1262, and two ESP32-C6 boards for Bluetooth-only nodes ([docs/BOARDS.md](docs/BOARDS.md)).
- **Tooling:** a serial console for status, provisioning and crash reports, a web flasher, host tests under ASan and UBSan, fuzzing, spec-derived vectors, on-device tests, CI with size gates, CodeQL and Scorecard, and reproducible release builds with SBOMs and build provenance ([docs/TESTING.md](docs/TESTING.md)).
