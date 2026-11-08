# Security Policy

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through GitHub's private vulnerability reporting (the repository's **Security** tab, **Report a vulnerability**) or email [hi@areeb.dev](mailto:hi@areeb.dev).

## What to Include

- A clear description of the vulnerability
- Steps to reproduce or a proof of concept
- The firmware version and board (`status` at the console prints both)
- The affected component (`ah_proto`, `ah_mesh`, the LoRa trunk, OTA, key storage, etc.)
- Potential impact (memory corruption, signature bypass, mail delivered to the wrong phone, an image accepted unsigned, etc.)

## Response Timeline

| Stage               | Target                                    |
| ------------------- | ----------------------------------------- |
| Acknowledgment      | 48 hours                                  |
| Triage and severity | 5 business days                           |
| Critical fix        | 7 days                                    |
| High fix            | 14 days                                   |
| Public disclosure   | Coordinated with reporter after fix ships |

We will credit you in the advisory unless you prefer to stay anonymous. Only the latest release is supported; a fix ships in a new release, which nodes take over the air from a newer node of their board in Bluetooth reach ([docs/OTA.md](docs/OTA.md)); a node with none in reach keeps what it runs.

## Threat Model

- **A hostile phone or node** can send anything over Bluetooth or LoRa. LoRa frames between nodes are authenticated, so a radio cannot act for another node whose secret key it does not hold ([docs/LORA.md](docs/LORA.md)). Every parser bounds every read and is fuzzed, signature checks run within a per-second budget, every table has a fixed size and an eviction rule, the clock trusts no single source, and the node never lists the phones beside it.
- **A thief with a release-flashed board** meets Secure Boot, flash encryption with an on-chip key, encrypted settings and mailbox, secure download mode and disabled JTAG ([docs/RELEASE.md](docs/RELEASE.md)). The node's keys are generated on the board and never leave it, and the mailbox holds only end-to-end encrypted envelopes. On a locked node `lock yes` has also burned `DIS_DOWNLOAD_MODE`, so there is no serial loader to write flash with. Before the lock, secure download mode still writes flash: the thief can erase the settings (the node starts over unlocked, with a new identity) or send it back to an older signed image in its other app slot ([docs/RELEASE.md](docs/RELEASE.md), "Until the Lock"); neither reads out a key.
- **Anyone with a USB cable at an unlocked node** can set its owner key and lock it to their own fleet: provisioning is open until `lock yes`, which is part of deploying a node ([README.md](README.md)).
- **A compromised update channel** can offer any image, but a node takes one only with a manifest signed by the fleet's offline owner key, naming its board and a newer version, only after the whole image hashes correctly, and only on a rollback trial ([docs/OTA.md](docs/OTA.md)).

Logs carry packet types, lengths, short ID prefixes and counters, never keys, plaintext or envelope contents.

## In Scope

- Memory corruption or a crash from any Bluetooth or LoRa input
- Relaying a forged packet of a type the phones verify before relaying (leave, file transfer, board post, live voice and video)
- A LoRa frame acted on from a radio that does not hold the secret key of the node it names
- Noise XX handshake and session handling, and courier mail handed to the wrong peer
- OTA images or manifests accepted without the owner's signature, for another board, or as a downgrade
- Key extraction from a release-flashed board
- Moving the node's clock beyond its documented bounds
- The LoRa trunk transmitting outside its region's power or duty limits

## Out of Scope

- Denial of service by radio jamming or connection flooding (inherent to an open radio mesh)
- Attacks that need a development build, or physical access to a board that never ran a release image
- Fault injection and side-channel attacks on the chip itself
- Vulnerabilities in the Airhop or bitchat apps (report those to their own projects)
- Theoretical attacks without a proof of concept
