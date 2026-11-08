# Over-the-Air Updates

Airlink nodes (Airhop's relay firmware) update each other: a node running a newer image offers it to a neighbor node running an older one, and the neighbor pulls it over Bluetooth, checks it, and boots it on trial. One wired node updates a fleet. This page covers the trust model, the keys, the packets and how to cut an update.

## Trust Model

Two keys at two layers, kept apart and both offline ([RELEASE.md](RELEASE.md)):

- **The Secure Boot key** (release builds): the chip's ROM checks the bootloader and the bootloader checks the app against it on every boot. It decides what the chip will run at all.
- **The fleet's owner key** (Ed25519): a node checks an image's signed manifest against it before taking a single byte of the image. It decides which updates a fleet accepts from the mesh.

The owner key is per fleet and provisioned per node (`owner <key> <fingerprint>` at the console, write-once), not compiled in. A node with no owner key neither serves nor accepts updates. Until a node is locked (`lock yes`), anyone at its console can set the key, so provisioning and locking it are part of deploying it.

A node:

- accepts a manifest only if the owner key signed it and it names this node's board;
- checks at most one manifest per link every 10 s, since each costs a signature check before anything else about it is known;
- takes only a strictly newer version: never a downgrade, never the same version again, and never a version at or below one it rolled back from, which it keeps in NVS, since the bootloader's own record of the rollback is erased when the next transfer starts;
- writes the image as it arrives and checks its SHA-256 whole against the manifest before it can boot it; ESP-IDF then checks the image itself (and its Secure Boot signature on a release build);
- boots the new image on a rollback trial. The trial ends once the image has run 15 minutes (`AH_OTA_TRIAL_MIN`, long enough to reach what an image fails at a few minutes in: the first clock save, mail write, beacon and sync rounds) and a neighbor's announce has verified over a live link, or after 30 minutes up without a crash (`AH_OTA_TRIAL_FALLBACK_MIN`), so a node alone at a site keeps the image through its next power cut. A crash before then boots the previous image, and an image on trial is never offered to other nodes, so one that fails rolls back before it spreads. A trial ended by a fault (a panic or a watchdog) refuses that version for good; one ended by a power cut, a brownout or a restart says nothing of the image, and the version is tried at most three times in all. An image fetched whole and then refused (its hash, or ESP-IDF's checks), or a transfer given up as too slow (a server that drops the link early included), is not fetched again from the node that served it for an hour; another node's copy is taken. The node remembers one such server at a time, so a hostile node that keeps minting identities can hold an update back a minute or so per identity, each costing it a fresh verified announce.

With the trial and no offers while on it, each hop takes about 20 minutes (the trial, the next offer and a transfer of a few minutes), so an update crosses ten hops in three hours or more.

Anti-rollback (release builds) adds a floor the bootloader enforces from eFuse; raising it is a deliberate release step.

## Link-Local, Never Through Phones

Phones relay packet types they do not know, so an OTA packet with any TTL to spare would flood through every phone in range. OTA packets therefore:

- carry TTL 0 and are addressed to the one neighbor they are for;
- go only on a Bluetooth link to a peer whose verified announce marks it a node (`0xB1` bit 0);
- are taken only from such a link, from the peer bound to it, and never enter the mesh.

They never cross the LoRa trunk: an image would take days of a region's duty budget. Airhop's PROTOCOLS section 3 reserves `0xA0` to `0xA3`, `0xB0` and `0xB1` for relay firmware so Airhop never allocates them.

## Packets

| Type   | Name     | From     | Payload                                                         |
| ------ | -------- | -------- | --------------------------------------------------------------- |
| `0xA0` | MANIFEST | server   | the 125-byte signed manifest                                    |
| `0xA1` | REQUEST  | receiver | `version(4) offset(4) length(2)`                                |
| `0xA2` | CHUNK    | server   | `version(4) offset(4) data`                                     |
| `0xA3` | STATUS   | receiver | `code(1)`: `00` applied, `E1` hash mismatch, `E2` flash refused |

Integers are big-endian. The receiver asks for each piece in turn, sized to fit its link (at most 472 bytes: what a 512-byte Bluetooth frame holds after the packet's header and both IDs and the piece's own 8 bytes), and asks again after 4 s without an answer; the transfer ends at the 41st unanswered request in a row, or once it has run a minute and moves slower than 512 bytes a second, and a piece of any size but the one asked for is ignored, so no server can trickle a transfer out for hours. So a server answers with exactly the size asked, never less, and every later version has to as well. An offer goes to a neighbor at most once a minute, when its announce (`0xB0`) shows an older version.

Manifest (`components/ah_proto/src/ah_ota_manifest.c`):

```text
"AHOT" format(1)=1 version(4) size(4) sha256(32) board(16, NUL-padded) | signature(64)
```

`version` is `major << 16 | minor << 8 | patch`, as the announce carries it. The Ed25519 signature covers `"airhop-fw-v1"` followed by every byte before it.

## One-Time Setup

```bash
python3 tools/ota_manifest.py keygen ~/airlink-keys      # owner_key.pem, and the line that provisions a node
python3 tools/ota_manifest.py provision --key ~/airlink-keys/owner_key.pem   # that line again, later
```

Keep `owner_key.pem` offline and backed up: losing it ends updates for the fleet, and leaking it lets anyone push images to it. On each node, at its serial console, before it is deployed:

```text
owner <the 64-digit public key> <its 16-digit fingerprint>
status
lock yes
reboot
```

The key is written once, so the node takes it only with the fingerprint the tool printed: a mistyped key has another fingerprint and is refused. `status` shows the fingerprint set; `lock yes` then closes provisioning for good, and `reboot` applies both.

## Cutting an Update

1. Raise `PROJECT_VER` in `CMakeLists.txt` and move the changelog's Unreleased section under the new version ([RELEASE.md](RELEASE.md) cuts a project release end to end).
2. Build the board's image (`scripts/build.sh <board> release`, or `dev` for a development fleet).
3. Sign its manifest: `python3 tools/ota_manifest.py sign --key owner_key.pem --board <board> airlink.bin` (`tools/release_sign.sh` does this, and the Secure Boot signing, for a release).

## Seeding the First Node

Flash the image by wire (`scripts/build.sh <board> <profile> flash`, or the web flasher, whose release images carry their manifest already), then write its manifest beside it, in the `manifest` partition:

```bash
esptool write-flash 0x1a000 airlink.bin.ahot
```

The node checks the manifest against its own running image at boot and serves it from then on. A node that received its image over the air keeps the manifest it came with and serves it too, so the update spreads node to node. Each app slot's manifest is kept apart, so a node that rolls back still serves the image it returned to.

Updates travel only over Bluetooth, between nodes of the same board: a node with no newer node of its board in Bluetooth reach (alone at its site, or a LoRa repeater kilometers from the next) never updates, and a release board takes no wired image either. Plan a fleet with that in mind: seed each site, and keep a fresh, never-booted board of each model to seed each release, since a release board once booted cannot be flashed by wire.

Sign development and release images with different owner keys. A manifest names its board and version but not its profile, so under one key a release node would fetch a development image only to have Secure Boot refuse it, and a development node would take a release image whose app refuses to run without flash encryption, roll back on a fault, and then refuse that version and every one below it.
