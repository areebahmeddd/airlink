# Architecture

How the firmware is put together: the layers, the tasks and what each owns, the path a packet takes through the node, boot, power, and what survives a reboot.

## Layers

```text
main/            boot, the mesh task, settings, mailbox storage, OTA, the console
  │
  ├── ah_ble          the GATT service for phones and the central that dials nodes  ┐
  ├── ah_board        board wiring, the OLED and its status screen                   ├ device
  ├── ah_lora/esp     the SX1262 driver and the LoRa task                            ┘
  │
  ├── ah_mesh         the node: relaying, dedup, clock, peers, sync, mailbox, DMs    ┐
  ├── ah_lora/core    the trunk link layer and the region profiles                   │
  ├── ah_noise        Noise XX                                                       ├ core, host-tested
  ├── ah_proto        the wire format                                                │
  └── ah_crypto       Monocypher, with SHA-256 and randomness from the chip          ┘
```

The core (`ah_proto`, `ah_noise`, `ah_mesh`, `ah_lora/core`, and `ah_crypto` but for its SHA-256 and random source) is plain C23 with no ESP-IDF header. It builds unchanged on the host, where the tests, simulations and fuzzers run it under the sanitizers; on the device the same sources take SHA-256 from ESP-IDF's PSA Crypto, on the chip's SHA peripheral, and randomness from `esp_fill_random`. Everything that touches hardware or the RTOS lives in `main/`, `ah_ble`, `ah_board` and `ah_lora/esp`, and carries bytes: no decision about a packet is made outside the core.

The core reaches the device through one table of callbacks, `ah_node_ops_t`: write a frame to a link, store or delete an envelope, save the clock floor, allocate a table. Everything it allocates, it allocates once, in `ah_node_create`, sized by Kconfig ([MEMORY.md](MEMORY.md)).

## Tasks

| Task        | Core on the S3 | Priority  | Owns                                                                                |
| ----------- | -------------- | --------- | ----------------------------------------------------------------------------------- |
| NimBLE host | 0              | ESP-IDF's | The GATT server for phones and the central that dials nodes; posts events           |
| `lora`      | 0              | 6         | The SX1262 and the trunk: pieces, answers, pair keys and tags, duty budget, beacons |
| `mesh`      | 1              | 5         | The node, the OTA state, the status snapshot; the only caller of the core           |
| `display`   | either         | 2         | The OLED, drawn from the snapshot                                                   |
| console     | either         | ESP-IDF's | The serial console, reading the snapshot and writing settings                       |

The ESP32-C6 runs them all on its one core. The core is single-threaded by contract: transports never call into it from their own callbacks, they post an event to the mesh task's queue and return. Link up, link down, MTU and ready events wait up to 50 ms for a slot; frames take a slot only while four stay free for those. More than four of those during a longer stall can still be lost, so once a second the mesh task checks its Bluetooth links against the transport's own connection table and opens, closes or wakes any link a lost event left wrong.

The mesh task handles events for at most 250 ms before it runs its timers and feeds the task watchdog (10 s), and sleeps one tick a second so the idle task on its core, which the watchdog also watches, always runs. A pass is then at most those 250 ms, one event and one tick. The heaviest event is a few Ed25519 checks, a mailbox write of up to 17 KiB, at most one hash of the running image (about a second, once per new manifest for it), or the last piece of an update, which finishes its hash and has ESP-IDF verify the whole image twice before it can boot; the heaviest tick spends the verify budget (`AH_VERIFY_PER_SECOND`). Monocypher's check takes about 4.9 M cycles on the original ESP32's Xtensa LX6 (Banegas et al., "Quantum-Resistant Security for Software Updates on Low-power Networked Embedded Devices", 2021, Table 5), so about 30 ms at the S3's 160 MHz, and the S3's default budget of 8 costs about 0.25 s, or 0.5 s where two of its one-second windows meet (the C6's 13, at about 19 ms each on a RISC-V core, Table 6, the same): a pass comes to about 2.5 s. These chips' own check and flash write times are unmeasured, so `status` shows the longest pass since boot, which is what to check on a board ([TESTING.md](TESTING.md), S13).

## A Frame's Path

1. **In.** A phone writes to the characteristic, or a node notifies one the node dialed; NimBLE's callback copies the frame into an event. A LoRa frame comes reassembled from the trunk, acknowledged, as one bitchat packet.
2. **Decode.** The mesh task decodes the header and payload bounds, drops what is malformed (counted), and looks the packet ID up in its dedup set; a repeat stops here.
3. **Relay.** The relay policy decides whether the packet goes further, at what TTL and after what jitter, as the phones decide ([PROTOCOL.md](PROTOCOL.md)). The types phones verify before relaying are verified here too, within a per-second budget of which each link is held a share. A relayed copy is the received buffer with its TTL byte changed, queued on every other link by priority, and on each LoRa neighbor when the trunk policy allows the type. Announces go first and live media is dropped once stale; anything else still unsent after 10 s (5 minutes on a LoRa link, which waits on its duty budget) is dropped, and a busy link never holds more than a quarter of the frame buffers.
4. **Act.** Separately from relaying, and only for a packet inside the freshness window once the clock is synced (an announce, once it is confirmed): an announce updates the peer table and the clock; courier mail is taken or handed over; a handshake or DM to the node gets its receipt and one reply.
A sync request takes its own path before any of this: answered from the stores, whatever its time, when it comes at TTL 0 from the link's own peer and is signed by it ([PROTOCOL.md](PROTOCOL.md), "Gossip Sync").
5. **Out.** Each tick drains the link queues into the transports. A BLE link that refuses a write is retried every 10 ms, except a phone that has not yet subscribed, whose subscription wakes it; the trunk reports when it can take more.

## Boot

1. Power management: frequency scaling between 80 MHz and the default CPU clock.
2. Storage: the settings store and the mailbox. An unreadable settings store is erased and the node starts over with a new identity; an unreadable mailbox leaves mail in RAM only. A factory reset asked for at the console runs here, before any task that could write again has started.
3. Settings: the identity (generated on first boot), nickname, region, owner key, provisioning lock and clock floor.
4. The board: power rails (Vext, a T-Beam Supreme's PMU rails) and, on a Heltec V4, which front end it carries. A LoRa front end stays off until the trunk starts.
5. OTA: whether this boot is a rollback trial, and the manifest for the running image.
6. The mesh task's event queue, then the LoRa task when the board has a radio and a region is set, then the mesh task itself: the node's tables, with the mailbox restored into them.
7. NimBLE: advertising for phones and a periodic scan for nodes.
8. The display and the console.

Nothing the node originates that a phone would time-check (its announce included) goes out until its clock syncs: from the phones around it, or, while no phone is in reach, from other nodes' announces. Time from nodes alone, or from one phone, never expires mail, prunes the gossip stores or moves the saved clock floor; that waits for two phones that agree. Until they do, the floor restored at boot plus the node's uptime is a time real time is surely past: mail expires by it and the floor saved climbs by it, so it never rests on a phone's word. A floor saved from a confirmed time is never later than the restored one plus the time since, except at a node's first boot, which has none to measure from. Relaying needs no clock and starts immediately.

## Power

A relay has to listen, so both radios stay on: Bluetooth advertises every 160 ms and scans for other nodes for 3 s a minute, and the SX1262 receives continuously, which costs it a few milliamps. What can rest does:

- The CPU scales between 80 MHz and its default clock. The mesh task holds it at full speed only while it handles events and runs its timers, and lets it drop before it waits.
- The display turns off 30 s after boot or a button press (`AH_DISPLAY_ON_S`).
- A Heltec V4's LoRa front end is powered only while the trunk runs.

Bluetooth controller sleep and automatic light sleep are left off until measured on hardware ([TESTING.md](TESTING.md), S16): light sleep would need a wake source on the radio's interrupt line and would drop console input.

## What Survives a Reboot

| Kept in flash                                                 | Kept in RAM only                                   |
| ------------------------------------------------------------- | -------------------------------------------------- |
| Identity keys, nickname, region, owner key, provisioning lock | Peers, links, dedup sets, Noise sessions           |
| The clock floor, every 10 minutes; the duty ledger            | The gossip sync stores: a reboot starts them empty |
| Courier envelopes, one NVS entry each                         | The trunk's neighbors and transfers                |
| Each slot's OTA manifest, the trial state, a refused version  | Counters, reset at boot                            |

A release build encrypts both NVS partitions and flash; see [MEMORY.md](MEMORY.md) for the layout and [RELEASE.md](RELEASE.md) for the keys.
