# Memory and Flash

Where the node keeps what, in flash and in RAM, and what a board without PSRAM gives up.

## Flash Layout

Two tables, chosen by the board (`partitions-8mb.csv`, `partitions-4mb.csv`). The table sits at `0x10000` (`CONFIG_PARTITION_TABLE_OFFSET`) so a release bootloader, with Secure Boot and flash encryption, fits before it. **Changing the layout means re-flashing every node by wire: it is settled before the first deployment.**

| Partition  | 8 MiB layout        | 4 MiB layout        | What it holds                                                                                                                                           |
| ---------- | ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nvs`      | `0x11000`, 28 KiB   | `0x11000`, 28 KiB   | Identity keys, nickname, region, owner key, provisioning lock, clock floor, OTA manifests, the refused version, radio calibration, the LoRa duty ledger |
| `otadata`  | `0x18000`, 8 KiB    | `0x18000`, 8 KiB    | Which app slot boots, and the rollback trial's state                                                                                                    |
| `manifest` | `0x1a000`, 4 KiB    | `0x1a000`, 4 KiB    | The signed OTA manifest flashed beside a wired image ([OTA.md](OTA.md))                                                                                 |
| `nvs_keys` | `0x1b000`, 4 KiB    | `0x1b000`, 4 KiB    | The NVS encryption keys of a release build, generated on its first boot                                                                                 |
| `ota_0`    | `0x20000`, 3 MiB    | `0x20000`, 1.5 MiB  | App slot                                                                                                                                                |
| `ota_1`    | `0x320000`, 3 MiB   | `0x1a0000`, 1.5 MiB | App slot                                                                                                                                                |
| `mailbox`  | `0x620000`, 1.8 MiB | `0x320000`, 832 KiB | Courier envelopes, an NVS partition of its own                                                                                                          |
| `coredump` | `0x7f0000`, 64 KiB  | `0x3f0000`, 64 KiB  | The last crash, read with the console's `crash`; encrypted on a release build, since task stacks can hold session keys                                  |

Each app slot leaves the image room to grow several times over; `test/size-baseline.json` records the current sizes, and CI holds every change to them. The Heltec V4's 16 MiB of flash takes the 8 MiB layout, so its upper 8 MiB is unused.

In a release build both NVS partitions are encrypted with keys the node generates on its first boot into `nvs_keys`, which flash encryption covers (`CONFIG_NVS_SEC_KEY_PROTECT_USING_FLASH_ENC`). The HMAC scheme is not used: its eFuse key must be burned before Secure Boot disables read protection on first boot, and a board flashed from the browser has no step for that.

### Flash Wear

The mailbox writes one NVS entry per envelope, writes it again when its spray budget changes, and erases it when it leaves, so its wear follows deposits. NVS fills its 4 KiB pages in turn (126 entries of 32 bytes each) and erases one when it reclaims it, copying out what that page still holds; the flash is rated for 100,000 erases a page. At 1,000 deposits a day of 2 KiB envelopes, each written back twice as its budget is sprayed (6 MiB a day), each page of the 8 MiB layout's 1.8 MiB partition is erased about four times a day, which lasts about 70 years.

Nothing else bounds the deposit rate: at 50 KiB a second, about what one phone can write over Bluetooth, that partition would wear out in five weeks, and the 4 MiB layout's 832 KiB one in under three. So the mailbox writes at most `AH_MAIL_FLASH_KIB_PER_HOUR` in an hour, each record charged its envelope plus 128 bytes for NVS's own entries, and refuses deposits past it, and each depositor its quota's share of that hour (64 KiB with PSRAM, 128 KiB without), so one identity whose mail leaves as fast as it comes cannot spend the hour for everyone. Without pause at the defaults, 1 MiB an hour lasts about 17 years on the 8 MiB layout (464 pages of 4,032 bytes, 100,000 erases each, less the copying of up to 256 KiB of mail held), and the compact set's 256 KiB an hour over 30 years on the 4 MiB layout's 208 pages.

The settings partition sees the clock floor every 10 minutes (144 small writes a day, about one page filled a day, some 34 page erases a month across its pages) and, on a LoRa node, the duty ledger's copy (244 bytes) as the trunk starts and each time the airtime that copy lacks reaches a sixty-first of the budget: at most 61 writes an hour while the trunk sends all it may, and one more for each boot. Even at that rate it fills about 116 pages a day, about 19 erases a day for each of the partition's six working pages, which lasts about 14 years; a trunk that is mostly quiet writes a small part of that.

## RAM

The node allocates every table once, at boot, and never again. Tables of 4 KiB or more go to PSRAM where the board has it (`ah_app.c`). Kconfig sets each table's size, with two sets of defaults chosen by `CONFIG_SPIRAM`:

| Table                                                 | With PSRAM                                         | Without PSRAM                                                       | Each      |
| ----------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------- | --------- |
| Inflater window                                       | 32 KiB (any payload)                               | 4 KiB (payloads that decode to 4 KiB or less)                       |           |
| Frame buffers                                         | 256                                                | 24                                                                  | 518 bytes |
| Peers                                                 | 256                                                | 32                                                                  | 112 bytes |
| Signing keys kept for peers given up                  | 1024                                               | 256                                                                 | 16 bytes  |
| Message, fragment, live dedup slots                   | 4096, 8192, 16384                                  | 1024, 1024, 1024                                                    | 8 bytes   |
| Sync stores: announces, messages, groups, board posts | 256, 512, 128, 256 entries in 64, 256, 64, 128 KiB | 12, 32, 8, 12 entries in 3, 8, 2, 3 KiB                             |           |
| Courier envelopes                                     | 64 in 256 KiB                                      | 4 in 8 KiB                                                          |           |
| Largest packet reassembled or sent in fragments       | 17 KiB, 4 at once                                  | 4 KiB, 1 at once                                                    |           |
| **Node tables in all**                                | **1.39 MiB, nearly all in PSRAM**                  | **118 KiB (C6) to 123 KiB (S3, with its LoRa links), internal RAM** |           |

Measured on the host from the allocator (`ah_node_create` with each default set). What the compact set gives up:

- **Dedup.** 1024 slots hold 512 IDs per class over the window: a message every 0.6 s for 5 minutes, a video stream for 21 s. Past that a repeat may be forwarded once more; nothing is lost.
- **Pins.** A departed peer's signing key is kept until 256 more peers have been given up, rather than 1024, so its identity is that much cheaper to flood out of reach before someone else claims it ([PROTOCOL.md](PROTOCOL.md)).
- **Inflate.** A compressed packet that decodes to more than 4 KiB is refused and counted. One Bluetooth frame holds at most 467 bytes of payload, so that needs better than 8 to 1 compression, which text does not reach.
- **Mail.** Envelopes up to about 4 KiB (any text DM), four in all and two from any one depositor; a larger one, or a third, is refused, and its sender carries it itself.
- **Sync.** A late phone catches up on the last 32 public messages rather than 512.

Outside the tables, and counted in that heap: NVS keeps about 84 bytes of internal RAM for each flash page (39.6 KiB on the 8 MiB layout, 18.1 KiB on the 4 MiB one), the mailbox holds one blob buffer (4 KiB, or 17 KiB with PSRAM, internal either way), and the event queue takes about 520 bytes an event (8 KiB, or 16 KiB with PSRAM).

The heap left after boot is logged (`node ready: heap ... free`) and `status` at the console shows it, with its low point since boot. Measure the compact set's headroom on the board before deploying it: with NimBLE's six connections, the task stacks and the event queue, about 30 to 50 KiB should remain. Should it run short, lower `AH_FRAME_BUFFERS` or the sync stores first.

CI fails a change that grows static internal RAM by more than 1 KiB, or the image by more than 2 % (at least 8 KiB), against `test/size-baseline.json`, unless the same change updates the baseline deliberately.
