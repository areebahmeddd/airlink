# Boards

One build per board: `scripts/build.sh <board> [dev|release]`. The profile in `components/ah_board/src/ah_board.c` holds the wiring; `config/board.<board>` sets its target, flash size, PSRAM and console port. Pin maps follow each vendor's schematic as the boards' Meshtastic variants encode them, cross-checked against the vendors' own libraries where they publish one.

[TESTING.md](TESTING.md) lists what to confirm on each board before deploying it.

## Tier 1: ESP32-S3 with an SX1262

| Board                               | Build           | Flash, PSRAM        | Radio (SCK, MISO, MOSI, NSS, RESET, BUSY, DIO1) | RF path                                           | Display                     | Console         |
| ----------------------------------- | --------------- | ------------------- | ----------------------------------------------- | ------------------------------------------------- | --------------------------- | --------------- |
| Heltec WiFi LoRa 32 V4              | `heltec_v4`     | 16 MiB, 2 MiB quad  | 9, 11, 10, 8, 12, 13, 14                        | DIO2 switch, TCXO 1.8 V, front end (below)        | SSD1306 on 17, 18, reset 21 | USB Serial/JTAG |
| Heltec WiFi LoRa 32 V4-R8           | `heltec_v4_r8`  | 16 MiB, 8 MiB octal | 9, 11, 10, 8, 12, 13, 14                        | DIO2 switch, TCXO 1.8 V, KCT8103L front end       | SSD1306 on 17, 18, reset 21 | USB Serial/JTAG |
| Heltec WiFi LoRa 32 V3              | `heltec_v3`     | 8 MiB, none         | 9, 11, 10, 8, 12, 13, 14                        | DIO2 switch, TCXO 1.8 V                           | SSD1306 on 17, 18, reset 21 | UART (CP2102)   |
| LilyGO T-Beam Supreme               | `tbeam_supreme` | 8 MiB, 8 MiB quad   | 12, 13, 11, 10, 5, 4, 1                         | DIO2 switch, TCXO 1.8 V, radio powered by the PMU | SH1106 on 17, 18            | USB Serial/JTAG |
| Seeed XIAO ESP32-S3 with Wio-SX1262 | `xiao_s3_wio`   | 8 MiB, 8 MiB octal  | 7, 8, 9, 41, 42, 40, 39                         | DIO2 switch, RXEN 38, TCXO 1.8 V                  | none                        | USB Serial/JTAG |

- **Heltec V4.** A front-end module sits after the SX1262: V4.2 boards carry a GC1109, V4.3 boards a KCT8103L. Both are powered from GPIO7 and enabled on GPIO2; read as an input first, GPIO2 is high on a KCT8103L board and low on a GC1109 one, which is how the firmware tells them apart (as Meshtastic does). The front end is powered only while the trunk runs: at boot just long enough to tell which it is, then again when a provisioned region starts the radio. The transmit path is GPIO46 (GC1109) or GPIO5 (KCT8103L), high while transmitting. The front end adds 7 to 13 dB depending on drive (Heltec's measured tables, in the profile), for 28 dBm at most; the SX1262 is never driven above 21 dBm into it, and the power the region allows is converted to the SX1262 setting through the table, rounding down.
- **Heltec V4-R8.** The V4 with an ESP32-S3R8, whose 8 MiB of octal PSRAM takes GPIO33 to GPIO37: Vext moves to GPIO40, the front end is the KCT8103L alone (transmit path on GPIO5; GPIO46 is the LED and never driven), and the build runs the PSRAM in octal mode. The other pins are the V4's (Heltec's pin change list for the R8). Each takes its own image: one built for the other never starts its app, and on a release image the first boot has already burned its eFuses, so read the chip's marking (ESP32-S3R2 or ESP32-S3R8) before flashing. Vext's polarity on GPIO40 is taken to be the V4's, active low; confirm it on the bench (the OLED lights).
- **Heltec V3.** Vext (GPIO36) powers the OLED, switched on by driving it low, as Heltec's library and the Meshtastic variant both do (`AH_BOARD_VEXT_ACTIVE_LOW`). The radio is powered directly. No PSRAM, so the node runs the compact tables ([MEMORY.md](MEMORY.md)). The battery divider's control pin changes polarity between board revisions, so battery sensing is not used.
- **T-Beam Supreme.** The AXP2101 PMU (I2C at 0x34 on SDA 42, SCL 41) feeds the display from ALDO1, the sensors from ALDO2 and the SX1262 from ALDO3, each set to 3.3 V and switched on at boot. Charging is left at the PMU's defaults; check it charges with no thermistor fitted before a solar deployment.
- **XIAO ESP32-S3 with Wio-SX1262.** RXEN (GPIO38) is high while receiving. No display, no battery divider.

## Tier 2: ESP32-C6, Bluetooth Only

| Board               | Build       | Flash                        | Notes                                                                                                            | Console         |
| ------------------- | ----------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------- |
| ESP32-C6-DevKitC-1  | `c6_devkit` | 8 MiB                        | button on GPIO9                                                                                                  | UART bridge     |
| Seeed XIAO ESP32-C6 | `xiao_c6`   | 4 MiB (`partitions-4mb.csv`) | GPIO3 low powers the RF switch; GPIO14 picks the antenna (`AH_BOARD_XIAO_C6_EXTERNAL_ANTENNA` for the U.FL port) | USB Serial/JTAG |

The C6 was chosen over the C5 for its 512 KiB of SRAM against 384 KiB, and over the C3 for headroom: a Bluetooth relay node needs RAM more than anything else here. Neither C6 board has PSRAM, so both run the compact tables.

## Adding a Board

Add a choice to `AH_BOARD` in `main/Kconfig.projbuild` (its prompt is the name the flasher shows), its profile to `ah_board.c`, and `config/board.<name>` with the board's target, flash size and Kconfig choice; `tools/boards.py` then lists it for the scripts, the OTA tool and the flasher. Add it to the matrices in `.github/workflows/ci.yml` and `release.yml` and to the board tables in the README and here, in the place its Kconfig choice takes (the recommended LoRa boards first, Bluetooth-only last), and record its baseline with `scripts/size-gate.sh <name> --write`. A board on a new target also needs that target's chip family in `tools/flasher_manifests.py`, and its first build writes `dependencies.lock.<target>`. The name is at most 16 characters, since OTA manifests carry it.
