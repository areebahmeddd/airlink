# LoRa board wiring

The LoRa trunk (see [README](../README.md#lora-backhaul)) runs on ESP32-S3
boards with a Semtech SX1262 radio. The radio architecture is identical
across supported boards — TCXO on DIO3 at 1.8 V, DIO2 as the TX/RX RF
switch — so only the pin map and the power gate differ. Both are selected
at build time via Kconfig; no source edits are needed.

The SX1262 is probed at boot (scratch-register check). If the selected
wiring doesn't match the hardware, the probe simply finds no radio and the
node runs BLE-only — a misconfigured board cannot crash the firmware.

## Supported boards

| | Seeed XIAO ESP32-S3 + Wio-SX1262 (default) | Heltec WiFi LoRa 32 V3 / Wireless Stick Lite V3 |
|---|---|---|
| Kconfig symbol | `CONFIG_BITLE_LORA_BOARD_XIAO_WIO_SX1262` | `CONFIG_BITLE_LORA_BOARD_HELTEC_V3` |
| SCK | 7 | 9 |
| MISO | 8 | 11 |
| MOSI | 9 | 10 |
| CS/NSS | 41 | 8 |
| RESET | 42 | 12 |
| BUSY | 40 | 13 |
| DIO1 | 39 | 14 |
| RXEN | 38 | — (DIO2 switches RX/TX) |
| Vext power gate | — | 36 (active-high, powered at boot) |

Heltec pinout source: the MeshCore `heltec_v3` board variant. Both Heltec
V3 models share the same radio wiring; the WiFi LoRa 32's OLED is unused.

**Vext.** Heltec boards gate the radio (and OLED) behind a switchable
peripheral rail. The SX1262 is inert — no SPI response — until Vext is on.
`CONFIG_BITLE_LORA_VEXT_PIN` (default 36 for Heltec, -1 otherwise) is
driven active-high at boot before the radio probe, with a 20 ms settle
delay.

## Switching boards

With menuconfig (interactive):

```bash
idf.py set-target esp32s3
idf.py menuconfig   # → Bitle hardware → SX1262 board wiring → Heltec V3
idf.py build flash
```

Non-interactively, append to `sdkconfig.defaults` (or
`sdkconfig.defaults.esp32s3`) **before** the first build:

```kconfig
CONFIG_BITLE_LORA_BOARD_HELTEC_V3=y
```

On an already-configured build tree, `sdkconfig` takes precedence: set the
symbol there (and clear `CONFIG_BITLE_LORA_BOARD_XIAO_WIO_SX1262`), then
`idf.py reconfigure build`.

## Porting a new board

1. Add a `config BITLE_LORA_BOARD_<NAME>` entry to the choice in
   `main/Kconfig.projbuild`. If the board gates radio power, also add a
   `default <gpio> if BITLE_LORA_BOARD_<NAME>` line to
   `CONFIG_BITLE_LORA_VEXT_PIN` (active-high; extend the code if a board
   needs active-low).
2. Add the matching `#elif CONFIG_BITLE_LORA_BOARD_<NAME>` pin block in
   `main/bitle_lora.c`. Set `LORA_PIN_RXEN` to -1 when the board has no
   GPIO-driven RX-enable (DIO2-as-RF-switch designs).
3. Verify: build, flash, and check the boot log for
   `bitle_lora: trunk up: ...` (success) vs `no SX1262 radio; running
   BLE-only` (wrong pins or power gate).
