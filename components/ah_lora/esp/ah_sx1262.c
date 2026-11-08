// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The SX1262's command sequences: setup for the region's channel, receive,
// channel activity detection, transmit, and recovery from a fault.
#include "ah_sx1262.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ah_sx1262";

// Command and register numbers are the datasheet's chapter 13; the errata
// worked around below are its chapter 15.
#define OP_GET_STATUS 0xC0
#define OP_GET_PACKET_TYPE 0x11
#define OP_SET_STANDBY 0x80
#define OP_SET_TX 0x83
#define OP_SET_RX 0x82
#define OP_SET_CAD 0xC5
#define OP_SET_PACKET_TYPE 0x8A
#define OP_SET_RF_FREQUENCY 0x86
#define OP_SET_PA_CONFIG 0x95
#define OP_SET_TX_PARAMS 0x8E
#define OP_SET_BUFFER_BASE 0x8F
#define OP_SET_MODULATION 0x8B
#define OP_SET_PACKET_PARAMS 0x8C
#define OP_SET_CAD_PARAMS 0x88
#define OP_SET_DIO_IRQ 0x08
#define OP_GET_IRQ_STATUS 0x12
#define OP_CLEAR_IRQ 0x02
#define OP_SET_DIO2_RF_SWITCH 0x9D
#define OP_SET_DIO3_TCXO 0x97
#define OP_SET_REGULATOR 0x96
#define OP_SET_FALLBACK 0x93
#define OP_CALIBRATE 0x89
#define OP_CALIBRATE_IMAGE 0x98
#define OP_GET_DEVICE_ERRORS 0x17
#define OP_CLEAR_DEVICE_ERRORS 0x07
#define OP_WRITE_REGISTER 0x0D
#define OP_READ_REGISTER 0x1D
#define OP_WRITE_BUFFER 0x0E
#define OP_READ_BUFFER 0x1E
#define OP_GET_RX_BUFFER_STATUS 0x13
#define OP_GET_PACKET_STATUS 0x14

#define IRQ_TX_DONE (1u << 0)
#define IRQ_RX_DONE (1u << 1)
#define IRQ_HEADER_VALID (1u << 4)
#define IRQ_HEADER_ERR (1u << 5)
#define IRQ_CRC_ERR (1u << 6)
#define IRQ_CAD_DONE (1u << 7)
#define IRQ_CAD_DETECTED (1u << 8)
#define IRQ_TIMEOUT (1u << 9)
#define IRQ_ALL 0x03FFu
// The causes that raise DIO1. HEADER_VALID is latched for ah_sx1262_cad and
// ah_sx1262_transmit to read, never raised: a frame in flight is no event.
// PREAMBLE_DETECTED is left out: noise latches it, and nothing would clear it
// until the next frame, so it would hold off transmissions for nothing.
#define IRQ_EVENTS \
    (IRQ_TX_DONE | IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR | IRQ_CAD_DONE | IRQ_CAD_DETECTED | IRQ_TIMEOUT)
#define IRQ_FRAME_END (IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR)

#define REG_IQ_POLARITY 0x0736
#define REG_LORA_SYNC 0x0740
#define REG_TX_MODULATION 0x0889
#define REG_RX_GAIN 0x08AC
#define REG_TX_CLAMP 0x08D8
#define REG_OCP 0x08E7

#define STANDBY_RC 0x00
#define STANDBY_XOSC 0x01
#define FALLBACK_STANDBY_XOSC 0x30
#define RX_GAIN_BOOSTED 0x96
// SetPaConfig sets this for the SX1262 anyway: 140 mA in 2.5 mA steps. It is
// written and read back so a marginal SPI bus shows at boot, not on air.
#define OCP_140_MA 0x38
// Command status in bits 3:1 of the status byte, chip mode in bits 6:4
// (datasheet table 13-76).
#define STATUS_COMMAND(s) (((s) >> 1) & 0x07u)
#define STATUS_PROCESSING_ERROR 0x4u
#define STATUS_EXECUTE_FAILED 0x5u
#define STATUS_MODE(s) (((s) >> 4) & 0x07u)
#define MODE_RX 0x5u
#define PACKET_TYPE_LORA 0x01

// BUSY falls within about 100 us for most commands, within a few ms after
// calibration or a TCXO start. Spin briefly, then yield.
#define BUSY_SPIN_US 200
#define BUSY_TIMEOUT_MS 40
#define RECOVERY_ATTEMPTS 2
#define TX_MARGIN_MIN_MS 500u
#define TX_MARGIN_PERCENT 25u
#define TX_WATCHDOG_EXTRA_MS 1000u
// SetTx and SetRx timeouts count 15.625 us units in 24 bits.
#define TIMEOUT_UNITS_MAX 0xFFFFFFu
// The TCXO's start-up allowance on DIO3: 5 ms in 15.625 us steps.
#define TCXO_STARTUP_UNITS 320u
#define DETECT_PROBE 0xA7

static spi_device_handle_t s_spi;
static ah_sx1262_config_t s_cfg;
static bool s_ready;
static int8_t s_power = INT8_MIN;
// When a latched HEADER_VALID was first seen without its frame's end; 0 none.
static int64_t s_header_seen_us;
// Driver-owned DMA buffers: the LoRa task is the only caller.
static DMA_ATTR uint8_t s_tx[AH_SX1262_FRAME_MAX + 4];
static DMA_ATTR uint8_t s_rx[AH_SX1262_FRAME_MAX + 4];

static esp_err_t busy_wait(void)
{
    for (int us = 0; us < BUSY_SPIN_US; us += 5) {
        if (gpio_get_level(s_cfg.pin_busy) == 0) {
            return ESP_OK;
        }
        esp_rom_delay_us(5);
    }
    const int64_t deadline = esp_timer_get_time() + BUSY_TIMEOUT_MS * 1000LL;
    while (gpio_get_level(s_cfg.pin_busy) != 0) {
        if (esp_timer_get_time() > deadline) {
            return ESP_ERR_TIMEOUT;
        }
        vTaskDelay(1);
    }
    return ESP_OK;
}

// One SPI transaction of `len` bytes from s_tx, the answer in s_rx.
static esp_err_t xfer(size_t len)
{
    ESP_RETURN_ON_ERROR(busy_wait(), TAG, "busy");
    spi_transaction_t t = {.length = len * 8, .tx_buffer = s_tx, .rx_buffer = s_rx};
    return spi_device_polling_transmit(s_spi, &t);
}

static esp_err_t cmd(uint8_t op, const uint8_t *args, size_t n)
{
    s_tx[0] = op;
    if (n > 0) {
        memcpy(s_tx + 1, args, n);
    }
    return xfer(n + 1);
}

// A command answering `n` bytes after its status byte.
static esp_err_t cmd_read(uint8_t op, uint8_t *out, size_t n)
{
    memset(s_tx, 0, n + 2);
    s_tx[0] = op;
    ESP_RETURN_ON_ERROR(xfer(n + 2), TAG, "read 0x%02x", op);
    memcpy(out, s_rx + 2, n);
    return ESP_OK;
}

static esp_err_t write_reg(uint16_t address, const uint8_t *data, size_t n)
{
    s_tx[0] = OP_WRITE_REGISTER;
    s_tx[1] = (uint8_t)(address >> 8);
    s_tx[2] = (uint8_t)address;
    memcpy(s_tx + 3, data, n);
    return xfer(n + 3);
}

static esp_err_t read_reg(uint16_t address, uint8_t *data, size_t n)
{
    memset(s_tx, 0, n + 4);
    s_tx[0] = OP_READ_REGISTER;
    s_tx[1] = (uint8_t)(address >> 8);
    s_tx[2] = (uint8_t)address;
    ESP_RETURN_ON_ERROR(xfer(n + 4), TAG, "read reg");
    memcpy(data, s_rx + 4, n);
    return ESP_OK;
}

static esp_err_t write_verify(uint16_t address, const uint8_t *data, size_t n)
{
    uint8_t back[4] = {0};
    ESP_RETURN_ON_ERROR(write_reg(address, data, n), TAG, "write reg");
    ESP_RETURN_ON_ERROR(read_reg(address, back, n), TAG, "read back");
    if (memcmp(back, data, n) != 0) {
        ESP_LOGE(TAG, "register 0x%04x did not take its value", address);
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

static esp_err_t update_reg(uint16_t address, uint8_t clear, uint8_t set)
{
    uint8_t v = 0;
    ESP_RETURN_ON_ERROR(read_reg(address, &v, 1), TAG, "read reg");
    v = (uint8_t)((v & ~clear) | set);
    return write_reg(address, &v, 1);
}

// STDBY_RC for calibration, which needs it; STDBY_XOSC before a transmission
// or a channel check, which keeps the TCXO running.
static esp_err_t standby(uint8_t mode)
{
    return cmd(OP_SET_STANDBY, &mode, 1);
}

static esp_err_t clear_irq(uint16_t bits)
{
    const uint8_t clear[2] = {(uint8_t)(bits >> 8), (uint8_t)bits};
    return cmd(OP_CLEAR_IRQ, clear, sizeof(clear));
}

static esp_err_t chip_reset(void)
{
    ESP_RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_reset, 0), TAG, "reset low");
    // Datasheet 8.1 asks for over 100 us low; a tick-based wait this short is
    // zero ticks at 100 Hz.
    esp_rom_delay_us(200);
    ESP_RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_reset, 1), TAG, "reset high");
    vTaskDelay(pdMS_TO_TICKS(10));
    return busy_wait();
}

// The frequency synthesizer's image rejection is calibrated per band
// (datasheet table 9-2); a frequency outside every band has no calibration.
static bool image_band(uint32_t hz, uint8_t out[2])
{
    static const struct {
        uint32_t lo_mhz;
        uint32_t hi_mhz;
        uint8_t f1;
        uint8_t f2;
    } bands[] = {
        {430, 440, 0x6B, 0x6F}, {470, 510, 0x75, 0x81}, {779, 787, 0xC1, 0xC5},
        {863, 870, 0xD7, 0xDB}, {902, 928, 0xE1, 0xE9},
    };
    for (size_t i = 0; i < sizeof(bands) / sizeof(bands[0]); ++i) {
        if (hz >= bands[i].lo_mhz * 1000000u && hz <= bands[i].hi_mhz * 1000000u) {
            out[0] = bands[i].f1;
            out[1] = bands[i].f2;
            return true;
        }
    }
    return false;
}

// SetDIO3AsTCXOCtrl voltage codes (datasheet table 13-35).
static bool tcxo_code(uint16_t mv, uint8_t *code)
{
    static const uint16_t steps[] = {1600, 1700, 1800, 2200, 2400, 2700, 3000, 3300};
    for (uint8_t i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i) {
        if (steps[i] == mv) {
            *code = i;
            return true;
        }
    }
    return false;
}

static uint8_t bandwidth_code(uint32_t hz)
{
    return hz == 500000u ? 0x06 : hz == 250000u ? 0x05 : 0x04;
}

// The airtime plus the larger of a fixed and a proportional margin.
static uint32_t tx_timeout_ms(size_t len)
{
    const uint32_t airtime = ah_lora_airtime_ms(&s_cfg.phy, (uint16_t)len);
    const uint32_t share = (airtime * TX_MARGIN_PERCENT + 99u) / 100u;
    return airtime + (share > TX_MARGIN_MIN_MS ? share : TX_MARGIN_MIN_MS);
}

static esp_err_t set_packet_params(size_t payload_len)
{
    const uint8_t p[6] = {
        (uint8_t)(s_cfg.phy.preamble_symbols >> 8), (uint8_t)s_cfg.phy.preamble_symbols,
        0x00,                 // explicit header
        (uint8_t)payload_len, // the most to receive, or the length to send
        0x01,                 // CRC on
        0x00,                 // standard IQ
    };
    ESP_RETURN_ON_ERROR(cmd(OP_SET_PACKET_PARAMS, p, sizeof(p)), TAG, "packet params");
    // Erratum 15.4: with standard IQ, bit 2 of the IQ register must be set.
    return update_reg(REG_IQ_POLARITY, 0, 0x04);
}

static esp_err_t check_device(const char *stage)
{
    uint8_t status = 0;
    uint8_t errors[2] = {0};
    // GetStatus answers only the status byte, which comes right after the opcode.
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_STATUS, &status, 0), TAG, "status");
    status = s_rx[1];
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_DEVICE_ERRORS, errors, sizeof(errors)), TAG, "errors");
    const uint16_t err = (uint16_t)((errors[0] << 8) | errors[1]);
    const uint8_t command = STATUS_COMMAND(status);
    if (err != 0 || command == STATUS_PROCESSING_ERROR || command == STATUS_EXECUTE_FAILED) {
        // Calibration, oscillator or PLL lock failures: a wrong TCXO voltage
        // or a damaged part; the radio cannot run as configured.
        ESP_LOGE(TAG, "%s: device errors 0x%04x, status 0x%02x", stage, err, status);
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

// A radio that reset on its own (a brownout or a spike on its rail) is back
// in STDBY_RC as it powers up: no packet type of ours, every IRQ masked so no
// interrupt ever comes, and a sync word that still reads as ours, since
// 0x1424 is the register's reset value. Its packet type is what tells.
static esp_err_t still_configured(void)
{
    uint8_t type = 0;
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_PACKET_TYPE, &type, 1), TAG, "packet type");
    if (type != PACKET_TYPE_LORA) {
        ESP_LOGE(TAG, "radio lost its setup (packet type 0x%02x)", type);
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

static esp_err_t configure(void)
{
    uint8_t image[2];
    if (!image_band(s_cfg.frequency_hz, image)) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_RETURN_ON_ERROR(standby(STANDBY_RC), TAG, "standby");
    const uint8_t dcdc = 0x01;
    ESP_RETURN_ON_ERROR(cmd(OP_SET_REGULATOR, &dcdc, 1), TAG, "regulator");
    if (s_cfg.tcxo_mv != 0) {
        uint8_t code = 0;
        if (!tcxo_code(s_cfg.tcxo_mv, &code)) {
            return ESP_ERR_INVALID_ARG;
        }
        const uint8_t tcxo[4] = {code, (uint8_t)(TCXO_STARTUP_UNITS >> 16), (uint8_t)(TCXO_STARTUP_UNITS >> 8),
                                 (uint8_t)TCXO_STARTUP_UNITS
                                };
        ESP_RETURN_ON_ERROR(cmd(OP_SET_DIO3_TCXO, tcxo, sizeof(tcxo)), TAG, "tcxo");
        // The oscillator start error latched at power-up, before DIO3 fed the
        // TCXO, means nothing; clear it so the check below sees fresh state.
        const uint8_t zero[2] = {0, 0};
        ESP_RETURN_ON_ERROR(cmd(OP_CLEAR_DEVICE_ERRORS, zero, sizeof(zero)), TAG, "clear errors");
    }
    // A TCXO invalidates the calibration done at power-up: redo all of it,
    // then the image for this band.
    const uint8_t all = 0x7F;
    ESP_RETURN_ON_ERROR(cmd(OP_CALIBRATE, &all, 1), TAG, "calibrate");
    ESP_RETURN_ON_ERROR(cmd(OP_CALIBRATE_IMAGE, image, sizeof(image)), TAG, "image");
    ESP_RETURN_ON_ERROR(busy_wait(), TAG, "calibration");
    ESP_RETURN_ON_ERROR(check_device("calibration"), TAG, "calibration");

    if (s_cfg.dio2_rf_switch) {
        const uint8_t on = 0x01;
        ESP_RETURN_ON_ERROR(cmd(OP_SET_DIO2_RF_SWITCH, &on, 1), TAG, "rf switch");
    }
    // Fall back to STDBY_XOSC after TX and RX, so the TCXO keeps running and
    // the turnaround to an answer skips its 5 ms start. A channel check still
    // ends in STDBY_RC (CAD_ONLY, datasheet 13.4.7).
    const uint8_t fallback = FALLBACK_STANDBY_XOSC;
    ESP_RETURN_ON_ERROR(cmd(OP_SET_FALLBACK, &fallback, 1), TAG, "fallback");
    const uint8_t lora = 0x01;
    ESP_RETURN_ON_ERROR(cmd(OP_SET_PACKET_TYPE, &lora, 1), TAG, "packet type");
    const uint32_t frf = (uint32_t)(((uint64_t)s_cfg.frequency_hz << 25) / 32000000u);
    const uint8_t freq[4] = {(uint8_t)(frf >> 24), (uint8_t)(frf >> 16), (uint8_t)(frf >> 8), (uint8_t)frf};
    ESP_RETURN_ON_ERROR(cmd(OP_SET_RF_FREQUENCY, freq, sizeof(freq)), TAG, "frequency");

    // The +22 dBm PA setting (datasheet table 13-21), used for every power:
    // SetTxParams then sets the level, as the datasheet allows.
    const uint8_t pa[4] = {0x04, 0x07, 0x00, 0x01};
    ESP_RETURN_ON_ERROR(cmd(OP_SET_PA_CONFIG, pa, sizeof(pa)), TAG, "pa");
    const uint8_t ocp = OCP_140_MA;
    ESP_RETURN_ON_ERROR(write_verify(REG_OCP, &ocp, 1), TAG, "ocp");
    // Erratum 15.2: clamp the PA harder against an antenna mismatch.
    ESP_RETURN_ON_ERROR(update_reg(REG_TX_CLAMP, 0, 0x1E), TAG, "tx clamp");
    s_power = INT8_MIN;

    const uint8_t base[2] = {0x00, 0x00};
    ESP_RETURN_ON_ERROR(cmd(OP_SET_BUFFER_BASE, base, sizeof(base)), TAG, "buffer base");
    const uint8_t mod[4] = {s_cfg.phy.spreading_factor, bandwidth_code(s_cfg.phy.bandwidth_hz),
                            (uint8_t)(s_cfg.phy.coding_rate - 4u), ah_lora_low_data_rate(&s_cfg.phy) ? 0x01 : 0x00
                           };
    ESP_RETURN_ON_ERROR(cmd(OP_SET_MODULATION, mod, sizeof(mod)), TAG, "modulation");
    const uint8_t sync[2] = {(uint8_t)(s_cfg.sync_word >> 8), (uint8_t)s_cfg.sync_word};
    ESP_RETURN_ON_ERROR(write_verify(REG_LORA_SYNC, sync, sizeof(sync)), TAG, "sync word");
    // About 2 dB more sensitivity for about 2 mA more in receive.
    const uint8_t gain = RX_GAIN_BOOSTED;
    ESP_RETURN_ON_ERROR(write_verify(REG_RX_GAIN, &gain, 1), TAG, "rx gain");

    const uint16_t mask = IRQ_EVENTS | IRQ_HEADER_VALID;
    const uint8_t irq[8] = {(uint8_t)(mask >> 8), (uint8_t)mask, (uint8_t)(IRQ_EVENTS >> 8), (uint8_t)IRQ_EVENTS,
                            0, 0, 0, 0
                           };
    ESP_RETURN_ON_ERROR(cmd(OP_SET_DIO_IRQ, irq, sizeof(irq)), TAG, "irq");
    ESP_RETURN_ON_ERROR(clear_irq(IRQ_ALL), TAG, "clear irq");
    s_header_seen_us = 0;
    // CAD over 4 symbols with the peak and minimum the datasheet recommends
    // for 4 symbols (table 13-73: SF + 13 and 10). AN1200.48's thresholds are
    // equal or higher, so this errs toward finding the channel busy.
    const uint8_t cad[7] = {0x02, (uint8_t)(s_cfg.phy.spreading_factor + 13u), 10, 0x00, 0, 0, 0};
    ESP_RETURN_ON_ERROR(cmd(OP_SET_CAD_PARAMS, cad, sizeof(cad)), TAG, "cad");
    return check_device("configuration");
}

// The antenna path for receiving or transmitting, where the board switches
// it from GPIOs rather than DIO2 alone.
static esp_err_t path(bool transmit)
{
    if (s_cfg.pin_rxen >= 0) {
        ESP_RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_rxen, transmit ? 0 : 1), TAG, "rxen");
    }
    if (s_cfg.pin_txen >= 0) {
        ESP_RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_txen, transmit ? 1 : 0), TAG, "txen");
    }
    return ESP_OK;
}

static esp_err_t listen(void)
{
    ESP_RETURN_ON_ERROR(path(false), TAG, "path");
    ESP_RETURN_ON_ERROR(set_packet_params(AH_SX1262_FRAME_MAX), TAG, "rx params");
    // A header latched before this reception began belongs to no frame now.
    ESP_RETURN_ON_ERROR(clear_irq(IRQ_HEADER_VALID), TAG, "clear header");
    s_header_seen_us = 0;
    const uint8_t continuous[3] = {0xFF, 0xFF, 0xFF};
    return cmd(OP_SET_RX, continuous, sizeof(continuous));
}

// Whether leaving receive now would destroy a frame: one whose header the
// modem accepted and whose end has not come, or one that has ended and whose
// event the task has not yet taken (a transmission would overwrite it in the
// buffer). A header older than any frame lasts is one the modem never
// finished, and is forgotten.
static esp_err_t receiving(bool *busy)
{
    *busy = false;
    uint8_t status[2] = {0};
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_IRQ_STATUS, status, sizeof(status)), TAG, "irq status");
    const uint16_t irq = (uint16_t)((status[0] << 8) | status[1]);
    if (irq & IRQ_FRAME_END) {
        *busy = true;
        return ESP_OK;
    }
    if ((irq & IRQ_HEADER_VALID) == 0) {
        s_header_seen_us = 0;
        return ESP_OK;
    }
    const int64_t now = esp_timer_get_time();
    if (s_header_seen_us == 0) {
        s_header_seen_us = now;
    }
    if (now - s_header_seen_us > (int64_t)ah_lora_airtime_ms(&s_cfg.phy, AH_SX1262_FRAME_MAX) * 1000) {
        s_header_seen_us = 0;
        return clear_irq(IRQ_HEADER_VALID);
    }
    *busy = true;
    return ESP_OK;
}

static esp_err_t bus_init(const ah_sx1262_config_t *cfg)
{
    const gpio_config_t out = {
        .pin_bit_mask = (1ULL << cfg->pin_reset) | (cfg->pin_rxen >= 0 ? 1ULL << cfg->pin_rxen : 0) |
        (cfg->pin_txen >= 0 ? 1ULL << cfg->pin_txen : 0),
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&out), TAG, "outputs");
    ESP_RETURN_ON_ERROR(gpio_set_level(cfg->pin_reset, 1), TAG, "reset");
    // BUSY pulled low: with no radio fitted it reads ready, and the detect
    // probe then fails on its read-back instead of timing out.
    const gpio_config_t in = {
        .pin_bit_mask = (1ULL << cfg->pin_busy) | (1ULL << cfg->pin_dio1),
        .mode = GPIO_MODE_INPUT,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&in), TAG, "inputs");
    if (s_spi != NULL) {
        return ESP_OK;
    }
    const spi_bus_config_t bus = {
        .sclk_io_num = cfg->pin_sck,
        .miso_io_num = cfg->pin_miso,
        .mosi_io_num = cfg->pin_mosi,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = sizeof(s_tx),
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO), TAG, "spi bus");
    // 8 MHz: well under the chip's 16 MHz, and margin for long board traces.
    const spi_device_interface_config_t dev = {
        .clock_speed_hz = 8 * 1000 * 1000,
        .mode = 0,
        .spics_io_num = cfg->pin_nss,
        .queue_size = 1,
    };
    return spi_bus_add_device(SPI2_HOST, &dev, &s_spi);
}

static bool present(void)
{
    // A scratch write and read-back of the sync word register: a real SX126x
    // echoes it; an empty footprint does not. configure() rewrites it.
    const uint8_t probe = DETECT_PROBE;
    uint8_t back = 0;
    return write_reg(REG_LORA_SYNC, &probe, 1) == ESP_OK && read_reg(REG_LORA_SYNC, &back, 1) == ESP_OK &&
           back == probe;
}

static bool config_valid(const ah_sx1262_config_t *cfg)
{
    uint8_t image[2];
    return cfg->pin_sck >= 0 && cfg->pin_miso >= 0 && cfg->pin_mosi >= 0 && cfg->pin_nss >= 0 &&
           cfg->pin_reset >= 0 && cfg->pin_busy >= 0 && cfg->pin_dio1 >= 0 && ah_lora_phy_valid(&cfg->phy) &&
           image_band(cfg->frequency_hz, image);
}

esp_err_t ah_sx1262_init(const ah_sx1262_config_t *cfg, void (*dio1_isr)(void *arg), void *arg)
{
    ESP_RETURN_ON_FALSE(config_valid(cfg), ESP_ERR_INVALID_ARG, TAG, "configuration");
    s_cfg = *cfg;
    s_ready = false;
    ESP_RETURN_ON_ERROR(bus_init(cfg), TAG, "bus");
    ESP_RETURN_ON_ERROR(chip_reset(), TAG, "reset");
    if (!present()) {
        return ESP_ERR_NOT_FOUND;
    }
    ESP_RETURN_ON_ERROR(configure(), TAG, "configure");
    // Not an IRAM handler: it may wait out a flash write (an OTA, the
    // mailbox), and DIO1 stays high until the cause is cleared, so the edge
    // is taken late rather than lost.
    const esp_err_t svc = gpio_install_isr_service(0);
    ESP_RETURN_ON_FALSE(svc == ESP_OK || svc == ESP_ERR_INVALID_STATE, svc, TAG, "isr service");
    ESP_RETURN_ON_ERROR(gpio_set_intr_type(cfg->pin_dio1, GPIO_INTR_POSEDGE), TAG, "dio1");
    ESP_RETURN_ON_ERROR(gpio_isr_handler_add(cfg->pin_dio1, dio1_isr, arg), TAG, "dio1 handler");
    ESP_RETURN_ON_ERROR(gpio_intr_enable(cfg->pin_dio1), TAG, "dio1 enable");
    s_ready = true;
    const esp_err_t err = listen();
    s_ready = err == ESP_OK;
    return err;
}

esp_err_t ah_sx1262_recover(void)
{
    s_ready = false;
    esp_err_t err = ESP_FAIL;
    for (int attempt = 0; attempt < RECOVERY_ATTEMPTS && err != ESP_OK; ++attempt) {
        err = chip_reset();
        if (err == ESP_OK) {
            err = configure();
        }
        if (err == ESP_OK) {
            err = listen();
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "recovery failed: %s", esp_err_to_name(err));
        return err;
    }
    s_ready = true;
    ESP_LOGW(TAG, "radio recovered");
    return ESP_OK;
}

ah_sx1262_event_t ah_sx1262_poll(void)
{
    if (!s_ready) {
        return AH_SX1262_EVENT_NONE;
    }
    uint8_t status[2] = {0};
    if (cmd_read(OP_GET_IRQ_STATUS, status, sizeof(status)) != ESP_OK) {
        return AH_SX1262_EVENT_ERROR;
    }
    const uint16_t irq = (uint16_t)(((status[0] << 8) | status[1]) & IRQ_EVENTS);
    if (irq == 0) {
        return AH_SX1262_EVENT_NONE;
    }
    // A frame's end clears the header it latched; a header in flight stays.
    const uint16_t clear = (irq & IRQ_FRAME_END) ? (uint16_t)(irq | IRQ_HEADER_VALID) : irq;
    if (clear_irq(clear) != ESP_OK) {
        return AH_SX1262_EVENT_ERROR;
    }
    if (irq & IRQ_FRAME_END) {
        s_header_seen_us = 0;
    }
    if (irq & IRQ_CAD_DONE) {
        return (irq & IRQ_CAD_DETECTED) ? AH_SX1262_EVENT_CAD_BUSY : AH_SX1262_EVENT_CAD_CLEAR;
    }
    if (irq & IRQ_TX_DONE) {
        return AH_SX1262_EVENT_TX_DONE;
    }
    if (irq & (IRQ_CRC_ERR | IRQ_HEADER_ERR)) {
        return AH_SX1262_EVENT_RX_BAD;
    }
    if (irq & IRQ_RX_DONE) {
        return AH_SX1262_EVENT_RX_DONE;
    }
    return (irq & IRQ_TIMEOUT) ? AH_SX1262_EVENT_TIMEOUT : AH_SX1262_EVENT_NONE;
}

esp_err_t ah_sx1262_read(uint8_t *buf, size_t cap, size_t *len, int8_t *snr_db, int16_t *rssi_dbm)
{
    *len = 0;
    ESP_RETURN_ON_FALSE(s_ready, ESP_ERR_INVALID_STATE, TAG, "not ready");
    // Latched at RX_DONE: RSSI is -RssiPkt/2 dBm, SNR is SnrPkt/4 dB, signed.
    uint8_t pkt[3] = {0};
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_PACKET_STATUS, pkt, sizeof(pkt)), TAG, "packet status");
    *rssi_dbm = (int16_t)(-(int16_t)pkt[0] / 2);
    *snr_db = (int8_t)((int8_t)pkt[1] / 4);
    uint8_t rx[2] = {0};
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_RX_BUFFER_STATUS, rx, sizeof(rx)), TAG, "rx status");
    const size_t n = rx[0];
    ESP_RETURN_ON_FALSE(n > 0 && n <= cap, ESP_ERR_INVALID_SIZE, TAG, "rx length");
    memset(s_tx, 0, n + 3);
    s_tx[0] = OP_READ_BUFFER;
    s_tx[1] = rx[1];
    ESP_RETURN_ON_ERROR(xfer(n + 3), TAG, "read buffer");
    memcpy(buf, s_rx + 3, n);
    *len = n;
    return ESP_OK;
}

static esp_err_t set_power(int8_t dbm)
{
    if (dbm == s_power) {
        return ESP_OK;
    }
    const uint8_t p[2] = {(uint8_t)dbm, 0x04}; // 200 us ramp
    ESP_RETURN_ON_ERROR(cmd(OP_SET_TX_PARAMS, p, sizeof(p)), TAG, "tx params");
    s_power = dbm;
    return ESP_OK;
}

esp_err_t ah_sx1262_transmit(const uint8_t *frame, size_t len, int8_t power_dbm)
{
    ESP_RETURN_ON_FALSE(s_ready, ESP_ERR_INVALID_STATE, TAG, "not ready");
    ESP_RETURN_ON_FALSE(len > 0 && len <= AH_SX1262_FRAME_MAX, ESP_ERR_INVALID_SIZE, TAG, "length");
    ESP_RETURN_ON_FALSE(power_dbm >= AH_SX1262_POWER_MIN && power_dbm <= AH_SX1262_POWER_MAX, ESP_ERR_INVALID_ARG,
                        TAG, "power");
    // Never key a radio that reset into its power-on modulation and channel.
    ESP_RETURN_ON_ERROR(still_configured(), TAG, "setup");
    bool busy = false;
    ESP_RETURN_ON_ERROR(receiving(&busy), TAG, "receiving");
    if (busy) {
        return ESP_ERR_NOT_FINISHED;
    }
    ESP_RETURN_ON_ERROR(standby(STANDBY_XOSC), TAG, "standby");
    ESP_RETURN_ON_ERROR(path(true), TAG, "path");
    ESP_RETURN_ON_ERROR(set_power(power_dbm), TAG, "power");
    // Erratum 15.1: bit 2 of the modulation register is cleared at 500 kHz
    // and set otherwise, before every transmission.
    ESP_RETURN_ON_ERROR(update_reg(REG_TX_MODULATION, 0x04, s_cfg.phy.bandwidth_hz == 500000u ? 0x00 : 0x04), TAG,
                        "modulation erratum");
    s_tx[0] = OP_WRITE_BUFFER;
    s_tx[1] = 0x00;
    memcpy(s_tx + 2, frame, len);
    ESP_RETURN_ON_ERROR(xfer(len + 2), TAG, "write buffer");
    ESP_RETURN_ON_ERROR(set_packet_params(len), TAG, "tx params");
    // The radio's own timeout, in 15.625 us units: the airtime plus margin.
    const uint64_t units = (uint64_t)tx_timeout_ms(len) * 64u;
    const uint32_t capped = units > TIMEOUT_UNITS_MAX ? TIMEOUT_UNITS_MAX : (uint32_t)units;
    const uint8_t timeout[3] = {(uint8_t)(capped >> 16), (uint8_t)(capped >> 8), (uint8_t)capped};
    return cmd(OP_SET_TX, timeout, sizeof(timeout));
}

esp_err_t ah_sx1262_cad(void)
{
    ESP_RETURN_ON_FALSE(s_ready, ESP_ERR_INVALID_STATE, TAG, "not ready");
    ESP_RETURN_ON_ERROR(still_configured(), TAG, "setup");
    bool busy = false;
    ESP_RETURN_ON_ERROR(receiving(&busy), TAG, "receiving");
    if (busy) {
        return ESP_ERR_NOT_FINISHED;
    }
    ESP_RETURN_ON_ERROR(standby(STANDBY_XOSC), TAG, "standby");
    return cmd(OP_SET_CAD, NULL, 0);
}

esp_err_t ah_sx1262_receive(void)
{
    ESP_RETURN_ON_FALSE(s_ready, ESP_ERR_INVALID_STATE, TAG, "not ready");
    return listen();
}

esp_err_t ah_sx1262_check(void)
{
    ESP_RETURN_ON_FALSE(s_ready, ESP_ERR_INVALID_STATE, TAG, "not ready");
    ESP_RETURN_ON_ERROR(still_configured(), TAG, "setup");
    // Continuous receive never ends on its own (datasheet 13.1.5), and every
    // reset lands in STDBY_RC.
    uint8_t status = 0;
    ESP_RETURN_ON_ERROR(cmd_read(OP_GET_STATUS, &status, 0), TAG, "status");
    status = s_rx[1];
    if (STATUS_MODE(status) != MODE_RX) {
        ESP_LOGE(TAG, "radio left receive on its own (status 0x%02x)", status);
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

uint32_t ah_sx1262_tx_deadline_ms(size_t len)
{
    // The radio's timeout is the airtime with margin; the task's watchdog
    // allows a second more, so a timeout the radio reports wins.
    return tx_timeout_ms(len) + TX_WATCHDOG_EXTRA_MS;
}
