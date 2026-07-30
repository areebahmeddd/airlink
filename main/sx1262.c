#include "sx1262.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lora_airtime.h"
#include "lora_region.h"

static const char *TAG = "sx1262";

/* SX126x opcodes (datasheet ch. 13) */
#define OP_SET_STANDBY            0x80
#define OP_SET_TX                 0x83
#define OP_SET_RX                 0x82
#define OP_SET_CAD                0xC5
#define OP_SET_PACKET_TYPE        0x8A
#define OP_SET_RF_FREQUENCY       0x86
#define OP_SET_PA_CONFIG          0x95
#define OP_SET_TX_PARAMS          0x8E
#define OP_SET_BUF_BASE           0x8F
#define OP_SET_MOD_PARAMS         0x8B
#define OP_SET_PACKET_PARAMS      0x8C
#define OP_SET_CAD_PARAMS         0x88
#define OP_SET_DIO_IRQ_PARAMS     0x08
#define OP_GET_IRQ_STATUS         0x12
#define OP_CLR_IRQ_STATUS         0x02
#define OP_SET_DIO2_RF_SWITCH     0x9D
#define OP_SET_DIO3_TCXO          0x97
#define OP_SET_REGULATOR_MODE     0x96
#define OP_CALIBRATE              0x89
#define OP_CALIBRATE_IMAGE        0x98
#define OP_WRITE_REGISTER         0x0D
#define OP_READ_REGISTER          0x1D
#define OP_WRITE_BUFFER           0x0E
#define OP_READ_BUFFER            0x1E
#define OP_GET_RX_BUFFER_STATUS   0x13
#define OP_GET_PACKET_STATUS      0x14

#define IRQ_TX_DONE       (1u << 0)
#define IRQ_RX_DONE       (1u << 1)
#define IRQ_CRC_ERR       (1u << 6)
#define IRQ_CAD_DONE      (1u << 7)
#define IRQ_CAD_DETECTED  (1u << 8)
#define IRQ_TIMEOUT       (1u << 9)
#define IRQ_ALL           0x03FF

#define REG_LORA_SYNC_MSB 0x0740
#define REG_RX_GAIN       0x08AC
#define REG_OCP           0x08E7

#define RX_GAIN_BOOSTED   0x96
/* OCP is programmed in 2.5 mA steps: 0x38 = 140 mA. */
#define OCP_140_MA        0x38

#define BUSY_POLL_US              10
#define BUSY_TIMEOUT_US           40000
#define RECOVERY_ATTEMPTS         2
#define TX_MIN_MARGIN_MS          500
#define TX_MARGIN_PERCENT         25
#define TX_WATCHDOG_MARGIN_MS     1000

static spi_device_handle_t s_spi;
static sx1262_config_t s_cfg;
static sx1262_diag_t s_diag;
static bool s_ready;

static void note_command_error(esp_err_t err, const char *operation)
{
    s_diag.command_errors++;
    ESP_LOGW(TAG, "%s failed: %s", operation, esp_err_to_name(err));
}

static esp_err_t busy_wait(void)
{
    /* BUSY falls when the chip can accept the next command (<~100 us
     * typical, up to a few ms after TCXO-related operations). Never issue
     * another SPI command while BUSY remains asserted. */
    for (int elapsed = 0; elapsed < BUSY_TIMEOUT_US; elapsed += BUSY_POLL_US) {
        if (gpio_get_level(s_cfg.pin_busy) == 0) {
            return ESP_OK;
        }
        esp_rom_delay_us(BUSY_POLL_US);
    }
    s_diag.busy_timeouts++;
    note_command_error(ESP_ERR_TIMEOUT, "BUSY wait");
    return ESP_ERR_TIMEOUT;
}

static esp_err_t xfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
    spi_transaction_t transaction = {
        .length = len * 8,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t err = spi_device_transmit(s_spi, &transaction);
    if (err != ESP_OK) {
        note_command_error(err, "SPI transfer");
    }
    return err;
}

static esp_err_t cmd(uint8_t op, const uint8_t *args, size_t count)
{
    if (count > 15) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t buffer[16] = {op};
    if (count) {
        memcpy(buffer + 1, args, count);
    }
    esp_err_t err = busy_wait();
    if (err != ESP_OK) {
        return err;
    }
    return xfer(buffer, NULL, count + 1);
}

static esp_err_t cmd_read(uint8_t op, uint8_t *out, size_t count)
{
    if (count > 14) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t tx[16] = {0};
    uint8_t rx[16] = {0};
    tx[0] = op;
    esp_err_t err = busy_wait();
    if (err != ESP_OK) {
        return err;
    }
    err = xfer(tx, rx, count + 2); /* opcode + status + payload */
    if (err == ESP_OK) {
        memcpy(out, rx + 2, count);
    }
    return err;
}

static esp_err_t write_reg(uint16_t address, const uint8_t *data, size_t count)
{
    if (count > 17) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t buffer[20] = {0};
    buffer[0] = OP_WRITE_REGISTER;
    buffer[1] = address >> 8;
    buffer[2] = address & 0xFF;
    memcpy(buffer + 3, data, count);
    esp_err_t err = busy_wait();
    if (err != ESP_OK) {
        return err;
    }
    return xfer(buffer, NULL, count + 3);
}

static esp_err_t read_reg(uint16_t address, uint8_t *data, size_t count)
{
    if (count > 16) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t tx[20] = {0};
    uint8_t rx[20] = {0};
    tx[0] = OP_READ_REGISTER;
    tx[1] = address >> 8;
    tx[2] = address & 0xFF;
    esp_err_t err = busy_wait();
    if (err != ESP_OK) {
        return err;
    }
    err = xfer(tx, rx, count + 4); /* opcode + address + status + data */
    if (err == ESP_OK) {
        memcpy(data, rx + 4, count);
    }
    return err;
}

static esp_err_t chip_reset(void)
{
    esp_err_t err = gpio_set_level(s_cfg.pin_reset, 0);
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(2));
    err = gpio_set_level(s_cfg.pin_reset, 1);
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(10));
    return ESP_OK;
}

static bool config_valid(const sx1262_config_t *cfg)
{
    if (!cfg ||
        cfg->pin_sck < 0 || cfg->pin_miso < 0 ||
        cfg->pin_mosi < 0 || cfg->pin_cs < 0 ||
        cfg->pin_reset < 0 || cfg->pin_busy < 0 ||
        cfg->pin_dio1 < 0) {
        return false;
    }
    lora_phy_profile_t profile = {
        .region = cfg->region,
        .frequency_hz = cfg->freq_hz,
        .spreading_factor = cfg->sf,
        .bandwidth_hz = cfg->bw_hz,
        .coding_rate = cfg->cr,
        .preamble_symbols = cfg->preamble_symbols,
        .sync_word = LORA_PRIVATE_SYNC_WORD,
        .tx_dbm = cfg->tx_dbm,
    };
    return lora_phy_profile_valid(&profile);
}

static esp_err_t bus_init(const sx1262_config_t *cfg)
{
    if (!config_valid(cfg)) {
        return ESP_ERR_INVALID_ARG;
    }
    s_cfg = *cfg;

    gpio_config_t output = {
        .pin_bit_mask = (1ULL << cfg->pin_reset) |
                        (cfg->pin_rxen >= 0 ? (1ULL << cfg->pin_rxen) : 0),
        .mode = GPIO_MODE_OUTPUT,
    };
    esp_err_t err = gpio_config(&output);
    if (err != ESP_OK) {
        return err;
    }
    err = gpio_set_level(cfg->pin_reset, 1);
    if (err != ESP_OK) {
        return err;
    }
    if (cfg->pin_rxen >= 0) {
        err = gpio_set_level(cfg->pin_rxen, 1);
        if (err != ESP_OK) {
            return err;
        }
    }

    gpio_config_t input = {
        .pin_bit_mask = (1ULL << cfg->pin_busy) | (1ULL << cfg->pin_dio1),
        .mode = GPIO_MODE_INPUT,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
    };
    err = gpio_config(&input);
    if (err != ESP_OK) {
        return err;
    }

    if (!s_spi) {
        spi_bus_config_t bus = {
            .sclk_io_num = cfg->pin_sck,
            .miso_io_num = cfg->pin_miso,
            .mosi_io_num = cfg->pin_mosi,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 300,
        };
        err = spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            return err;
        }
        spi_device_interface_config_t device = {
            .clock_speed_hz = 8 * 1000 * 1000,
            .mode = 0,
            .spics_io_num = cfg->pin_cs,
            .queue_size = 4,
        };
        err = spi_bus_add_device(SPI2_HOST, &device, &s_spi);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

static esp_err_t verify_reg(uint16_t address, uint8_t expected, const char *name)
{
    uint8_t actual = 0;
    esp_err_t err = read_reg(address, &actual, 1);
    if (err != ESP_OK) {
        return err;
    }
    if (actual != expected) {
        s_diag.command_errors++;
        ESP_LOGE(TAG, "%s verify failed: wrote 0x%02x read 0x%02x",
                 name, expected, actual);
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

static esp_err_t verify_regs(
    uint16_t address, const uint8_t *expected, size_t count,
    const char *name)
{
    if (!expected || count == 0 || count > 4) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t actual[4] = {0};
    esp_err_t err = read_reg(address, actual, count);
    if (err != ESP_OK) {
        return err;
    }
    if (memcmp(actual, expected, count) != 0) {
        s_diag.command_errors++;
        ESP_LOGE(TAG, "%s verify failed", name);
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

#define RETURN_ON_ERROR(expression) do { \
    esp_err_t return_on_error_result = (expression); \
    if (return_on_error_result != ESP_OK) { \
        return return_on_error_result; \
    } \
} while (0)

static esp_err_t set_packet_params(uint16_t payload_len)
{
    uint8_t params[6] = {
        s_cfg.preamble_symbols >> 8,
        s_cfg.preamble_symbols & 0xFF,
        0x00,                       /* explicit header */
        (uint8_t)payload_len,
        0x01,                       /* CRC on */
        0x00,                       /* standard IQ */
    };
    return cmd(OP_SET_PACKET_PARAMS, params, sizeof(params));
}

static esp_err_t resume_rx_internal(void)
{
    if (s_cfg.pin_rxen >= 0) {
        RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_rxen, 1));
    }
    /* This register is expected to survive standby/TX transitions. Verify it
     * whenever RX is resumed so a mode-transition regression is actionable. */
    RETURN_ON_ERROR(verify_reg(REG_RX_GAIN, RX_GAIN_BOOSTED, "RX gain"));
    RETURN_ON_ERROR(set_packet_params(SX1262_MAX_PAYLOAD));
    uint8_t timeout[3] = {0xFF, 0xFF, 0xFF}; /* continuous RX */
    return cmd(OP_SET_RX, timeout, sizeof(timeout));
}

static esp_err_t configure_radio(void)
{
    const lora_region_profile_t *profile = lora_region_profile(s_cfg.region);
    if (!profile || !lora_region_frequency_valid(s_cfg.region, s_cfg.freq_hz)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t standby_rc = 0x00;
    RETURN_ON_ERROR(cmd(OP_SET_STANDBY, &standby_rc, 1));

    uint8_t dcdc = 0x01;
    RETURN_ON_ERROR(cmd(OP_SET_REGULATOR_MODE, &dcdc, 1));

    /* TCXO on DIO3 at 1.8 V, 5 ms startup (board requirement). Enabling the
     * TCXO invalidates earlier calibration, so perform the full calibration
     * and then the regional image calibration. */
    uint8_t tcxo[4] = {0x02, 0x00, 0x01, 0x40};
    RETURN_ON_ERROR(cmd(OP_SET_DIO3_TCXO, tcxo, sizeof(tcxo)));
    uint8_t calibrate_all = 0x7F;
    RETURN_ON_ERROR(cmd(OP_CALIBRATE, &calibrate_all, 1));
    vTaskDelay(pdMS_TO_TICKS(5));

    uint8_t image[2] = {
        profile->image_calibration[0],
        profile->image_calibration[1]
    };
    RETURN_ON_ERROR(cmd(OP_CALIBRATE_IMAGE, image, sizeof(image)));

    uint8_t dio2_switch = 0x01;
    RETURN_ON_ERROR(cmd(OP_SET_DIO2_RF_SWITCH, &dio2_switch, 1));

    uint8_t packet_lora = 0x01;
    RETURN_ON_ERROR(cmd(OP_SET_PACKET_TYPE, &packet_lora, 1));

    uint32_t frf = (uint32_t)(((uint64_t)s_cfg.freq_hz << 25) / 32000000ULL);
    uint8_t frequency[4] = {frf >> 24, frf >> 16, frf >> 8, frf};
    RETURN_ON_ERROR(cmd(OP_SET_RF_FREQUENCY, frequency, sizeof(frequency)));

    /* SX1262 +22 dBm PA profile and 140 mA over-current protection. The
     * register readback catches marginal SPI/configuration failures at boot. */
    uint8_t pa[4] = {0x04, 0x07, 0x00, 0x01};
    RETURN_ON_ERROR(cmd(OP_SET_PA_CONFIG, pa, sizeof(pa)));
    uint8_t ocp = OCP_140_MA;
    RETURN_ON_ERROR(write_reg(REG_OCP, &ocp, 1));
    RETURN_ON_ERROR(verify_reg(REG_OCP, ocp, "OCP"));
    uint8_t tx_params[2] = {(uint8_t)s_cfg.tx_dbm, 0x04}; /* 200 us ramp */
    RETURN_ON_ERROR(cmd(OP_SET_TX_PARAMS, tx_params, sizeof(tx_params)));

    uint8_t base[2] = {0x00, 0x00};
    RETURN_ON_ERROR(cmd(OP_SET_BUF_BASE, base, sizeof(base)));

    uint8_t bandwidth_code =
        s_cfg.bw_hz == 500000 ? 0x06 :
        s_cfg.bw_hz == 250000 ? 0x05 : 0x04;
    /* Low-data-rate optimize whenever symbol time exceeds 16 ms. */
    uint8_t ldro = (s_cfg.sf >= 11 && s_cfg.bw_hz == 125000) ||
                   (s_cfg.sf >= 12 && s_cfg.bw_hz == 250000) ? 0x01 : 0x00;
    uint8_t modulation[4] = {
        s_cfg.sf, bandwidth_code, (uint8_t)(s_cfg.cr - 4), ldro
    };
    RETURN_ON_ERROR(cmd(OP_SET_MOD_PARAMS, modulation, sizeof(modulation)));

    uint8_t sync[2] = {
        LORA_PRIVATE_SYNC_WORD >> 8,
        LORA_PRIVATE_SYNC_WORD & 0xFF
    };
    RETURN_ON_ERROR(write_reg(REG_LORA_SYNC_MSB, sync, sizeof(sync)));
    RETURN_ON_ERROR(verify_regs(
        REG_LORA_SYNC_MSB, sync, sizeof(sync), "sync word"));

    uint8_t rx_gain = RX_GAIN_BOOSTED;
    RETURN_ON_ERROR(write_reg(REG_RX_GAIN, &rx_gain, 1));
    RETURN_ON_ERROR(verify_reg(REG_RX_GAIN, rx_gain, "RX gain"));

    uint16_t mask = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_CRC_ERR |
                    IRQ_CAD_DONE | IRQ_CAD_DETECTED | IRQ_TIMEOUT;
    uint8_t irq[8] = {
        mask >> 8, mask & 0xFF,
        mask >> 8, mask & 0xFF,
        0, 0, 0, 0
    };
    RETURN_ON_ERROR(cmd(OP_SET_DIO_IRQ_PARAMS, irq, sizeof(irq)));
    uint8_t clear[2] = {IRQ_ALL >> 8, IRQ_ALL & 0xFF};
    RETURN_ON_ERROR(cmd(OP_CLR_IRQ_STATUS, clear, sizeof(clear)));

    /* CAD per Semtech AN1200.48: 4 symbols, detPeak follows SF, detMin 10. */
    uint8_t cad[7] = {
        0x02,                       /* 4 symbols */
        (uint8_t)(s_cfg.sf + 13),
        10,
        0x00,                       /* CAD only */
        0, 0, 0
    };
    return cmd(OP_SET_CAD_PARAMS, cad, sizeof(cad));
}

bool sx1262_detect(const sx1262_config_t *cfg)
{
    if (!config_valid(cfg) || bus_init(cfg) != ESP_OK) {
        return false;
    }
    if (chip_reset() != ESP_OK) {
        return false;
    }

    /* Scratch write/read of the LoRa sync word register: a real SX126x
     * echoes the value; floating or absent hardware does not. Initialization
     * resets the scratch value before normal use. */
    uint8_t probe = 0xA7;
    uint8_t actual = 0;
    return write_reg(REG_LORA_SYNC_MSB, &probe, 1) == ESP_OK &&
           read_reg(REG_LORA_SYNC_MSB, &actual, 1) == ESP_OK &&
           actual == probe;
}

esp_err_t sx1262_init(const sx1262_config_t *cfg,
                      void (*dio1_notify)(void *arg), void *arg)
{
    s_ready = false;
    RETURN_ON_ERROR(bus_init(cfg));
    RETURN_ON_ERROR(chip_reset());
    RETURN_ON_ERROR(configure_radio());

    if (dio1_notify) {
        esp_err_t err = gpio_install_isr_service(0);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            return err;
        }
        RETURN_ON_ERROR(gpio_set_intr_type(cfg->pin_dio1, GPIO_INTR_POSEDGE));
        RETURN_ON_ERROR(gpio_isr_handler_add(cfg->pin_dio1, dio1_notify, arg));
        RETURN_ON_ERROR(gpio_intr_enable(cfg->pin_dio1));
    }

    s_ready = true;
    esp_err_t err = resume_rx_internal();
    if (err != ESP_OK) {
        s_ready = false;
    }
    return err;
}

esp_err_t sx1262_recover(void)
{
    s_diag.recoveries++;
    s_ready = false;

    esp_err_t last_error = ESP_FAIL;
    for (int attempt = 1; attempt <= RECOVERY_ATTEMPTS; ++attempt) {
        last_error = chip_reset();
        if (last_error == ESP_OK) {
            last_error = configure_radio();
        }
        if (last_error == ESP_OK) {
            last_error = resume_rx_internal();
        }
        if (last_error == ESP_OK) {
            s_ready = true;
            ESP_LOGW(TAG, "radio recovered on attempt %d", attempt);
            return ESP_OK;
        }
        ESP_LOGW(TAG, "radio recovery attempt %d failed: %s",
                 attempt, esp_err_to_name(last_error));
    }

    s_diag.recovery_failures++;
    ESP_LOGE(TAG, "radio recovery exhausted");
    return last_error;
}

sx1262_event_t sx1262_poll_event(void)
{
    if (!s_ready) {
        return SX1262_EVT_NONE;
    }
    uint8_t status[2] = {0};
    if (cmd_read(OP_GET_IRQ_STATUS, status, sizeof(status)) != ESP_OK) {
        return SX1262_EVT_ERROR;
    }
    uint16_t irq = ((uint16_t)status[0] << 8) | status[1];
    if (!irq) {
        return SX1262_EVT_NONE;
    }
    uint8_t clear[2] = {irq >> 8, irq & 0xFF};
    if (cmd(OP_CLR_IRQ_STATUS, clear, sizeof(clear)) != ESP_OK) {
        return SX1262_EVT_ERROR;
    }

    if (irq & IRQ_CAD_DONE) {
        return (irq & IRQ_CAD_DETECTED) ?
               SX1262_EVT_CAD_BUSY : SX1262_EVT_CAD_CLEAR;
    }
    if (irq & IRQ_TX_DONE) {
        return SX1262_EVT_TX_DONE;
    }
    if (irq & IRQ_CRC_ERR) {
        return SX1262_EVT_RX_CRC_ERROR;
    }
    if (irq & IRQ_RX_DONE) {
        return SX1262_EVT_RX_DONE;
    }
    if (irq & IRQ_TIMEOUT) {
        return SX1262_EVT_TIMEOUT;
    }
    return SX1262_EVT_NONE;
}

uint16_t sx1262_read_packet(uint8_t *buffer, uint16_t max_len,
                            int16_t *rssi_dbm, int8_t *snr_db)
{
    if (!s_ready || !buffer) {
        return 0;
    }

    /* Packet status latches at RX_DONE. RSSI[dBm] = -RssiPkt/2 and
     * SNR[dB] = (int8)SnrPkt/4. */
    if (rssi_dbm || snr_db) {
        uint8_t packet_status[3] = {0};
        if (cmd_read(OP_GET_PACKET_STATUS, packet_status,
                     sizeof(packet_status)) != ESP_OK) {
            return 0;
        }
        if (rssi_dbm) {
            *rssi_dbm = -(int16_t)packet_status[0] / 2;
        }
        if (snr_db) {
            *snr_db = (int8_t)packet_status[1] / 4;
        }
    }

    uint8_t rx_status[2] = {0};
    if (cmd_read(OP_GET_RX_BUFFER_STATUS, rx_status, sizeof(rx_status)) != ESP_OK) {
        return 0;
    }
    uint16_t len = rx_status[0];
    uint8_t offset = rx_status[1];
    if (len == 0 || len > max_len) {
        return 0;
    }

    uint8_t tx[SX1262_MAX_PAYLOAD + 3] = {0};
    uint8_t rx[SX1262_MAX_PAYLOAD + 3] = {0};
    tx[0] = OP_READ_BUFFER;
    tx[1] = offset;
    if (busy_wait() != ESP_OK || xfer(tx, rx, len + 3) != ESP_OK) {
        return 0;
    }
    memcpy(buffer, rx + 3, len);
    return len;
}

static uint32_t tx_timeout_ms(uint16_t len)
{
    lora_airtime_params_t params = {
        .spreading_factor = s_cfg.sf,
        .bandwidth_hz = s_cfg.bw_hz,
        .coding_rate = s_cfg.cr,
        .preamble_symbols = s_cfg.preamble_symbols,
        .explicit_header = true,
        .crc_enabled = true,
    };
    return lora_tx_timeout_ms(&params, len,
                              TX_MIN_MARGIN_MS, TX_MARGIN_PERCENT);
}

uint32_t sx1262_tx_watchdog_ms(uint16_t len)
{
    if (len == 0 || len > SX1262_MAX_PAYLOAD) {
        return 0;
    }
    uint32_t radio_timeout = tx_timeout_ms(len);
    if (UINT32_MAX - radio_timeout < TX_WATCHDOG_MARGIN_MS) {
        return UINT32_MAX;
    }
    return radio_timeout + TX_WATCHDOG_MARGIN_MS;
}

esp_err_t sx1262_transmit(const uint8_t *data, uint16_t len)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!data || len == 0 || len > SX1262_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_cfg.pin_rxen >= 0) {
        RETURN_ON_ERROR(gpio_set_level(s_cfg.pin_rxen, 0));
    }

    uint8_t standby_rc = 0x00;
    RETURN_ON_ERROR(cmd(OP_SET_STANDBY, &standby_rc, 1));

    uint8_t write_buffer[SX1262_MAX_PAYLOAD + 2];
    write_buffer[0] = OP_WRITE_BUFFER;
    write_buffer[1] = 0x00;
    memcpy(write_buffer + 2, data, len);
    RETURN_ON_ERROR(busy_wait());
    RETURN_ON_ERROR(xfer(write_buffer, NULL, len + 2));
    RETURN_ON_ERROR(set_packet_params(len));

    uint32_t timeout_units = lora_sx126x_timeout_units(tx_timeout_ms(len));
    uint8_t timeout[3] = {
        timeout_units >> 16,
        timeout_units >> 8,
        timeout_units
    };
    return cmd(OP_SET_TX, timeout, sizeof(timeout));
}

esp_err_t sx1262_start_cad(void)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t standby_rc = 0x00;
    RETURN_ON_ERROR(cmd(OP_SET_STANDBY, &standby_rc, 1));
    return cmd(OP_SET_CAD, NULL, 0);
}

esp_err_t sx1262_resume_rx(void)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    return resume_rx_internal();
}

void sx1262_get_diag(sx1262_diag_t *out)
{
    if (out) {
        *out = s_diag;
    }
}
