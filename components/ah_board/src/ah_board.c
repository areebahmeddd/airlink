// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The board profiles and the power-up each board's rails and front end need.
// Pin maps follow each vendor's schematic as the boards' Meshtastic variants
// encode them; docs/BOARDS.md lists the sources.
#include "ah_board.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "ah_board";

#define NONE (-1)

// An SX1262 behind no front end: its own +22 dBm ceiling.
#define SX1262_ALONE 22
// TCXO on DIO3 at 1.8 V on every supported SX1262 board.
#define TCXO_1V8 1800

#if CONFIG_AH_BOARD_HELTEC_V4 || CONFIG_AH_BOARD_HELTEC_V3
#define VEXT_PIN 36
#elif CONFIG_AH_BOARD_HELTEC_V4_R8
// The S3R8's octal PSRAM takes GPIO33 to GPIO37.
#define VEXT_PIN 40
#endif

#if CONFIG_AH_BOARD_HELTEC_V4 || CONFIG_AH_BOARD_HELTEC_V4_R8
#define HELTEC_V4_FRONT_END 1
// The front end's gain at each SX1262 setting from 0 to 21 dBm, as Heltec
// measured it: the PA compresses toward its 28 dBm output. The SX1262 is
// never driven above 21 dBm into it.
#if CONFIG_AH_BOARD_HELTEC_V4
static const uint8_t s_gc1109_gain[] = {11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
                                        11, 11, 11, 11, 11, 10, 10, 9,  9,  8,  7
                                       };
#endif
static const uint8_t s_kct8103l_gain[] = {13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                                          13, 13, 13, 12, 12, 11, 11, 10, 9,  8,  7
                                         };
#define V4_PA_POWER 7
#define V4_CSD 2
#define V4_GC1109_CPS 46
#define V4_KCT8103L_CTX 5
#define V4_RADIO_MAX 21
#endif

#if CONFIG_AH_BOARD_TBEAM_SUPREME
#define AXP2101_ADDR 0x34
#define AXP2101_SDA 42
#define AXP2101_SCL 41
#define AXP2101_LDO_ENABLE 0x90
// LilyGO's rail table: ALDO1 the display, ALDO2 the sensors, ALDO3 the SX1262.
// The voltage registers run from 0x92, one per ALDO.
#define AXP2101_ALDO1_BIT 0x01
#define AXP2101_ALDO2_BIT 0x02
#define AXP2101_ALDO3_BIT 0x04
#define AXP2101_ALDO1_VOLTAGE 0x92
// 0.5 V plus 100 mV a step: 3.3 V.
#define AXP2101_3V3 28
#endif

#if CONFIG_AH_BOARD_XIAO_C6
#define XIAO_C6_RF_ENABLE 3
#define XIAO_C6_ANTENNA_SELECT 14
#if CONFIG_AH_BOARD_XIAO_C6_EXTERNAL_ANTENNA
#define XIAO_C6_ANTENNA 1
#else
#define XIAO_C6_ANTENNA 0
#endif
#endif

static ah_board_t s_board = {
#if CONFIG_AH_BOARD_HELTEC_V4
    .name = "heltec_v4",
    .has_lora = true,
    // The front end (and so pin_txen and the gain table) is found at init.
    .radio = {
        .pin_sck = 9, .pin_miso = 11, .pin_mosi = 10, .pin_nss = 8, .pin_reset = 12, .pin_busy = 13,
        .pin_dio1 = 14, .pin_rxen = NONE, .pin_txen = NONE, .dio2_rf_switch = true, .tcxo_mv = TCXO_1V8,
        .radio_max_dbm = V4_RADIO_MAX
    },
    .display = AH_DISPLAY_SSD1306,
    .display_sda = 17,
    .display_scl = 18,
    .display_rst = 21,
    .button = 0,
#elif CONFIG_AH_BOARD_HELTEC_V4_R8
    .name = "heltec_v4_r8",
    .has_lora = true,
    // Wired as the V4 but for Vext and the front end (VEXT_PIN, v4_detect_front_end).
    .radio = {
        .pin_sck = 9, .pin_miso = 11, .pin_mosi = 10, .pin_nss = 8, .pin_reset = 12, .pin_busy = 13,
        .pin_dio1 = 14, .pin_rxen = NONE, .pin_txen = NONE, .dio2_rf_switch = true, .tcxo_mv = TCXO_1V8,
        .radio_max_dbm = V4_RADIO_MAX
    },
    .display = AH_DISPLAY_SSD1306,
    .display_sda = 17,
    .display_scl = 18,
    .display_rst = 21,
    .button = 0,
#elif CONFIG_AH_BOARD_HELTEC_V3
    .name = "heltec_v3",
    .has_lora = true,
    .radio = {
        .pin_sck = 9, .pin_miso = 11, .pin_mosi = 10, .pin_nss = 8, .pin_reset = 12, .pin_busy = 13,
        .pin_dio1 = 14, .pin_rxen = NONE, .pin_txen = NONE, .dio2_rf_switch = true, .tcxo_mv = TCXO_1V8,
        .radio_max_dbm = SX1262_ALONE
    },
    .display = AH_DISPLAY_SSD1306,
    .display_sda = 17,
    .display_scl = 18,
    .display_rst = 21,
    .button = 0,
#elif CONFIG_AH_BOARD_TBEAM_SUPREME
    .name = "tbeam_supreme",
    .has_lora = true,
    .radio = {
        .pin_sck = 12, .pin_miso = 13, .pin_mosi = 11, .pin_nss = 10, .pin_reset = 5, .pin_busy = 4,
        .pin_dio1 = 1, .pin_rxen = NONE, .pin_txen = NONE, .dio2_rf_switch = true, .tcxo_mv = TCXO_1V8,
        .radio_max_dbm = SX1262_ALONE
    },
    .display = AH_DISPLAY_SH1106,
    .display_sda = 17,
    .display_scl = 18,
    .display_rst = NONE,
    .button = 0,
#elif CONFIG_AH_BOARD_XIAO_S3_WIO
    .name = "xiao_s3_wio",
    .has_lora = true,
    .radio = {
        .pin_sck = 7, .pin_miso = 8, .pin_mosi = 9, .pin_nss = 41, .pin_reset = 42, .pin_busy = 40,
        .pin_dio1 = 39, .pin_rxen = 38, .pin_txen = NONE, .dio2_rf_switch = true, .tcxo_mv = TCXO_1V8,
        .radio_max_dbm = SX1262_ALONE
    },
    .display = AH_DISPLAY_NONE,
    .display_sda = NONE,
    .display_scl = NONE,
    .display_rst = NONE,
    .button = NONE,
#elif CONFIG_AH_BOARD_C6_DEVKIT
    .name = "c6_devkit",
    .has_lora = false,
    .display = AH_DISPLAY_NONE,
    .display_sda = NONE,
    .display_scl = NONE,
    .display_rst = NONE,
    .button = 9,
#elif CONFIG_AH_BOARD_XIAO_C6
    .name = "xiao_c6",
    .has_lora = false,
    .display = AH_DISPLAY_NONE,
    .display_sda = NONE,
    .display_scl = NONE,
    .display_rst = NONE,
    .button = NONE,
#else
#error "no profile for the chosen board (main/Kconfig.projbuild, AH_BOARD)"
#endif
};

[[maybe_unused]] static esp_err_t output(int pin, int level)
{
    ESP_RETURN_ON_ERROR(gpio_reset_pin(pin), TAG, "reset %d", pin);
    ESP_RETURN_ON_ERROR(gpio_set_direction(pin, GPIO_MODE_OUTPUT), TAG, "output %d", pin);
    return gpio_set_level(pin, level);
}

// vTaskDelay(n) ends at the n-th tick boundary from now, so it can fall up to
// a tick short: one tick more makes the wait a floor, as a rail needs.
[[maybe_unused]] static void wait_at_least_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms) + 1);
}

#ifdef VEXT_PIN
#if CONFIG_AH_BOARD_VEXT_ACTIVE_LOW
#define VEXT_ON 0
#else
#define VEXT_ON 1
#endif

// Vext feeds the OLED, and on the V4 the receive path's LNA.
static esp_err_t vext_on(void)
{
    ESP_RETURN_ON_ERROR(output(VEXT_PIN, VEXT_ON), TAG, "vext");
    wait_at_least_ms(20);
    return ESP_OK;
}
#endif

#ifdef HELTEC_V4_FRONT_END
#if CONFIG_AH_BOARD_HELTEC_V4
// V4.2 carries a GC1109 front end, V4.3 a KCT8103L; both share the enable on
// GPIO2, which the KCT8103L's board pulls high and the GC1109's leaves low.
// Read with the front end powered, which is then switched off again: it draws
// current only while the trunk runs (ah_board_radio_power).
static esp_err_t v4_detect_front_end(void)
{
    ESP_RETURN_ON_ERROR(output(V4_PA_POWER, 1), TAG, "fem power");
    // Busy waits: a few milliseconds is zero FreeRTOS ticks at 100 Hz.
    esp_rom_delay_us(5000);
    ESP_RETURN_ON_ERROR(gpio_reset_pin(V4_CSD), TAG, "csd");
    ESP_RETURN_ON_ERROR(gpio_set_direction(V4_CSD, GPIO_MODE_INPUT), TAG, "csd in");
    ESP_RETURN_ON_ERROR(gpio_set_pull_mode(V4_CSD, GPIO_FLOATING), TAG, "csd float");
    // gpio_reset_pin pulled the pin up: let the board's resistor settle it.
    esp_rom_delay_us(1000);
    const bool kct = gpio_get_level(V4_CSD) == 1;
    ESP_RETURN_ON_ERROR(output(V4_CSD, 0), TAG, "csd off");
    ESP_RETURN_ON_ERROR(gpio_set_level(V4_PA_POWER, 0), TAG, "fem power off");
    s_board.radio.pin_txen = kct ? V4_KCT8103L_CTX : V4_GC1109_CPS;
    s_board.radio.fem_gain_db = kct ? s_kct8103l_gain : s_gc1109_gain;
    s_board.radio.fem_points = kct ? sizeof(s_kct8103l_gain) : sizeof(s_gc1109_gain);
    ESP_LOGI(TAG, "front end %s", kct ? "KCT8103L (V4.3)" : "GC1109 (V4.2)");
    return ESP_OK;
}
#else
// The V4-R8 carries the KCT8103L alone, and its GPIO46 is the LED, never the
// GC1109's transmit line. Both front-end lines start low: it is powered
// only while the trunk runs (ah_board_radio_power).
static esp_err_t v4_detect_front_end(void)
{
    ESP_RETURN_ON_ERROR(output(V4_PA_POWER, 0), TAG, "fem power off");
    ESP_RETURN_ON_ERROR(output(V4_CSD, 0), TAG, "csd off");
    s_board.radio.pin_txen = V4_KCT8103L_CTX;
    s_board.radio.fem_gain_db = s_kct8103l_gain;
    s_board.radio.fem_points = sizeof(s_kct8103l_gain);
    return ESP_OK;
}
#endif

static esp_err_t v4_front_end_power(bool on)
{
    if (!on) {
        ESP_RETURN_ON_ERROR(gpio_set_level(V4_CSD, 0), TAG, "csd off");
        return gpio_set_level(V4_PA_POWER, 0);
    }
    ESP_RETURN_ON_ERROR(gpio_set_level(V4_PA_POWER, 1), TAG, "fem power");
    esp_rom_delay_us(5000);
    return gpio_set_level(V4_CSD, 1);
}
#endif

#if CONFIG_AH_BOARD_TBEAM_SUPREME
// Set ALDO1 to ALDO3 to 3.3 V and switch them on, keeping whatever else the PMU has on.
static esp_err_t pmu_radio_on(void)
{
    const i2c_master_bus_config_t bus_cfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = AXP2101_SDA,
        .scl_io_num = AXP2101_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t bus = NULL;
    ESP_RETURN_ON_ERROR(i2c_new_master_bus(&bus_cfg, &bus), TAG, "pmu bus");
    const i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = AXP2101_ADDR,
        .scl_speed_hz = 100000,
    };
    i2c_master_dev_handle_t dev = NULL;
    esp_err_t err = i2c_master_bus_add_device(bus, &dev_cfg, &dev);
    uint8_t reg = AXP2101_LDO_ENABLE;
    uint8_t enabled = 0;
    for (uint8_t aldo = 0; aldo < 3u && err == ESP_OK; ++aldo) {
        const uint8_t voltage[2] = {(uint8_t)(AXP2101_ALDO1_VOLTAGE + aldo), AXP2101_3V3};
        err = i2c_master_transmit(dev, voltage, sizeof(voltage), 100);
    }
    if (err == ESP_OK) {
        err = i2c_master_transmit_receive(dev, &reg, 1, &enabled, 1, 100);
    }
    if (err == ESP_OK) {
        const uint8_t rails = AXP2101_ALDO1_BIT | AXP2101_ALDO2_BIT | AXP2101_ALDO3_BIT;
        const uint8_t on[2] = {AXP2101_LDO_ENABLE, (uint8_t)(enabled | rails)};
        err = i2c_master_transmit(dev, on, sizeof(on), 100);
    }
    if (dev != NULL) {
        i2c_master_bus_rm_device(dev);
    }
    i2c_del_master_bus(bus);
    ESP_RETURN_ON_ERROR(err, TAG, "aldo");
    wait_at_least_ms(10);
    return ESP_OK;
}
#endif

esp_err_t ah_board_init(void)
{
#ifdef VEXT_PIN
    ESP_RETURN_ON_ERROR(vext_on(), TAG, "vext");
#endif
#ifdef HELTEC_V4_FRONT_END
    ESP_RETURN_ON_ERROR(v4_detect_front_end(), TAG, "front end");
#endif
#if CONFIG_AH_BOARD_TBEAM_SUPREME
    ESP_RETURN_ON_ERROR(pmu_radio_on(), TAG, "pmu");
#endif
#if CONFIG_AH_BOARD_XIAO_C6
    // GPIO3 low powers the RF switch; GPIO14 high picks the U.FL port over
    // the ceramic antenna.
    ESP_RETURN_ON_ERROR(output(XIAO_C6_RF_ENABLE, 0), TAG, "rf switch");
    ESP_RETURN_ON_ERROR(output(XIAO_C6_ANTENNA_SELECT, XIAO_C6_ANTENNA), TAG, "antenna");
#endif
    ESP_LOGI(TAG, "board %s", s_board.name);
    return ESP_OK;
}

esp_err_t ah_board_radio_power(bool on)
{
#ifdef HELTEC_V4_FRONT_END
    return v4_front_end_power(on);
#else
    (void)on;
    return ESP_OK;
#endif
}

const ah_board_t *ah_board(void)
{
    return &s_board;
}
