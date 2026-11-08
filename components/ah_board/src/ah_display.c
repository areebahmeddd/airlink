// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The I2C side of an SSD1306 or SH1106 128 x 64 panel, and the display task
// that refreshes it from the latest model; drawing is ah_screen's. The task
// owns the bus and the frame.
#include "ah_display.h"

#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "ah_display";

#define PANEL_ADDR 0x3C
#define CONTROL_COMMAND 0x00
#define CONTROL_DATA 0x40
#define I2C_HZ 400000
#define I2C_TIMEOUT_MS 100
#define REFRESH_MS 250
#define BOOT_SPLASH_MS 2500
// A panel that keeps refusing writes has a marginal rail or wiring: stop
// using the bus rather than retry forever.
#define FAILURES_BEFORE_GIVING_UP 25
// The SH1106 holds 132 columns and shows the middle 128.
#define SH1106_COLUMN_OFFSET 2
#define TASK_STACK 4096
#define TASK_PRIORITY 2

static i2c_master_dev_handle_t s_dev;
static ah_display_kind_t s_kind;
static int s_button = -1;
static char s_nickname[AH_SCREEN_NICK_MAX + 1];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ah_screen_model_t s_model;
static uint32_t s_last_relayed;
static bool s_started;
static uint8_t s_fb[AH_SCREEN_FB_BYTES];
static uint8_t s_out[AH_SCREEN_FB_BYTES + 1];

static esp_err_t commands(const uint8_t *cmds, size_t n)
{
    uint8_t buf[32];
    if (n + 1 > sizeof(buf)) {
        return ESP_ERR_INVALID_SIZE;
    }
    buf[0] = CONTROL_COMMAND;
    memcpy(buf + 1, cmds, n);
    return i2c_master_transmit(s_dev, buf, n + 1, I2C_TIMEOUT_MS);
}

static esp_err_t panel_init(void)
{
    // The SH1106 takes the same sequence but for its DC-DC switch in place of
    // the charge pump, its own pre-charge, and no horizontal addressing mode:
    // panel_push writes it a page at a time.
    static const uint8_t ssd1306[] = {
        0xAE,       // display off
        0xD5, 0x80, // clock divide
        0xA8, 0x3F, // 64 rows
        0xD3, 0x00, // no offset
        0x40,       // start line 0
        0x8D, 0x14, // charge pump on
        0x20, 0x00, // horizontal addressing
        0xA1,       // columns mirrored
        0xC8,       // rows mirrored
        0xDA, 0x12, // COM pins
        0x81, 0xCF, // contrast
        0xD9, 0xF1, // pre-charge
        0xDB, 0x40, // VCOMH
        0xA4,       // show RAM
        0xA6,       // not inverted
        0xAF,       // display on
    };
    static const uint8_t sh1106[] = {
        0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40,
        0xAD, 0x8B, // DC-DC on
        0xA1, 0xC8, 0xDA, 0x12, 0x81, 0xCF, 0xD9, 0x22, 0xDB, 0x40, 0xA4, 0xA6, 0xAF,
    };
    return s_kind == AH_DISPLAY_SH1106 ? commands(sh1106, sizeof(sh1106)) : commands(ssd1306, sizeof(ssd1306));
}

static esp_err_t panel_power(bool on)
{
    const uint8_t cmd = on ? 0xAF : 0xAE;
    return commands(&cmd, 1);
}

static esp_err_t panel_push(void)
{
    if (s_kind == AH_DISPLAY_SH1106) {
        for (uint8_t page = 0; page < AH_SCREEN_H / 8; ++page) {
            const uint8_t at[3] = {(uint8_t)(0xB0 | page), SH1106_COLUMN_OFFSET & 0x0F,
                                   0x10 | (SH1106_COLUMN_OFFSET >> 4)
                                  };
            ESP_RETURN_ON_ERROR(commands(at, sizeof(at)), TAG, "page");
            s_out[0] = CONTROL_DATA;
            memcpy(s_out + 1, s_fb + page * AH_SCREEN_W, AH_SCREEN_W);
            ESP_RETURN_ON_ERROR(i2c_master_transmit(s_dev, s_out, AH_SCREEN_W + 1, I2C_TIMEOUT_MS), TAG, "data");
        }
        return ESP_OK;
    }
    static const uint8_t window[] = {0x21, 0, AH_SCREEN_W - 1, 0x22, 0, AH_SCREEN_H / 8 - 1};
    ESP_RETURN_ON_ERROR(commands(window, sizeof(window)), TAG, "window");
    // The whole frame in one transaction: clone controllers lose the RAM
    // pointer across a stop and start, and a chunked write visibly tears.
    s_out[0] = CONTROL_DATA;
    memcpy(s_out + 1, s_fb, AH_SCREEN_FB_BYTES);
    return i2c_master_transmit(s_dev, s_out, sizeof(s_out), I2C_TIMEOUT_MS);
}

static void display_task(void *arg)
{
    (void)arg;
    const int64_t boot_until = esp_timer_get_time() / 1000 + BOOT_SPLASH_MS;
    int64_t dark_at = boot_until + CONFIG_AH_DISPLAY_ON_S * 1000LL;
    bool lit = true;
    bool was_pressed = false;
    int failures = 0;
    for (;;) {
        const int64_t now = esp_timer_get_time() / 1000;
        const bool pressed = s_button >= 0 && gpio_get_level(s_button) == 0;
        if (pressed && !was_pressed) {
            dark_at = now + CONFIG_AH_DISPLAY_ON_S * 1000LL;
            if (!lit && panel_power(true) == ESP_OK) {
                lit = true;
            }
        }
        was_pressed = pressed;
        if (lit) {
            if (now < boot_until) {
                ah_screen_render_boot(s_fb, s_nickname);
            } else {
                ah_screen_model_t m;
                taskENTER_CRITICAL(&s_mux);
                m = s_model;
                taskEXIT_CRITICAL(&s_mux);
                ah_screen_render(s_fb, &m);
            }
            failures = panel_push() == ESP_OK ? 0 : failures + 1;
            if (failures >= FAILURES_BEFORE_GIVING_UP) {
                ESP_LOGE(TAG, "panel not answering; display off until reboot");
                vTaskDelete(NULL);
            }
            if (now >= dark_at && panel_power(false) == ESP_OK) {
                lit = false;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(REFRESH_MS));
    }
}

void ah_display_update(const ah_screen_model_t *model)
{
    if (!s_started) {
        return;
    }
    const uint32_t delta = model->relayed - s_last_relayed;
    s_last_relayed = model->relayed;
    taskENTER_CRITICAL(&s_mux);
    uint8_t activity[AH_SCREEN_W];
    memcpy(activity, s_model.activity + 1, AH_SCREEN_W - 1);
    activity[AH_SCREEN_W - 1] = delta > UINT8_MAX ? UINT8_MAX : (uint8_t)delta;
    s_model = *model;
    memcpy(s_model.activity, activity, sizeof(activity));
    memcpy(s_model.nickname, s_nickname, sizeof(s_model.nickname));
    taskEXIT_CRITICAL(&s_mux);
}

esp_err_t ah_display_start(const ah_board_t *board, const char *nickname)
{
    if (board->display == AH_DISPLAY_NONE || CONFIG_AH_DISPLAY_ON_S == 0) {
        return ESP_OK;
    }
    s_kind = board->display;
    snprintf(s_nickname, sizeof(s_nickname), "%s", nickname);
    if (board->display_rst >= 0) {
        ESP_RETURN_ON_ERROR(gpio_reset_pin(board->display_rst), TAG, "rst");
        ESP_RETURN_ON_ERROR(gpio_set_direction(board->display_rst, GPIO_MODE_OUTPUT), TAG, "rst out");
        // Busy waits: 5 ms is under one tick at FreeRTOS's 100 Hz.
        gpio_set_level(board->display_rst, 0);
        esp_rom_delay_us(5000);
        gpio_set_level(board->display_rst, 1);
        esp_rom_delay_us(5000);
    }
    const i2c_master_bus_config_t bus_cfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = board->display_sda,
        .scl_io_num = board->display_scl,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t bus = NULL;
    ESP_RETURN_ON_ERROR(i2c_new_master_bus(&bus_cfg, &bus), TAG, "bus");
    if (i2c_master_probe(bus, PANEL_ADDR, I2C_TIMEOUT_MS) != ESP_OK) {
        ESP_LOGI(TAG, "no panel; running headless");
        i2c_del_master_bus(bus);
        return ESP_OK;
    }
    const i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PANEL_ADDR,
        .scl_speed_hz = I2C_HZ,
    };
    esp_err_t err = i2c_master_bus_add_device(bus, &dev_cfg, &s_dev);
    if (err == ESP_OK) {
        err = panel_init();
        if (err != ESP_OK) {
            i2c_master_bus_rm_device(s_dev);
            s_dev = NULL;
        }
    }
    if (err != ESP_OK) {
        // The node runs headless; the bus goes back for anything else.
        i2c_del_master_bus(bus);
        ESP_LOGE(TAG, "panel did not take its setup (%s)", esp_err_to_name(err));
        return err;
    }
    if (board->button >= 0) {
        s_button = board->button;
        ESP_RETURN_ON_ERROR(gpio_reset_pin(s_button), TAG, "button");
        ESP_RETURN_ON_ERROR(gpio_set_direction(s_button, GPIO_MODE_INPUT), TAG, "button in");
        ESP_RETURN_ON_ERROR(gpio_set_pull_mode(s_button, GPIO_PULLUP_ONLY), TAG, "button pull");
    }
    s_started = true;
    ESP_RETURN_ON_FALSE(xTaskCreate(display_task, "display", TASK_STACK, NULL, TASK_PRIORITY, NULL) == pdPASS,
                        ESP_ERR_NO_MEM, TAG, "task");
    return ESP_OK;
}
