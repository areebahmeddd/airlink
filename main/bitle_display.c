/* SSD1306 128x64 status display (Heltec WiFi LoRa 32 V3 built-in OLED).
 * Auto-detected on I2C like the radio is probed: absent display -> the node
 * runs headless. All drawing happens in the portable bitle_screen renderer;
 * this file is only I2C transport plus the refresh task. */

#include "bitle_display.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bitle_lora.h"
#include "bitle_screen.h"
#include "bitle_stats.h"
#include "bitchat_ble.h"
#include "noise_handshake.h"

#if CONFIG_BITLE_DISPLAY

static const char *TAG = "bitle_display";

#define SSD1306_ADDR        0x3C
#define CTRL_CMD            0x00
#define CTRL_DATA           0x40
#define REFRESH_MS          125
#define I2C_FREQ_HZ         200000
#define WAKE_MS             (CONFIG_BITLE_DISPLAY_ON_SECS * 1000U)
#define BOOT_SCREEN_MS      2500

static i2c_master_dev_handle_t s_dev;
static uint8_t s_fb[BITLE_SCREEN_FB_BYTES];
static bool s_active;

static esp_err_t ssd1306_cmds(const uint8_t *cmds, size_t len)
{
    uint8_t buf[32];
    if (len + 1 > sizeof(buf)) {
        return ESP_ERR_INVALID_SIZE;
    }
    buf[0] = CTRL_CMD;
    memcpy(buf + 1, cmds, len);
    return i2c_master_transmit(s_dev, buf, len + 1, 100);
}

static esp_err_t ssd1306_init_seq(void)
{
    static const uint8_t seq[] = {
        0xAE,       /* display off */
        0xD5, 0x80, /* clock divide */
        0xA8, 0x3F, /* multiplex 64 */
        0xD3, 0x00, /* display offset */
        0x40,       /* start line 0 */
        0x8D, 0x14, /* charge pump on */
        0x20, 0x00, /* horizontal addressing */
        0xA1,       /* segment remap (flip X) */
        0xC8,       /* COM scan descending (flip Y) */
        0xDA, 0x12, /* COM pins config */
        0x81, 0xFF, /* contrast: max (charge pump sags with many lit pixels) */
        0xD9, 0xF1, /* pre-charge */
        0xDB, 0x40, /* VCOMH level */
        0xA4,       /* display from RAM */
        0xA6,       /* normal (non-inverted) */
        0xAF,       /* display on */
    };
    return ssd1306_cmds(seq, sizeof(seq));
}

static esp_err_t ssd1306_push(const uint8_t *fb)
{
    static const uint8_t win[] = { 0x21, 0, 127, 0x22, 0, 7 };
    esp_err_t err = ssd1306_cmds(win, sizeof(win));
    if (err != ESP_OK) {
        return err;
    }
    /* The whole frame in ONE transaction. Chunked writes with a STOP after
     * each chunk visibly tear on these modules (the GDDRAM pointer is not
     * reliably preserved across STOP/START on clone controllers), which is
     * why every working library (Adafruit/u8g2) blasts 1025 bytes at once. */
    static uint8_t buf[BITLE_SCREEN_FB_BYTES + 1];
    buf[0] = CTRL_DATA;
    memcpy(buf + 1, fb, BITLE_SCREEN_FB_BYTES);
    return i2c_master_transmit(s_dev, buf, sizeof(buf), 100);
}

static void display_task(void *arg)
{
    (void)arg;
    int consecutive_failures = 0;
    bool on = true;
    bool btn_was_down = false;
    uint64_t boot_until = esp_timer_get_time() / 1000ULL + BOOT_SCREEN_MS;
    uint64_t off_at = esp_timer_get_time() / 1000ULL + WAKE_MS;
    for (;;) {
        uint64_t now = esp_timer_get_time() / 1000ULL;

#if CONFIG_BITLE_DISPLAY_BUTTON_PIN >= 0
        /* User button (active low, two samples = debounce): wakes the
         * display and re-arms the auto-off timer. */
        bool btn_down = gpio_get_level(CONFIG_BITLE_DISPLAY_BUTTON_PIN) == 0;
        if (btn_down && !btn_was_down) {
            if (!on) {
                static const uint8_t disp_on[] = { 0xAF };
                if (ssd1306_cmds(disp_on, sizeof(disp_on)) == ESP_OK) {
                    on = true;
                    consecutive_failures = 0;
                }
            }
            off_at = now + WAKE_MS;
        }
        btn_was_down = btn_down;
#endif

        if (on) {
            bitle_stats_t st;
            bitle_stats_get(&st);

            bitle_screen_model_t m = { 0 };
            const char *nick = noise_get_nickname();
            if (nick) {
                snprintf(m.nickname, sizeof(m.nickname), "%s", nick);
            }
            m.ble_links = bitchat_ble_link_count();
            m.peers_seen = st.peers_seen;
            m.trunk_up = bitle_lora_active();
            m.rx_total = st.rx_total;
            m.tx_total = st.tx_total;
            m.now_ms = (uint32_t)now;
            m.event_count = st.event_count;
            memcpy(m.events, st.events, sizeof(st.events));

            if (now < boot_until) {
                bitle_screen_render_boot(s_fb, &m);
            } else {
                bitle_screen_render(s_fb, &m);
            }
            esp_err_t err = ssd1306_push(s_fb);
            if (err != ESP_OK) {
                /* A display that NACKs mid-frame has a marginal rail or
                 * wiring (seen on one field unit). Don't spam the bus
                 * forever: give up until the next reboot. */
                if (++consecutive_failures >= 25) {
                    ESP_LOGE(TAG, "display not responding; disabling until reboot");
                    vTaskDelete(NULL);
                }
            } else {
                consecutive_failures = 0;
            }

            if (now >= off_at) {
                static const uint8_t disp_off[] = { 0xAE };
                if (ssd1306_cmds(disp_off, sizeof(disp_off)) == ESP_OK) {
                    on = false;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(REFRESH_MS));
    }
}

esp_err_t bitle_display_init(void)
{
#if defined(CONFIG_BITLE_LORA_VEXT_PIN) && CONFIG_BITLE_LORA_VEXT_PIN >= 0
    /* The OLED shares the Vext rail with the radio on Heltec boards; power
     * it here too so the display works even with the trunk NVS-disabled.
     * Idempotent when the LoRa init already drove it. */
    gpio_reset_pin(CONFIG_BITLE_LORA_VEXT_PIN);
    gpio_set_direction(CONFIG_BITLE_LORA_VEXT_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(CONFIG_BITLE_LORA_VEXT_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
#endif

#if CONFIG_BITLE_DISPLAY_PIN_RST >= 0
    gpio_reset_pin(CONFIG_BITLE_DISPLAY_PIN_RST);
    gpio_set_direction(CONFIG_BITLE_DISPLAY_PIN_RST, GPIO_MODE_OUTPUT);
    gpio_set_level(CONFIG_BITLE_DISPLAY_PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(5));
    gpio_set_level(CONFIG_BITLE_DISPLAY_PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(5));
#endif

    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = CONFIG_BITLE_DISPLAY_PIN_SDA,
        .scl_io_num = CONFIG_BITLE_DISPLAY_PIN_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t bus;
    esp_err_t err = i2c_new_master_bus(&bus_cfg, &bus);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "I2C bus init failed: %s", esp_err_to_name(err));
        return err;
    }
    err = i2c_master_probe(bus, SSD1306_ADDR, 100);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "no SSD1306 display; running headless");
        i2c_del_master_bus(bus);
        return ESP_OK;
    }
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = SSD1306_ADDR,
        .scl_speed_hz = I2C_FREQ_HZ,
    };
    err = i2c_master_bus_add_device(bus, &dev_cfg, &s_dev);
    if (err == ESP_OK) {
        err = ssd1306_init_seq();
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "display init failed: %s", esp_err_to_name(err));
        return err;
    }
    s_active = true;
#if CONFIG_BITLE_DISPLAY_BUTTON_PIN >= 0
    gpio_reset_pin(CONFIG_BITLE_DISPLAY_BUTTON_PIN);
    gpio_set_direction(CONFIG_BITLE_DISPLAY_BUTTON_PIN, GPIO_MODE_INPUT);
    gpio_set_pull_mode(CONFIG_BITLE_DISPLAY_BUTTON_PIN, GPIO_PULLUP_ONLY);
#endif
    xTaskCreate(display_task, "bitle_disp", 4096, NULL, tskIDLE_PRIORITY + 2, NULL);
    ESP_LOGI(TAG, "display up: SSD1306 128x64 @0x%02X", SSD1306_ADDR);
    return ESP_OK;
}

#else /* !CONFIG_BITLE_DISPLAY */

esp_err_t bitle_display_init(void)
{
    return ESP_OK;
}

#endif
