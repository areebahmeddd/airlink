#ifndef SX1262_H
#define SX1262_H

/* Minimal SX1262 LoRa driver for the Wio-SX1262 module (ESP-IDF native).
 *
 * Covers exactly what the Bitle trunk needs: presence detection, LoRa
 * modem configuration, interrupt-driven RX, one-shot TX, and channel
 * activity detection (CAD) for listen-before-talk. Written against the
 * Semtech SX1261/2 datasheet command set; board specifics (TCXO on DIO3
 * at 1.8 V, DIO2 as TX RF switch, GPIO-driven RXEN) match the Seeed
 * Wio-SX1262 as configured by its shipping Meshtastic variant.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#include "lora_region.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SX1262_MAX_PAYLOAD 255

typedef struct {
    int pin_sck;
    int pin_miso;
    int pin_mosi;
    int pin_cs;
    int pin_reset;
    int pin_busy;
    int pin_dio1;
    int pin_rxen;      /* -1 if not board-controlled */
    uint32_t freq_hz;
    uint8_t sf;        /* 7..12 */
    uint32_t bw_hz;    /* 125000 / 250000 / 500000 */
    uint8_t cr;        /* 5..8 => 4/5..4/8 */
    uint16_t preamble_symbols;
    int8_t tx_dbm;     /* up to +22 */
    lora_region_id_t region;
} sx1262_config_t;

typedef struct {
    uint32_t command_errors;
    uint32_t busy_timeouts;
    uint32_t recoveries;
    uint32_t recovery_failures;
} sx1262_diag_t;

typedef enum {
    SX1262_EVT_NONE = 0,
    SX1262_EVT_TX_DONE,
    SX1262_EVT_RX_DONE,
    SX1262_EVT_RX_CRC_ERROR,
    SX1262_EVT_CAD_CLEAR,     /* CAD finished, channel free */
    SX1262_EVT_CAD_BUSY,      /* CAD finished, activity detected */
    SX1262_EVT_TIMEOUT,
    SX1262_EVT_ERROR,
} sx1262_event_t;

/* Probes for the radio non-destructively (scratch register write/read).
 * Safe to call on boards without the module: returns false. */
bool sx1262_detect(const sx1262_config_t *cfg);

/* Full init to RX-continuous. Requires a prior successful detect. */
esp_err_t sx1262_init(const sx1262_config_t *cfg, void (*dio1_isr_notify)(void *arg), void *arg);

/* Reads and clears the IRQ status, translating it to one event. */
sx1262_event_t sx1262_poll_event(void);

/* Fetches the packet that raised RX_DONE. Returns length, 0 on error.
 * rssi_dbm/snr_db may be NULL. RSSI saturates to 0 at very short range. */
uint16_t sx1262_read_packet(uint8_t *buf, uint16_t max_len, int16_t *rssi_dbm, int8_t *snr_db);

/* Transmits one frame (blocking only for the command, not completion;
 * TX_DONE arrives as an event). Radio returns to RX after TX_DONE via
 * sx1262_resume_rx(). */
esp_err_t sx1262_transmit(const uint8_t *data, uint16_t len);

/* Starts a CAD; result arrives as CAD_CLEAR or CAD_BUSY. */
esp_err_t sx1262_start_cad(void);

/* Re-enters continuous RX (after TX_DONE or CAD). */
esp_err_t sx1262_resume_rx(void);

/* Resets, reconfigures, verifies critical registers, and re-enters RX.
 * Recovery is bounded and leaves the driver not-ready if both attempts fail. */
esp_err_t sx1262_recover(void);

/* Independent software watchdog interval for a frame of this size. It is
 * longer than the airtime-derived radio timeout and does not depend on IRQs. */
uint32_t sx1262_tx_watchdog_ms(uint16_t len);

/* Snapshot low-level command and recovery diagnostics. */
void sx1262_get_diag(sx1262_diag_t *out);

#ifdef __cplusplus
}
#endif

#endif // SX1262_H
