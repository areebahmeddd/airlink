// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// SX1262 driver: the LoRa modem set up for one fixed channel, interrupt-driven
// receive, one-shot transmit and channel activity detection. Written against
// the Semtech SX1261/2 datasheet (rev 2.1) command set, errata included.
//
// Owned by the LoRa task: no call is safe from any other task or from an ISR.
// The DIO1 handler given to ah_sx1262_init only signals; ah_sx1262_poll then
// reads and clears the cause.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ah_lora_airtime.h"

#define AH_SX1262_FRAME_MAX 255u
// The high-power PA's range in SetTxParams, in dBm.
#define AH_SX1262_POWER_MIN (-9)
#define AH_SX1262_POWER_MAX 22

typedef struct {
    int pin_sck;
    int pin_miso;
    int pin_mosi;
    int pin_nss;
    int pin_reset;
    int pin_busy;
    int pin_dio1;
    int pin_rxen;            // driven high while receiving, low to transmit; -1 none
    int pin_txen;            // driven high to transmit, low while receiving (a front end's PA); -1 none
    bool dio2_rf_switch;     // DIO2 switches the antenna path
    uint16_t tcxo_mv;        // TCXO supply on DIO3 in millivolts; 0 for a crystal
    uint32_t frequency_hz;
    ah_lora_phy_t phy;
    uint16_t sync_word;
} ah_sx1262_config_t;

typedef enum {
    AH_SX1262_EVENT_NONE = 0,
    AH_SX1262_EVENT_TX_DONE,
    AH_SX1262_EVENT_RX_DONE,
    AH_SX1262_EVENT_RX_BAD,   // a header or CRC error: nothing to read
    AH_SX1262_EVENT_CAD_CLEAR,
    AH_SX1262_EVENT_CAD_BUSY,
    AH_SX1262_EVENT_TIMEOUT,
    AH_SX1262_EVENT_ERROR,    // the radio stopped answering; recover it
} ah_sx1262_event_t;

// Reset, configure and verify the radio, then listen; `dio1_isr` runs from the
// GPIO ISR on each DIO1 rising edge. Returns ESP_ERR_NOT_FOUND when no SX126x
// answers on the bus (a board without the radio), ESP_ERR_INVALID_ARG for a
// configuration the chip cannot run.
esp_err_t ah_sx1262_init(const ah_sx1262_config_t *cfg, void (*dio1_isr)(void *arg), void *arg);

// Read and clear the interrupt cause.
ah_sx1262_event_t ah_sx1262_poll(void);

// Copy the frame that raised RX_DONE into `buf`, setting `len` to its length
// and `snr_db` and `rssi_dbm` to what the radio measured it at.
esp_err_t ah_sx1262_read(uint8_t *buf, size_t cap, size_t *len, int8_t *snr_db, int16_t *rssi_dbm);

// Start a transmission at `power_dbm` (the SX1262's own setting); TX_DONE follows.
// Returns ESP_ERR_NOT_FINISHED while a frame is arriving (see ah_sx1262_cad): nothing was done.
esp_err_t ah_sx1262_transmit(const uint8_t *frame, size_t len, int8_t power_dbm);

// Start channel activity detection; CAD_CLEAR or CAD_BUSY follows.
// Returns ESP_ERR_NOT_FINISHED while a frame whose header the modem accepted is still
// arriving, or one has ended and its event is not yet taken: leaving receive
// would destroy it. The radio keeps listening; ask again later.
esp_err_t ah_sx1262_cad(void);

// Listen continuously (after TX done, CAD or a backoff).
esp_err_t ah_sx1262_receive(void);

// Reset and reconfigure a radio that stopped answering, then listen.
esp_err_t ah_sx1262_recover(void);

// While listening: whether the radio is still set up as configured and still
// receiving. ESP_ERR_INVALID_STATE when it reset on its own; recover it.
esp_err_t ah_sx1262_check(void);

// The longest a transmission of `len` bytes may take before the radio is declared stuck.
uint32_t ah_sx1262_tx_deadline_ms(size_t len);
