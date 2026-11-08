// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The LoRa transport: the SX1262 and the trunk link layer on a task of their
// own. Each trunk neighbor is a link to the mesh, named by a handle; the mesh
// writes whole bitchat packets to it and gets whole packets back.
//
// The LoRa task owns the radio and the trunk. The events (ah_lora_events_t)
// run on that task and must only enqueue. ah_lora_send, ah_lora_set_bound,
// ah_lora_links and ah_lora_status may be called from any one other task
// (the mesh task).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ah_lora_region.h"
#include "ah_trunk.h"

typedef struct {
    // A trunk neighbor was heard: a new link, to the node `node` names.
    void (*link_up)(uint32_t handle, uint16_t max_write, const uint8_t node[AH_TRUNK_NODE_LEN]);
    void (*link_down)(uint32_t handle);
    // One whole packet from a neighbor.
    void (*frame)(uint32_t handle, const uint8_t *packet, size_t len);
    // A link that refused a send has room again.
    void (*ready)(uint32_t handle);
} ah_lora_events_t;

// How the board wires the radio and what its RF path can do.
typedef struct {
    int pin_sck;
    int pin_miso;
    int pin_mosi;
    int pin_nss;
    int pin_reset;
    int pin_busy;
    int pin_dio1;
    int pin_rxen;               // high while receiving; -1 none
    int pin_txen;               // high while transmitting (a front end's PA); -1 none
    bool dio2_rf_switch;
    uint16_t tcxo_mv;           // 0 for a crystal
    int8_t radio_max_dbm;       // the highest SX1262 setting the RF path tolerates
    // A front end's measured gain in dB at each SX1262 setting from 0 dBm
    // up; NULL for none. Below 0 dBm the first entry applies, past the table
    // the last.
    const uint8_t *fem_gain_db;
    uint8_t fem_points;
} ah_lora_radio_t;

typedef struct {
    ah_lora_radio_t radio;
    ah_lora_region_id_t region;
    int16_t antenna_gain_ddbi;  // tenths of a dBi
    uint8_t self[AH_TRUNK_NODE_LEN];
    uint8_t key[AH_TRUNK_KEY_LEN];  // this node's static key, which `self` names
    // The pair key with another node, under this node's secret
    // (ah_trunk_auth_pair_key); runs on the LoRa task, once for each node met.
    bool (*pair_key)(const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                     uint8_t out[AH_TRUNK_KEY_LEN]);
    uint32_t task_stack;
    uint8_t task_priority;
    int task_core;
} ah_lora_config_t;

typedef struct {
    bool running;
    uint8_t neighbors;
    uint32_t airtime_ms;        // spent in the duty window
    uint32_t budget_ms;         // allowed in the duty window
    int8_t max_power_dbm;       // conducted, at the antenna port
    ah_trunk_stats_t trunk;
    uint32_t cad_busy;
    uint32_t cad_forced;        // sent after every channel check found the channel busy
    uint32_t rx_yields;         // a channel check or answer held back for a frame arriving
} ah_lora_status_t;

// Find, configure and start the radio and its task. Call once, from app_main.
// Returns ESP_ERR_NOT_FOUND when the board has no working radio (the node runs
// on BLE alone), ESP_ERR_INVALID_ARG without a region.
esp_err_t ah_lora_start(const ah_lora_config_t *config, const ah_lora_events_t *events);

typedef enum {
    AH_LORA_SEND_OK = 0,
    AH_LORA_SEND_BUSY, // no room now; `ready` follows
    AH_LORA_SEND_GONE, // the handle names no live link
} ah_lora_send_t;

// Hand a packet to the trunk for one link, copied before returning.
// Never displaces a packet already accepted: a full queue refuses.
ah_lora_send_t ah_lora_send(uint32_t handle, const uint8_t *packet, size_t len, uint8_t prio);

// The mesh verified the announce of the neighbor behind `handle`, the node
// its link_up named. Returns false when the trunk was too busy to take it
// now; ask again later.
bool ah_lora_set_bound(uint32_t handle);

typedef struct {
    uint32_t handle;
    uint8_t node[AH_TRUNK_NODE_LEN];
    bool room; // ah_lora_send would take a packet for it now
} ah_lora_link_t;

// The live trunk neighbors by handle, for the mesh task to check its LoRa
// links against when an event was lost. Returns false, with nothing written,
// when the trunk is not running or too busy to say now; ask again later.
bool ah_lora_links(ah_lora_link_t out[AH_TRUNK_NEIGHBORS], size_t *count);

// A snapshot for logs and the display; zeroed when the trunk is not running.
void ah_lora_status(ah_lora_status_t *out);
