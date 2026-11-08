// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The mesh task: sole owner of the protocol core, the OTA state and the status
// snapshot. Transports post events here from their own tasks and callbacks;
// nothing else touches the node.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ah_lora.h"
#include "ah_links.h"
#include "ah_node.h"
#include "ah_screen.h"
#include "ah_settings.h"

// Create the event queue, so a transport started before the node may post to
// it: call before any transport starts.
esp_err_t ah_app_init(void);

// Start the node and its task. `lora` says what the board's trunk is doing.
esp_err_t ah_app_start(const ah_settings_t *settings, ah_screen_lora_t lora);

// Posting functions for transports: copy, queue, return. Safe from any task
// (not from an ISR). A frame is dropped, and counted, once only the slots kept
// for control events are left; a link coming, going or becoming ready waits
// up to 50 ms for a slot before it is dropped and counted (a lost Bluetooth
// one is made good within a second, from the transport's own table).
// `node` is the node ID a LoRa link is to, NULL for Bluetooth.
void ah_app_post_link_up(ah_link_kind_t kind, uint32_t handle, uint16_t max_write, const uint8_t *node);
void ah_app_post_link_down(ah_link_kind_t kind, uint32_t handle);
void ah_app_post_mtu(ah_link_kind_t kind, uint32_t handle, uint16_t max_write);
void ah_app_post_ready(ah_link_kind_t kind, uint32_t handle);
void ah_app_post_frame(ah_link_kind_t kind, uint32_t handle, const uint8_t *data, size_t len);

typedef struct {
    ah_node_stats_t node;
    ah_lora_status_t lora;
    uint32_t dropped_events;
    int64_t uptime_ms;
    uint32_t longest_pass_ms; // the mesh task's longest gap between watchdog feeds (10 s panics)
} ah_app_status_t;

// The latest snapshot, refreshed once a second. Safe from any task.
void ah_app_status(ah_app_status_t *out);
