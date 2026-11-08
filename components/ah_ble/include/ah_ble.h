// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The BLE transport: the bitchat GATT service as a peripheral for phones, and
// a central that dials other relay nodes. Bytes only: every decision about a
// frame is the mesh task's.
//
// NimBLE runs its callbacks on its own host task. Each one copies what it
// needs into the events below and returns; the events must only enqueue.
//
// A link's handle is its connection handle with a generation above it
// (generation << 16 | connection). NimBLE hands a freed connection handle to
// the next connection at once, so a handle the mesh still holds for a link
// that went away never names the connection that took its place.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    // A link opened. A phone (or a node that dialed us) is reported on
    // connecting, before it subscribes; a node we dialed once we have
    // subscribed to it.
    void (*link_up)(uint32_t handle, uint16_t max_write);
    void (*link_down)(uint32_t handle);
    // The largest single write on a link changed (ATT MTU less 3).
    void (*mtu)(uint32_t handle, uint16_t max_write);
    // One whole frame: a write to our characteristic or a notification from a node.
    void (*frame)(uint32_t handle, const uint8_t *data, size_t len);
    // A peer subscribed to our notifications: writes refused as unsubscribed can go now.
    void (*ready)(uint32_t handle);
} ah_ble_events_t;

typedef struct {
    uint16_t adv_interval_ms;
    uint8_t max_node_links; // outbound links to other nodes
    uint8_t reserved_for_phones;
    uint32_t scan_every_ms;
    uint32_t scan_for_ms;
} ah_ble_config_t;

typedef enum {
    AH_BLE_WRITE_OK = 0,
    AH_BLE_WRITE_BUSY,         // no room in the host; poll again
    AH_BLE_WRITE_UNSUBSCRIBED, // not subscribed yet; `ready` follows when it is, so there is nothing to poll
    AH_BLE_WRITE_GONE,
} ah_ble_write_t;

// Bring up NimBLE, register the service and start advertising. Call once, from app_main.
esp_err_t ah_ble_start(const ah_ble_config_t *config, const ah_ble_events_t *events);

// Write one frame on a link: a notification to a phone, a write without
// response to a node we dialed. Copies before returning. Called from the mesh
// task; NimBLE serializes it against its host task.
ah_ble_write_t ah_ble_write(uint32_t handle, const uint8_t *frame, size_t len);

// A periodic scan for other nodes, when one could be dialed; call from the
// mesh task's timer.
void ah_ble_scan_tick(int64_t now_ms);

// Ask a node-to-node link for LE Coded PHY. A preference the link layer may
// decline; asked once per link.
void ah_ble_prefer_coded_phy(uint32_t handle);

// Disconnect a link the mesh refuses to keep (its tables are full).
void ah_ble_drop(uint32_t handle);

typedef struct {
    uint32_t handle;
    uint16_t max_write;
    bool open;     // reported by link_up: a phone from connecting, a node we dialed once subscribed
    bool writable; // takes frames now
} ah_ble_conn_t;

// The live connections as the transport holds them, for the mesh task to
// check its links against when an event was lost. Writes at most `cap` and
// returns how many.
size_t ah_ble_connections(ah_ble_conn_t *out, size_t cap);

// Disconnect a link that never proved who is on it. A node we dialed is not
// dialed again for a while: a device that merely advertises the node name
// would otherwise take a dial slot back at every scan.
void ah_ble_drop_unbound(uint32_t handle);
