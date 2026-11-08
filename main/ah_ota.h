// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Firmware updates from node to node (docs/OTA.md). A node running a newer
// image offers its signed manifest to a neighbor node running an older one;
// the neighbor pulls the image piece by piece, checks it whole against the
// manifest, and boots it on a rollback trial.
//
// Link-local by construction: every OTA packet has TTL 0, is addressed to the
// neighbor, goes only on a BLE link to a peer announcing itself as a node, and
// never enters the mesh. A phone never sees one and never relays one.
//
// Runs on the mesh task: every call but ah_ota_init (app_main) and
// ah_ota_running_version (any task) comes from it.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ah_node.h"
#include "ah_settings.h"

// Read the update state at boot: whether this image is on trial, and
// whether a stored manifest lets the node serve it.
//
// With no owner key provisioned the node neither serves nor accepts images;
// the rollback trial still runs.
esp_err_t ah_ota_init(const ah_settings_t *settings, const char *board);

// An OTA packet arrived on `link`.
void ah_ota_on_frame(ah_node_t *node, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms);

// Retries, offers, the trial's health check and the reboot into a new image.
void ah_ota_tick(ah_node_t *node, int64_t now_ms);

// The running image's version as the announce carries it: major << 16 | minor << 8 | patch.
uint32_t ah_ota_running_version(void);
