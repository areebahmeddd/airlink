// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The courier mailbox's flash copy, an NVS partition of its own.
//
// One entry per envelope, written whole (again when its spray budget changes,
// under the same key) and erased whole: NVS commits an entry atomically, and
// writes a key's new version before erasing the old, so a power cut mid-write
// leaves either the old state or the new one, never a torn envelope. The RAM
// copy in the protocol core is the working set; this is what survives a reboot.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ah_node.h"

// Open the partition. Call after nvs_flash_init.
esp_err_t ah_mailbox_init(void);

// Persist one envelope with its depositor. Called from the mesh task.
void ah_mailbox_put(uint32_t record, uint64_t depositor, const uint8_t *envelope, size_t len);
void ah_mailbox_delete(uint32_t record);

// Hand every persisted envelope to the node. Call before the mesh starts.
void ah_mailbox_restore(ah_node_t *node);

esp_err_t ah_mailbox_erase_all(void);
