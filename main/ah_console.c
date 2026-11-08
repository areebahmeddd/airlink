// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Runs on the console's own task (esp_console's REPL). It reads the mesh
// task's snapshot and writes NVS; it never touches the node.
#include "ah_console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_check.h"
#include "esp_console.h"
#include "esp_core_dump.h"
#include "esp_log.h"
#include "esp_system.h"
#include "sdkconfig.h"

#include "ah_app.h"
#include "ah_clock.h"
#include "ah_crypto.h"
#include "ah_ota.h"

static const char *TAG = "ah_console";

// The owner key's fingerprint: SHA-256 of the key, cut to 8 bytes, as
// tools/ota_manifest.py keygen prints it.
#define FINGERPRINT_LEN 8u
// The panic handler's own description of a crash, as ESP-IDF's example sizes it.
#define PANIC_REASON_LEN 200u

// What NVS holds, which a provisioning write changes at once; the running node
// takes it at its next boot.
static ah_settings_t s_settings;
static bool s_reboot_pending;
static const char *s_board;

static void print_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        printf("%02x", p[i]);
    }
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Exactly n bytes as 2n hex digits. sscanf's %x is no check: it takes a sign
// or a 0x, so "-1" would read as ff, and the owner key is written once.
static bool parse_hex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != n * 2) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        const int hi = hex_digit(s[2 * i]);
        const int lo = hex_digit(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

static void print_fingerprint(const uint8_t key[AH_KEY_LEN])
{
    uint8_t fp[AH_SHA256_LEN];
    ah_sha256(key, AH_KEY_LEN, fp);
    print_hex(fp, FINGERPRINT_LEN);
}

static int report(esp_err_t err, const char *done)
{
    if (err == ESP_ERR_INVALID_STATE) {
        printf("refused: provisioning is locked, or the value is write-once and set\n");
    } else if (err != ESP_OK) {
        printf("failed: %s\n", esp_err_to_name(err));
    } else {
        s_reboot_pending = true;
        printf("%s; takes effect after `reboot`\n", done);
    }
    return err == ESP_OK ? 0 : 1;
}

const char *ah_console_reset_reason(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON:
        return "power-on";
    case ESP_RST_EXT:
        return "reset pin";
    case ESP_RST_SW:
        return "restart";
    case ESP_RST_PANIC:
        return "crash";
    case ESP_RST_INT_WDT:
        return "interrupt watchdog";
    case ESP_RST_TASK_WDT:
        return "task watchdog";
    case ESP_RST_WDT:
        return "watchdog";
    case ESP_RST_DEEPSLEEP:
        return "deep sleep";
    case ESP_RST_BROWNOUT:
        return "brownout";
    case ESP_RST_USB:
        return "USB";
    case ESP_RST_JTAG:
        return "JTAG";
    case ESP_RST_EFUSE:
        return "eFuse error";
    case ESP_RST_PWR_GLITCH:
        return "power glitch";
    case ESP_RST_CPU_LOCKUP:
        return "CPU lockup";
    default:
        return "unknown";
    }
}

static int cmd_status(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    ah_app_status_t st;
    ah_app_status(&st);
    const ah_identity_t *id = &s_settings.identity;
    const uint32_t v = ah_ota_running_version();
    printf("airlink %lu.%lu.%lu on %s\n", (unsigned long)(v >> 16), (unsigned long)((v >> 8) & 0xFF),
           (unsigned long)(v & 0xFF), s_board);
    printf("peer %02x%02x%02x%02x%02x%02x%02x%02x  nickname %.*s\n", id->peer_id[0], id->peer_id[1],
           id->peer_id[2], id->peer_id[3], id->peer_id[4], id->peer_id[5], id->peer_id[6], id->peer_id[7],
           id->nickname_len, (const char *)id->nickname);
    const ah_lora_region_t *region = ah_lora_region(s_settings.region);
    // The flag is written before the eFuse burns, so a burn cut short leaves
    // the serial loader open.
    const char *lock = "open (anyone at this port can set the owner key and lock it)";
    if (s_settings.locked) {
        lock = !AH_LOCK_CLOSES_DOWNLOAD_MODE || ah_settings_loader_closed()
               ? "locked"
               : "locked, but the serial loader is still open: run `lock yes` again";
    }
    printf("region %s  provisioning %s\n", region != NULL ? region->code : "unset (LoRa off)", lock);
    if (s_settings.has_owner_key) {
        printf("owner key fingerprint ");
        print_fingerprint(s_settings.owner_key);
        printf("\n");
    } else {
        printf("owner key unset (updates off)\n");
    }
    if (s_reboot_pending) {
        printf("settings changed since boot: `reboot` applies them\n");
    }
    printf("last reset %s  longest mesh pass %lu ms\n", ah_console_reset_reason(),
           (unsigned long)st.longest_pass_ms);
    const ah_node_stats_t *n = &st.node;
    const char *clock = n->clock_state == AH_CLOCK_TENTATIVE ? "tentative" : "unsynced";
    if (n->clock_state == AH_CLOCK_SYNCED) {
        clock = n->clock_confirmed ? "synced, confirmed" : "synced, unconfirmed";
    }
    printf("uptime %llds  clock %s, %lu samples set aside  links %u bound of %u open  peers %u\n",
           (long long)(st.uptime_ms / 1000), clock, (unsigned long)n->clock_rejected, n->links_bound, n->links_open,
           n->peers_known);
    printf("rx %lu  duplicate %lu  malformed %lu  refused %lu  stale %lu  relayed %lu  tx %lu  tx dropped %lu\n",
           (unsigned long)n->rx, (unsigned long)n->rx_duplicate, (unsigned long)n->rx_malformed,
           (unsigned long)n->rx_refused, (unsigned long)n->rx_stale, (unsigned long)n->relayed, (unsigned long)n->tx,
           (unsigned long)n->tx_dropped);
    printf("sync stored %lu served %lu  mail stored %lu delivered %lu refused %lu  trunk refused %lu\n",
           (unsigned long)n->sync_stored, (unsigned long)n->sync_served, (unsigned long)n->mail_stored,
           (unsigned long)n->mail_delivered, (unsigned long)n->mail_refused, (unsigned long)n->trunk_refused);
    // Where the node ran short: any of these climbing means a table or a budget is small for the site.
    printf("short of: verify %lu  inflate %lu  buffers %lu  evicted dedup %lu peers %lu streams %lu\n",
           (unsigned long)n->verify_skipped, (unsigned long)n->inflate_skipped, (unsigned long)n->buffers_exhausted,
           (unsigned long)n->dedup_evicted, (unsigned long)n->peers_evicted, (unsigned long)n->reassembly_evicted);
    if (st.lora.budget_ms > 0) {
        printf("lora %s  neighbors %u  airtime %lu of %lu ms this hour  power %d dBm  held down %lu\n",
               st.lora.running ? "up" : "radio down", st.lora.neighbors, (unsigned long)st.lora.airtime_ms,
               (unsigned long)st.lora.budget_ms, st.lora.max_power_dbm, (unsigned long)st.lora.trunk.holds);
        // Transfers count per destination; ah_trunk_stats_t says what makes a frame bad or unknown.
        printf("lora transfers  delivered %lu  failed %lu  frames sent %lu  bad %lu  from unknown nodes %lu\n",
               (unsigned long)st.lora.trunk.transfers_ok, (unsigned long)st.lora.trunk.transfers_failed,
               (unsigned long)st.lora.trunk.frames_tx, (unsigned long)st.lora.trunk.frames_bad,
               (unsigned long)st.lora.trunk.frames_unknown);
    }
    printf("heap %lu free, %lu lowest  events dropped %lu\n", (unsigned long)esp_get_free_heap_size(),
           (unsigned long)esp_get_minimum_free_heap_size(), (unsigned long)st.dropped_events);
    return 0;
}

static int cmd_region(int argc, char **argv)
{
    const ah_lora_region_id_t r = argc == 2 ? ah_lora_region_from_code(argv[1]) : AH_LORA_REGION_NONE;
    if (r == AH_LORA_REGION_NONE) {
        printf("usage: region us|eu|in|anz|sea  (docs/LORA.md: the rules each profile meets)\n");
        return 1;
    }
    const esp_err_t err = ah_settings_set_region(r);
    if (err == ESP_OK) {
        s_settings.region = r;
    }
    return report(err, "region set");
}

static int cmd_nickname(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: nickname <name>  (1 to %u letters, digits, '-', '_', '.')\n",
               (unsigned)AH_SETTINGS_NICKNAME_MAX);
        return 1;
    }
    const esp_err_t err = ah_settings_set_nickname(argv[1]);
    if (err == ESP_OK) {
        s_settings.identity.nickname_len = (uint8_t)strnlen(argv[1], sizeof(s_settings.identity.nickname));
        memcpy(s_settings.identity.nickname, argv[1], s_settings.identity.nickname_len);
    }
    return report(err, "nickname set");
}

// The key is written once, so a valid but mistyped one would hold for good:
// it is taken only with the fingerprint keygen printed for it, typed back.
static int cmd_owner(int argc, char **argv)
{
    uint8_t key[AH_KEY_LEN];
    uint8_t fp[FINGERPRINT_LEN];
    if ((argc != 2 && argc != 3) || !parse_hex(argv[1], key, sizeof(key)) ||
            (argc == 3 && !parse_hex(argv[2], fp, sizeof(fp)))) {
        printf("usage: owner <64 hex digits: the fleet's Ed25519 public key> <its 16-digit fingerprint>"
               "  (write once)\n");
        return 1;
    }
    uint8_t digest[AH_SHA256_LEN];
    ah_sha256(key, sizeof(key), digest);
    if (argc == 2 || memcmp(fp, digest, sizeof(fp)) != 0) {
        printf("%s: this key's fingerprint is ", argc == 2 ? "not set" : "not set, fingerprints differ");
        print_fingerprint(key);
        printf(". Compare it with the one `ota_manifest.py keygen` printed, then give both: owner <key> "
               "<fingerprint>\n");
        return 1;
    }
    const esp_err_t err = ah_settings_set_owner_key(key);
    if (err == ESP_OK) {
        memcpy(s_settings.owner_key, key, sizeof(key));
        s_settings.has_owner_key = true;
    }
    return report(err, "owner key set");
}

static int cmd_lock(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "yes") != 0) {
        printf("`lock yes` closes provisioning for good: no region, nickname, owner key or reset from here on%s\n",
               AH_LOCK_CLOSES_DOWNLOAD_MODE ? ", and no serial loader" : "");
        return 1;
    }
    // A node locked with no owner key could never take an update, and on a
    // release board no wired flash either.
    if (!s_settings.has_owner_key) {
        printf("refused: set the owner key first (`owner <key> <fingerprint>`)\n");
        return 1;
    }
    const esp_err_t err = ah_settings_lock();
    if (err != ESP_OK) {
        return report(err, "");
    }
    // Unlike the settings, the lock holds at once.
    s_settings.locked = true;
    printf("locked: provisioning is closed%s\n", AH_LOCK_CLOSES_DOWNLOAD_MODE ? ", and the serial loader with it" : "");
    return 0;
}

static int cmd_factory_reset(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "yes") != 0) {
        printf("`factory-reset yes` reboots and erases the identity, the settings, the mailbox and the last "
               "crash\n");
        return 1;
    }
    const esp_err_t err = ah_settings_factory_reset();
    if (err != ESP_OK) {
        return report(err, "");
    }
    esp_restart();
}

// The last crash's summary, read through flash decryption on a release board,
// whose download mode cannot read the partition out. Code addresses and the
// cause only: the registers and the RISC-V stack dump it also holds can carry
// secrets from the crashed task.
static int cmd_crash(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "erase") == 0) {
        const esp_err_t err = esp_core_dump_image_erase();
        if (err != ESP_OK) {
            printf("erase failed: %s\n", esp_err_to_name(err));
            return 1;
        }
        printf("crash erased\n");
        return 0;
    }
    if (argc != 1) {
        printf("usage: crash [erase]\n");
        return 1;
    }
    if (esp_core_dump_image_check() != ESP_OK) {
        printf("no crash stored\n");
        return 0;
    }
    // Over 1 KiB on a RISC-V chip, so not on this task's stack.
    esp_core_dump_summary_t *s = calloc(1, sizeof(*s));
    char *reason = malloc(PANIC_REASON_LEN);
    if (s == NULL || reason == NULL || esp_core_dump_get_summary(s) != ESP_OK) {
        printf("crash stored, summary unreadable\n");
        free(s);
        free(reason);
        return 1;
    }
    printf("task %.*s  pc 0x%08lx  build %.*s\n", (int)sizeof(s->exc_task), s->exc_task, (unsigned long)s->exc_pc,
           (int)sizeof(s->app_elf_sha256) - 1, (const char *)s->app_elf_sha256);
    if (esp_core_dump_get_panic_reason(reason, PANIC_REASON_LEN) == ESP_OK) {
        printf("reason %s\n", reason);
    }
#if CONFIG_IDF_TARGET_ARCH_XTENSA
    printf("cause %lu  address 0x%08lx  backtrace%s", (unsigned long)s->ex_info.exc_cause,
           (unsigned long)s->ex_info.exc_vaddr, s->exc_bt_info.corrupted ? " (corrupt)" : "");
    for (uint32_t i = 0; i < s->exc_bt_info.depth && i < 16u; ++i) {
        printf(" 0x%08lx", (unsigned long)s->exc_bt_info.bt[i]);
    }
    printf("\n");
#else
    printf("mcause 0x%08lx  mtval 0x%08lx  ra 0x%08lx\n", (unsigned long)s->ex_info.mcause,
           (unsigned long)s->ex_info.mtval, (unsigned long)s->ex_info.ra);
#endif
    printf("`crash erase` clears it\n");
    free(s);
    free(reason);
    return 0;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    esp_restart();
}

esp_err_t ah_console_start(const ah_settings_t *settings, const char *board)
{
    s_settings = *settings;
    // The console's copy needs no secrets: drop them.
    ah_wipe(s_settings.identity.noise_secret, sizeof(s_settings.identity.noise_secret));
    ah_wipe(s_settings.identity.signing_secret, sizeof(s_settings.identity.signing_secret));
    s_board = board;
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_cfg.prompt = "airlink>";
    repl_cfg.max_cmdline_length = 160;
#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    const esp_console_dev_usb_serial_jtag_config_t hw = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    esp_err_t err = esp_console_new_repl_usb_serial_jtag(&hw, &repl_cfg, &repl);
#else
    const esp_console_dev_uart_config_t hw = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    esp_err_t err = esp_console_new_repl_uart(&hw, &repl_cfg, &repl);
#endif
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "no console: %s", esp_err_to_name(err));
        return err;
    }
    const esp_console_cmd_t cmds[] = {
        {.command = "status", .help = "What the node is doing", .func = cmd_status},
        {.command = "region", .help = "Set the LoRa region: us, eu, in, anz or sea", .func = cmd_region},
        {.command = "nickname", .help = "Set the name phones show", .func = cmd_nickname},
        {.command = "owner", .help = "Set the fleet's OTA owner key (write once)", .func = cmd_owner},
        {.command = "lock", .help = "Close provisioning for good", .func = cmd_lock},
        {.command = "factory-reset", .help = "Erase identity, settings and mailbox", .func = cmd_factory_reset},
        {.command = "crash", .help = "Show the last crash, or erase it", .func = cmd_crash},
        {.command = "reboot", .help = "Restart the node", .func = cmd_reboot},
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); ++i) {
        ESP_RETURN_ON_ERROR(esp_console_cmd_register(&cmds[i]), TAG, "register %s", cmds[i].command);
    }
    return esp_console_start_repl(repl);
}
