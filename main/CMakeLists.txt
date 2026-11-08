set(first_party "app_main.c" "ah_app.c" "ah_console.c" "ah_mailbox.c" "ah_ota.c" "ah_settings.c")
# espcoredump: the console reads and erases the last crash. It must be required
# anyway, so that MINIMAL_BUILD builds it, without which its Kconfig never loads
# and no core dump is written.
idf_component_register(
    SRCS ${first_party}
    INCLUDE_DIRS "."
    PRIV_REQUIRES ah_mesh ah_ble ah_lora ah_board ah_crypto ah_proto
                  nvs_flash app_update esp_partition esp_app_format esp_timer esp_pm console bootloader_support efuse
                  espcoredump)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/ah_component.cmake)
ah_first_party(${first_party})
