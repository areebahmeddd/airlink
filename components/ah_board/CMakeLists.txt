set(first_party "src/ah_board.c" "src/ah_display.c" "src/ah_screen.c")
idf_component_register(
    SRCS ${first_party}
    INCLUDE_DIRS "include"
    REQUIRES ah_lora
    PRIV_REQUIRES esp_driver_gpio esp_driver_i2c esp_timer)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party(${first_party})
