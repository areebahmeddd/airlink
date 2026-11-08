# core/ is the pure trunk (host-tested); esp/ drives the SX1262 and the task.
file(GLOB first_party RELATIVE ${CMAKE_CURRENT_LIST_DIR}
     "${CMAKE_CURRENT_LIST_DIR}/core/*.c" "${CMAKE_CURRENT_LIST_DIR}/esp/*.c")
idf_component_register(
    SRCS ${first_party}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "esp"
    PRIV_REQUIRES ah_crypto esp_driver_spi esp_driver_gpio esp_timer esp_hw_support nvs_flash)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party(${first_party})
