idf_component_register(
    SRCS "src/ah_ble.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES bt esp_timer ah_proto)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party("src/ah_ble.c")
