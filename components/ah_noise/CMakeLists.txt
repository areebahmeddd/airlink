idf_component_register(
    SRCS "src/ah_noise.c"
    INCLUDE_DIRS "include"
    REQUIRES ah_crypto)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party("src/ah_noise.c")
