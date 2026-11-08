file(GLOB first_party RELATIVE ${CMAKE_CURRENT_LIST_DIR} "${CMAKE_CURRENT_LIST_DIR}/src/*.c")
idf_component_register(
    SRCS ${first_party}
    INCLUDE_DIRS "include"
    REQUIRES ah_proto ah_noise ah_crypto)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party(${first_party})
