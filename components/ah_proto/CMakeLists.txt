file(GLOB first_party RELATIVE ${CMAKE_CURRENT_LIST_DIR} "${CMAKE_CURRENT_LIST_DIR}/src/*.c")
# The public headers take key and signature sizes from ah_crypto.h, so the
# dependency is public.
idf_component_register(
    SRCS ${first_party} "third_party/miniz/miniz.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "third_party/miniz"
    REQUIRES ah_crypto)
include(${CMAKE_CURRENT_LIST_DIR}/miniz.cmake)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ${AH_MINIZ_DEFINES})
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party(${first_party})
