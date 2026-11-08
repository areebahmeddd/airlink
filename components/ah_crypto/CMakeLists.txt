set(first_party "src/ah_crypto_common.c" "src/ah_crypto_esp.c")
# esp/ holds the device's ah_sha256_ctx.h, a PSA operation, so the public
# header needs mbedtls. It sits apart from include/ so the host tests can put
# their own in its place.
idf_component_register(
    SRCS ${first_party}
         "third_party/monocypher/monocypher.c"
         "third_party/monocypher/monocypher-ed25519.c"
    INCLUDE_DIRS "include" "esp"
    PRIV_INCLUDE_DIRS "third_party/monocypher"
    REQUIRES mbedtls
    PRIV_REQUIRES esp_hw_support)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ah_component.cmake)
ah_first_party(${first_party})
