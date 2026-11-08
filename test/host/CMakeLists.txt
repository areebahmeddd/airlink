# Host build of the protocol core: unit tests and simulations under ASan and
# UBSan, and libFuzzer harnesses with clang (scripts/fuzz-smoke.sh). The core
# is plain C with no ESP-IDF dependency, so it builds here exactly as it builds
# for the device; only SHA-256 and the random source come from
# support/ah_crypto_host.c.
#
#   cmake -S test/host -B build-host -G Ninja && cmake --build build-host && ctest --test-dir build-host
cmake_minimum_required(VERSION 3.20)
project(airlink_host C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(AH_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" ON)
option(AH_FUZZ "Build the libFuzzer harnesses (clang only)" OFF)
option(AH_COVERAGE "Build with clang's source-based coverage (scripts/coverage.sh)" OFF)

get_filename_component(FW "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(AH_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
if(AH_FUZZ)
    # Coverage feedback from every library, not only the harnesses, optimized:
    # unoptimized, the crypto behind every signed frame runs several times slower.
    add_compile_options(-fsanitize=fuzzer-no-link -O1 -g)
endif()
if(AH_COVERAGE)
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping -O0)
    add_link_options(-fprofile-instr-generate)
endif()

# Unity, as ESP-IDF ships it.
if(NOT DEFINED ENV{IDF_PATH})
    message(FATAL_ERROR "IDF_PATH is not set: run inside the airlink-tools container")
endif()
set(UNITY_DIR "$ENV{IDF_PATH}/components/unity/unity/src")
add_library(unity STATIC "${UNITY_DIR}/unity.c")
target_include_directories(unity SYSTEM PUBLIC "${UNITY_DIR}")
target_compile_definitions(unity PUBLIC UNITY_INCLUDE_DOUBLE UNITY_SUPPORT_64)

# Vendored code keeps its own style and warnings.
include("${FW}/components/ah_proto/miniz.cmake")
add_library(ah_third_party STATIC
    "${FW}/components/ah_proto/third_party/miniz/miniz.c"
    "${FW}/components/ah_crypto/third_party/monocypher/monocypher.c"
    "${FW}/components/ah_crypto/third_party/monocypher/monocypher-ed25519.c")
target_compile_definitions(ah_third_party PUBLIC ${AH_MINIZ_DEFINES})
target_include_directories(ah_third_party SYSTEM PUBLIC
    "${FW}/components/ah_proto/third_party/miniz"
    "${FW}/components/ah_crypto/third_party/monocypher")

file(GLOB AH_CORE_SOURCES CONFIGURE_DEPENDS
    "${FW}/components/ah_proto/src/*.c"
    "${FW}/components/ah_noise/src/*.c"
    "${FW}/components/ah_mesh/src/*.c"
    "${FW}/components/ah_lora/core/*.c")
add_library(ah_core STATIC
    ${AH_CORE_SOURCES}
    "${FW}/components/ah_crypto/src/ah_crypto_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/support/ah_crypto_host.c")
target_include_directories(ah_core PUBLIC
    "${FW}/components/ah_proto/include"
    "${FW}/components/ah_crypto/include"
    "${FW}/components/ah_noise/include"
    "${FW}/components/ah_mesh/include"
    "${FW}/components/ah_lora/include"
    "${CMAKE_CURRENT_LIST_DIR}/support")
target_link_libraries(ah_core PUBLIC ah_third_party OpenSSL::Crypto)
# The first-party warning set, as errors, on the host as on the device.
target_compile_options(ah_core PRIVATE -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wvla -Wcast-align
                                       -Wstrict-prototypes -Wmissing-prototypes)

set(GENERATED "${CMAKE_CURRENT_BINARY_DIR}/generated")
add_custom_command(
    OUTPUT "${GENERATED}/vectors.h"
    COMMAND Python3::Interpreter "${FW}/tools/vectors/gen_c_vectors.py" "${FW}/test/vectors" "${GENERATED}/vectors.h"
    DEPENDS "${FW}/tools/vectors/gen_c_vectors.py" "${FW}/test/vectors/bitchat-ios.json"
            "${FW}/test/vectors/courier-test-vectors.json" "${FW}/test/vectors/courier-test-vectors-bitchat.json"
            "${FW}/test/vectors/spec-vectors.json"
    COMMENT "Generating C vectors from test/vectors")
add_custom_target(vectors DEPENDS "${GENERATED}/vectors.h")

add_library(ah_test_support STATIC "${CMAKE_CURRENT_LIST_DIR}/support/sim.c")
target_link_libraries(ah_test_support PUBLIC ah_core unity)
target_include_directories(ah_test_support PUBLIC "${CMAKE_CURRENT_LIST_DIR}/support" "${GENERATED}")
add_dependencies(ah_test_support vectors)

enable_testing()
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/test_*.c")
foreach(src ${TEST_SOURCES})
    get_filename_component(name "${src}" NAME_WE)
    add_executable(${name} "${src}")
    target_link_libraries(${name} PRIVATE ah_test_support)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endforeach()

if(AH_FUZZ)
    file(GLOB FUZZ_SOURCES CONFIGURE_DEPENDS "${FW}/test/fuzz/fuzz_*.c")
    foreach(src ${FUZZ_SOURCES})
        get_filename_component(name "${src}" NAME_WE)
        add_executable(${name} "${src}")
        target_link_libraries(${name} PRIVATE ah_core)
        target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -fsanitize=fuzzer)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()
