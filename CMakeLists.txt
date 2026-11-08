cmake_minimum_required(VERSION 3.22)

# The release version, as SemVer. The announce carries it (TLV 0xB0) and OTA
# compares it: bump it for every release (CHANGELOG.md).
set(PROJECT_VER "1.0.0")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Build only what main requires, not every component ESP-IDF ships.
idf_build_set_property(MINIMAL_BUILD ON)
# One component lock per target: the component manager records the target.
idf_build_set_property(DEPENDENCIES_LOCK "${CMAKE_CURRENT_LIST_DIR}/dependencies.lock.${IDF_TARGET}")
project(airlink)
