#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Static analysis of the first-party C: clang-tidy over the host build of the
# protocol core (its compile database), and cppcheck over every component and
# main/. Vendored code (third_party/) is not ours to fix. Runs inside the tools
# image (scripts/docker.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

cmake -S test/host -B build-host -G Ninja >/dev/null
cmake --build build-host --target vectors >/dev/null
mapfile -t core < <(find components/ah_proto/src components/ah_noise/src components/ah_mesh/src \
    components/ah_lora/core components/ah_crypto/src/ah_crypto_common.c -name '*.c' | sort)
echo "== clang-tidy (${#core[@]} files)"
clang-tidy -p build-host --quiet "${core[@]}"

echo "== cppcheck"
cppcheck --std=c11 --enable=warning,performance,portability --error-exitcode=1 --inline-suppr --quiet \
    --suppress=missingIncludeSystem --suppress=unmatchedSuppression \
    -i components/ah_proto/third_party -i components/ah_crypto/third_party \
    -I components/ah_proto/include -I components/ah_crypto/include -I components/ah_crypto/esp -I components/ah_noise/include \
    -I components/ah_mesh/include -I components/ah_lora/include -I components/ah_board/include \
    components main
