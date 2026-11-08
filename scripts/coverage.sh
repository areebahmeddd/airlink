#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Line and branch coverage of the protocol core by the host tests, with
# clang's source-based coverage. Prints a per-file summary, and writes the
# HTML report to build-coverage/html and the LCOV file CI uploads to
# build-coverage/lcov.info. Runs inside the tools image (scripts/docker.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

build="build-coverage"
CC=clang-18 cmake -S test/host -B "$build" -G Ninja -DAH_SANITIZE=OFF -DAH_COVERAGE=ON >/dev/null
cmake --build "$build"
rm -rf "$build/profiles"
LLVM_PROFILE_FILE="$PWD/$build/profiles/%p.profraw" ctest --test-dir "$build" --output-on-failure >/dev/null
llvm-profdata merge -sparse "$build"/profiles/*.profraw -o "$build/tests.profdata"
objects=()
for test in "$build"/test_*; do
    [[ -x "$test" && -f "$test" ]] && objects+=(-object "$test")
done
filter=(-ignore-filename-regex='(third_party|test/|^/opt/)')
llvm-cov report "${objects[@]}" -instr-profile="$build/tests.profdata" "${filter[@]}"
llvm-cov export "${objects[@]}" -instr-profile="$build/tests.profdata" "${filter[@]}" -format=lcov |
    sed "s#^SF:$PWD/#SF:#" >"$build/lcov.info"
llvm-cov show "${objects[@]}" -instr-profile="$build/tests.profdata" "${filter[@]}" -format=html \
    -output-dir="$build/html" >/dev/null
