#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Build the libFuzzer harnesses with clang and run each from a corpus cut out
# of the test vectors. CI runs 30 s each; before a release, run them long:
#   FUZZ_SECONDS=3600 scripts/fuzz-smoke.sh
# Runs inside the tools image (scripts/docker.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

seconds=${FUZZ_SECONDS:-30}
build="build-fuzz"
CC=clang-18 cmake -S test/host -B "$build" -G Ninja -DAH_FUZZ=ON >/dev/null
cmake --build "$build"
python3 tools/vectors/fuzz_seeds.py test/vectors "$build/corpus"
for harness in "$build"/fuzz_*; do
    [[ -x "$harness" && -f "$harness" ]] || continue
    name=$(basename "$harness")
    mkdir -p "$build/corpus/$name" "$build/artifacts/$name"
    echo "== $name: ${seconds}s"
    "$harness" -max_total_time="$seconds" -max_len=4096 -timeout=10 -print_final_stats=1 \
        -artifact_prefix="$build/artifacts/$name/" "$build/corpus/$name" 2>&1 | tail -n 4
done
