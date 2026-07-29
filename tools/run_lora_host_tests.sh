#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
airtime_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-airtime.XXXXXX")"
region_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-region.XXXXXX")"
scheduler_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-scheduler.XXXXXX")"
trap 'rm -f "$airtime_bin" "$region_bin" "$scheduler_bin"' EXIT

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/main/lora_airtime.c" \
    "$repo_root/tests/test_lora_airtime.c" \
    -lm -o "$airtime_bin"
"$airtime_bin"

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/main/lora_region.c" \
    "$repo_root/tests/test_lora_region.c" \
    -o "$region_bin"
"$region_bin"

cc -std=c11 -Wall -Wextra -Werror \
    -pthread \
    -I"$repo_root/main" \
    "$repo_root/tests/test_lora_tx_scheduler.c" \
    "$repo_root/main/lora_tx_scheduler.c" \
    -o "$scheduler_bin"
"$scheduler_bin"

cd "$repo_root"
python3 -m unittest discover -s tests -p 'test_lora_*.py' -v
