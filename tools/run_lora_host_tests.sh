#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
airtime_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-airtime.XXXXXX")"
region_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-region.XXXXXX")"
trap 'rm -f "$airtime_bin" "$region_bin"' EXIT

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

cd "$repo_root"
python3 -m unittest discover -s tests -p 'test_lora_*.py' -v
