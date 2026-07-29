#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-airtime.XXXXXX")"
trap 'rm -f "$test_bin"' EXIT

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/main/lora_airtime.c" \
    "$repo_root/tests/test_lora_airtime.c" \
    -lm -o "$test_bin"
"$test_bin"

cd "$repo_root"
python3 -m unittest discover -s tests -p 'test_lora_*.py' -v
