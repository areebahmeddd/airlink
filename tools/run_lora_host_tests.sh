#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
airtime_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-airtime.XXXXXX")"
region_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-region.XXXXXX")"
scheduler_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-scheduler.XXXXXX")"
trunk_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-trunk.XXXXXX")"
reliability_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-reliability.XXXXXX")"
channel_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-channel.XXXXXX")"
forwarding_bin="$(mktemp "${TMPDIR:-/tmp}/bitle-lora-forwarding.XXXXXX")"
trap 'rm -f "$airtime_bin" "$region_bin" "$scheduler_bin" "$trunk_bin" "$reliability_bin" "$channel_bin" "$forwarding_bin"' EXIT

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

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/tests/test_lora_trunk_protocol.c" \
    "$repo_root/main/lora_trunk_protocol.c" \
    "$repo_root/main/lora_channel_policy.c" \
    "$repo_root/main/lora_forwarding.c" \
    -o "$trunk_bin"
"$trunk_bin"

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/tests/test_lora_packet_reliability.c" \
    "$repo_root/main/lora_packet_reliability.c" \
    "$repo_root/main/lora_airtime.c" \
    -lm -o "$reliability_bin"
"$reliability_bin"

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/tests/test_lora_channel_policy.c" \
    "$repo_root/main/lora_channel_policy.c" \
    -o "$channel_bin"
"$channel_bin"

cc -std=c11 -Wall -Wextra -Werror \
    -I"$repo_root/main" \
    "$repo_root/tests/test_lora_forwarding.c" \
    "$repo_root/main/lora_forwarding.c" \
    -o "$forwarding_bin"
"$forwarding_bin"

cd "$repo_root"
python3 -m unittest discover -s tests -p 'test_lora_*.py' -v
