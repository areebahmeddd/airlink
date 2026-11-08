#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Build one board in one profile into build/<board>-<profile>:
#   scripts/build.sh <board> [dev|release] [idf.py args...]
# The boards are config/board.* (tools/boards.py). Runs where ESP-IDF is set
# up: the tools image (scripts/docker.sh) or a local install.
set -euo pipefail
cd "$(dirname "$0")/.."

board=${1:?usage: scripts/build.sh <board> [dev|release] [idf.py args...]}
profile=${2:-dev}
shift $(($# < 2 ? $# : 2))

target=$(python3 tools/boards.py "$board" target)
[[ -f "config/profile.$profile" ]] || { echo "unknown profile: $profile" >&2; exit 2; }

build="build/$board-$profile"
# ESP-IDF adds sdkconfig.defaults.<target> after sdkconfig.defaults by itself.
defaults="sdkconfig.defaults;config/board.$board;config/profile.$profile"
idf.py -B "$build" -D IDF_TARGET="$target" -D SDKCONFIG="$build/sdkconfig" -D SDKCONFIG_DEFAULTS="$defaults" "${@:-build}"
