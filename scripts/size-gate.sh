#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Size gate for one board's dev build: scripts/size-gate.sh <board> [--write]
# Runs inside the tools image (scripts/docker.sh), after scripts/build.sh <board> dev.
set -euo pipefail
cd "$(dirname "$0")/.."
board=${1:?usage: scripts/size-gate.sh <board> [--write]}
report="build/$board-dev/size.json"
idf.py -B "build/$board-dev" size --format json2 --output-file "$report" >/dev/null
python3 tools/size_gate.py "$board" "$report" "${@:2}"
