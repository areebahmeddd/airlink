#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Run a command inside the pinned tools image (docker/Dockerfile) with this
# repository mounted at /work. Builds the image on first use.
#   scripts/docker.sh 'idf.py build'
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${AH_TOOLS_IMAGE:-airlink-tools:dev}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build -t "$image" "$here/docker"
fi

src="$here"
user=()
if command -v cygpath >/dev/null 2>&1; then
    # Git Bash on Windows: Docker wants the Windows path, and MSYS must not rewrite /work.
    src="$(cygpath -w "$here")"
    export MSYS_NO_PATHCONV=1
else
    # Linux and macOS: outputs belong to the caller, not to root.
    user=(--user "$(id -u):$(id -g)")
fi
# AH_BUILD_VOLUME=<name> keeps build/ in a Docker volume: much faster than a
# Windows or macOS bind mount, at the cost of the outputs staying in it.
volume=()
if [[ -n "${AH_BUILD_VOLUME:-}" ]]; then
    volume=(-v "$AH_BUILD_VOLUME:/work/build")
fi
env=(-e HOME=/tmp)
# The one setting a script reads from the caller (scripts/fuzz-smoke.sh).
if [[ -n "${FUZZ_SECONDS:-}" ]]; then
    env+=(-e "FUZZ_SECONDS=$FUZZ_SECONDS")
fi
exec docker run --rm "${user[@]}" -v "$src:/work" "${volume[@]}" -w /work "${env[@]}" "$image" bash -lc "$*"
