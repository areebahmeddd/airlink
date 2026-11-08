#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Every check CI runs but coverage and CodeQL, each in the pinned tools image.
# From the host:
#   scripts/check.sh            # everything
#   scripts/check.sh quick      # without the board builds and the size gate
set -euo pipefail
cd "$(dirname "$0")/.."
run() { scripts/docker.sh "$@"; }

echo "== format and lint"
# pre-commit sees only tracked files; the second run covers new ones. Quoted
# so the tools image, not this shell, expands it.
# shellcheck disable=SC2016
run 'git config --global --add safe.directory /work; pre-commit run --all-files --show-diff-on-failure &&
     untracked=$(git ls-files -o --exclude-standard) && { [ -z "$untracked" ] || pre-commit run --files $untracked; }'
echo "== spec vectors reproduce"
run 'python3 tools/vectors/gen_spec_vectors.py test/vectors/spec-vectors.json'
git diff --exit-code -- test/vectors
echo "== static analysis"
run scripts/static-analysis.sh
echo "== host tests (ASan, UBSan)"
run 'cmake -S test/host -B build-host -G Ninja >/dev/null && cmake --build build-host && ctest --test-dir build-host --output-on-failure'
echo "== fuzz smoke"
run scripts/fuzz-smoke.sh
if [[ "${1:-}" != quick ]]; then
    for file in config/board.*; do
        board=${file#config/board.}
        for profile in dev release; do
            echo "== $board $profile"
            run "scripts/build.sh $board $profile >/dev/null"
        done
        run "scripts/size-gate.sh $board"
    done
    git diff --exit-code -- 'dependencies.lock.*'
fi
echo "all checks passed"
