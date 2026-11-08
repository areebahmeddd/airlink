#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# Sign one board's release build on the offline machine that holds the keys
# (docs/RELEASE.md), then cut its OTA manifest and the merged image the web
# flasher writes.
#
#   tools/release_sign.sh <board> <release-dir> <secure-boot-key.pem> <owner-key.pem>
#
# <release-dir> holds the board's unsigned release outputs: the CI artifact,
# or build/<board>-release. Output goes to <release-dir>/signed/. Needs
# ESP-IDF's environment: espsecure, esptool, parttool and Python's
# cryptography package.
set -euo pipefail

usage="usage: release_sign.sh <board> <release-dir> <secure-boot-key.pem> <owner-key.pem>"
board=${1:?$usage}
dir=$(cd "${2:?$usage}" && pwd)
sb_key=${3:?$usage}
owner_key=${4:?$usage}
here="$(cd "$(dirname "$0")" && pwd)"
chip=$(python3 "$here/boards.py" "$board" target)

out="$dir/signed"
mkdir -p "$out/bootloader" "$out/partition_table"
# Secure Boot V2 (RSA-3072): the ROM checks the bootloader, and the bootloader
# checks the app on every boot.
espsecure sign-data --version 2 --keyfile "$sb_key" --output "$out/bootloader/bootloader.bin" \
    "$dir/bootloader/bootloader.bin"
espsecure sign-data --version 2 --keyfile "$sb_key" --output "$out/airlink.bin" "$dir/airlink.bin"
# The mesh's own check: nodes fetch only images their fleet's owner signed.
python3 "$here/ota_manifest.py" sign --key "$owner_key" --board "$board" -o "$out/airlink.bin.ahot" \
    "$out/airlink.bin"
cp "$dir/partition_table/partition-table.bin" "$out/partition_table/"
cp "$dir/ota_data_initial.bin" "$out/"

# One image from offset 0 for the web flasher: the bootloader, the partition
# table, the OTA data and the app at the offsets the attested partition table
# gives them (tools/check_merged.py --layout, the layout the flasher workflow
# checks it against), with the manifest at its own partition. The build's
# flash_args are not attested, so nothing is taken from them. The headers are
# kept as built, since rewriting one would break its signature.
manifest=$(python3 "$IDF_PATH/components/partition_table/parttool.py" --partition-table-file \
    "$out/partition_table/partition-table.bin" get_partition_info --partition-name manifest --info offset)
merged="airlink-$board-merged.bin"
cd "$out"
parts=()
while read -r offset file; do
    parts+=("$offset" "$file")
done < <(python3 "$here/check_merged.py" --layout .)
esptool --chip "$chip" merge-bin --output "$merged" --flash-mode keep --flash-freq keep --flash-size keep \
    "${parts[@]}" "$manifest" airlink.bin.ahot
# The check the flasher workflow runs: every byte is the attested build, a
# signature block, the manifest or erased flash.
python3 "$here/check_merged.py" "$merged" "$dir" >/dev/null
# Board-named, so every board's set attaches to the one release without a clash;
# the merged image goes up beside it on its own, as the flasher fetches it, so
# the checksums cover what the tarball holds.
find . \( -name '*.bin' -o -name '*.ahot' \) ! -name "$merged" -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
tar -czf "../airlink-$board-signed.tar.gz" --exclude "./$merged" .
echo "signed $board into $out and $dir/airlink-$board-signed.tar.gz"
