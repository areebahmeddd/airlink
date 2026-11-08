# Releases

A release is a tag `v<major>.<minor>.<patch>` (SemVer) whose version matches `PROJECT_VER` in `CMakeLists.txt` and has its entry in `CHANGELOG.md`. CI builds it; the maintainer signs it offline; the web flasher serves the signed images.

## The Two Keys

| Key                                | What it guards                                              | Made with                                                                                 | Kept                                                                       |
| ---------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Secure Boot signing key (RSA-3072) | What a release-flashed chip will run, checked on every boot | `espsecure generate-signing-key --version 2 --scheme rsa3072 secure_boot_signing_key.pem` | Offline, backed up. Lose it and released boards take no new firmware, ever |
| Fleet owner key (Ed25519)          | Which images nodes fetch from the mesh                      | `tools/ota_manifest.py keygen`                                                            | Offline, backed up, apart from the other                                   |

Neither reaches CI, and neither is ever committed (`.gitignore` refuses both names).

## Cutting a Release

1. Raise `PROJECT_VER`, move the changelog's Unreleased section under the new version, and tag.
2. The **Release and Changelog** workflow builds every board's release profile twice and fails unless the two builds are identical, writes an SPDX SBOM per board (`esp-idf-sbom`), and drafts a GitHub release with the unsigned outputs and their checksums.
3. On the online machine, download each board's unsigned tarball from the draft, unpack it, and check every image in it is what CI built for the tag, as the flasher workflow checks it later: `gh attestation verify <image.bin> --repo areebahmeddd/airlink --source-ref refs/tags/<tag> --signer-workflow areebahmeddd/airlink/.github/workflows/release.yml`. Only then carry it across: the keys sign whatever they are given, and an image the owner key signed spreads over the air.
4. On the offline machine, for each board:

   ```bash
   tools/release_sign.sh <board> <unpacked-dir> secure_boot_signing_key.pem owner_key.pem
   ```

   It signs the bootloader and the app for Secure Boot, signs the app's OTA manifest with the owner key, and merges bootloader, partition table, OTA data, manifest and app into one image from offset 0, at the offsets the attested partition table gives them (`tools/check_merged.py --layout`), never the build's `flash_args`, which nothing attests. It then runs the flasher workflow's own check on the result. Sign each board once per release: the Secure Boot signature is randomized, so a second run gives other bytes. The script needs `sha256sum` (on macOS, Homebrew's coreutils).

5. Attach each board's `airlink-<board>-merged.bin` and `airlink-<board>-signed.tar.gz` (the rest of its `signed/` set) to the draft, publish it, then run the **Publish Web Flasher** workflow with the tag. It checks each merged image against the unsigned build CI attested by the tag's own release workflow (`tools/check_merged.py`: every byte must be CI's build, a signature block, the manifest, or erased flash, so nothing can be planted in a data partition a board's first boot would take as its own), and serves ESP Web Tools from the site itself, unpacked from npm's tarball of the pinned version and checked against its published integrity.

The workflow does not check whose Secure Boot key signed a bootloader, and a fresh board burns the digest of whichever key that was on its first boot. It rests on the release assets only the maintainer's account can attach. Checking it would need the key's public half committed (`espsecure extract-public-key --version 2 --keyfile secure_boot_signing_key.pem secure_boot_public.pem`) and `espsecure verify-signature --version 2 --keyfile secure_boot_public.pem` run over the bootloader and app cut from each merged image.

## What a Release Image Does to a Chip, Once

The release profile (`config/profile.release`) turns on what Espressif recommends for production. On the first boot of a release image, the bootloader burns these eFuses (the app's startup burns secure download mode, and the anti-rollback floor rises when an image is marked kept), and `lock yes` burns the last (the principal ones; ESP-IDF's Security Guide for the chip lists every bit, and `espefuse summary` shows a board's state). **Every one is permanent:** a board that has booted a release image cannot go back to development images, and runs only images signed with the same Secure Boot key.

| Step                           | eFuses                                                                                                           | Effect                                                                              |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Secure Boot V2                 | the key digest into a key block, `SECURE_BOOT_EN`, and the key-revocation bits for the unused digests            | Only images signed with this key boot                                               |
| Flash encryption, release mode | a key generated on chip into a key block, `SPI_BOOT_CRYPT_CNT` to its final value, `DIS_DOWNLOAD_MANUAL_ENCRYPT` | Flash is encrypted at rest with a key no one can read; plaintext reflashing is over |
| NVS encryption                 | none: its keys are generated on chip into the `nvs_keys` partition, which flash encryption covers                | Settings and mailbox encrypted                                                      |
| Secure download mode           | `ENABLE_SECURITY_DOWNLOAD`                                                                                       | The ROM's serial loader reads nothing and runs nothing, but still writes flash      |
| JTAG                           | `DIS_PAD_JTAG`, `DIS_USB_JTAG` (by Secure Boot and flash encryption in release mode)                             | No debugger                                                                         |
| Anti-rollback                  | `SECURE_VERSION` raised to the image's `CONFIG_BOOTLOADER_APP_SECURE_VERSION`                                    | Images of a lower secure version never boot again                                   |
| `lock yes`, by the app         | `DIS_DOWNLOAD_MODE`                                                                                              | No serial loader at all: no flash writes, no `esptool`                              |

Raise `CONFIG_BOOTLOADER_APP_SECURE_VERSION` only in a release meant to retire every older image, and say so in its changelog entry.

A release board can no longer be flashed over USB: its serial loader writes flash only as plaintext, which flash encryption then reads as noise. It takes updates over the air alone. Keep it powered through its first boot, which encrypts the flash in place and can take a minute; cutting power during it corrupts the flash.

### Until the Lock

Secure download mode refuses reads of flash, memory and eFuses, and runs no uploaded code, but takes plain flash writes ([ESP-IDF's Security Guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/security/security.html)). Until a node is locked, someone holding it and a USB cable can therefore:

- **Erase its settings.** The `nvs` partition holds the identity, the provisioning lock and the owner key, and flash encryption cannot cover it; NVS encryption keeps its contents secret but cannot stop it being erased. Erased, the board boots as a new, unlocked node with a new identity, whose owner key anyone can then set. Nothing is read out: the keys it had are gone, not taken.
- **Erase its OTA data.** `otadata` is encrypted, so it cannot be forged, but noise written over it makes the bootloader start over from the first app slot, so a board can be sent back to an older image still there, when that image's secure version is not below the eFuse's.

Neither yields a key, a plaintext message or code of the attacker's own. `lock yes` closes both: on a release board it burns `DIS_DOWNLOAD_MODE`, and from then on the node also reads its lock from that eFuse, so it stays locked whatever happens to its settings. What a locked node gives up is the one recovery from a wrong owner key, erasing its settings on the bench, which the fingerprint `owner` asks for guards against. Provision and lock every node before it leaves the bench; `lock yes` refuses until the owner key is set, since a locked release board with none could never take an update. A locked node whose settings are ever lost (worn or corrupted flash) keeps relaying under a new identity, but takes no provisioning or update again.

Before burning any board in the field, burn one on the bench, check it boots from the web flasher's image, takes an OTA update from a second release node, and rolls back from a deliberately broken image. On that board, after an update so that its two app slots hold different versions, also check what the two writes above do before it is locked (`esptool --no-stub write-flash` of 0xFF bytes over `otadata`, then over `nvs`, at the offsets in [MEMORY.md](MEMORY.md)), so the release's own behavior is on record; then provision it again, `lock yes`, and check `esptool` no longer connects.

## Reproducibility

`CONFIG_APP_REPRODUCIBLE_BUILD` strips paths and build times; ESP-IDF and its Python environment are pinned by image digest (`docker/Dockerfile`), and the tools it lacks by hash (`docker/requirements-dev.txt`). The workflow checks two builds on one runner match; matching across machines follows from the pinned image, and anyone can check a release by building the tag in it and comparing against the unsigned artifacts.
