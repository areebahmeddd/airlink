# Contributing to Airlink

Thanks for your interest in contributing. This guide walks you from picking up an issue to a merged pull request. The rules the code itself must follow (protocol compatibility, layering, crypto, radio, C style and comments) live in [`AGENTS.md`](AGENTS.md), which binds human contributors and AI agents alike.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Found a vulnerability? Report it privately, as [`SECURITY.md`](SECURITY.md) describes, never in a public issue.

## 1. Read First

1. [`README.md`](README.md): what the node does, the boards, how to build
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the layers, the tasks and how a packet moves through the node
3. [`docs/PROTOCOL.md`](docs/PROTOCOL.md): each protocol rule the node follows, where it is implemented and its test
4. [`AGENTS.md`](AGENTS.md): the rules, and where each part of the code lives

If your change touches one subsystem, also read its document in [`docs/`](docs/); the README's [Documentation](README.md#documentation) table lists which covers what.

## 2. Set Up

Everything builds in one pinned Docker image, so you need only Docker and git:

```bash
scripts/docker.sh 'scripts/build.sh heltec_v4 dev'
scripts/check.sh quick
```

With ESP-IDF v6.1 installed locally, `scripts/build.sh heltec_v4 dev flash monitor` builds, flashes and opens the console.

**Flash only the `dev` profile while you work.** A `release` image burns one-time eFuses on its first boot ([`docs/RELEASE.md`](docs/RELEASE.md)), after which the board can never be flashed over USB again.

## 3. Make the Change

Keep the change to one concern, and follow the file's existing conventions before introducing your own. Protocol logic belongs in the pure C core (`ah_proto`, `ah_crypto`, `ah_noise`, `ah_mesh`, `ah_lora/core`), with tests, before any ESP-IDF code uses it.

A protocol change (anything a phone sends, reads or relays) is checked against Airhop's `docs/spec/PROTOCOLS.md` and against what bitchat-ios does, and needs a real exchange between an Airhop phone, a bitchat-ios phone and a bitchat-android phone through a node before it ships. Adding a board follows [`docs/BOARDS.md`](docs/BOARDS.md), "Adding a Board".

## 4. Test

A change to the core comes with host tests, and a bug fix comes with a test that fails without the fix. Beyond that:

- **Wire contracts** pin literal bytes from a spec or from bitchat-ios, not a round trip through the code under test. `test/vectors/` is the pattern.
- **A new parser** gets a fuzz harness beside the others in `test/fuzz/`, which `scripts/fuzz-smoke.sh` runs.
- **Anything that touches a radio** is tested on boards, using the runbook in [`docs/TESTING.md`](docs/TESTING.md). Say in the pull request which boards and phones you used.

## 5. Commits

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), scoped to the component where one fits: `feat(lora): ...`, `fix(mesh): ...`, `docs: ...`, `test(device): ...`. One logical change per commit.

Every commit carries a `Signed-off-by` trailer, which `git commit -s` adds. It certifies the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the contribution or have the right to submit it under this project's license.

## 6. Pull Request Checklist

- [ ] A bug fix has a test that fails without it
- [ ] `scripts/check.sh` passes (formatting, vectors, static analysis, host tests, fuzzing, every board, size gate)
- [ ] `dependencies.lock.*` unchanged, unless the change bumps a component
- [ ] `test/size-baseline.json` updated with `scripts/size-gate.sh <board> --write` only when a size change is intended, and the reason given
- [ ] [`docs/PROTOCOL.md`](docs/PROTOCOL.md) updated if a protocol rule changed, with the test that covers it
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` for anything a user would notice
- [ ] The pull request says what was tested, and on which boards and phones

## 7. Releases

Releases are cut by the maintainer, never from a pull request. The version and changelog are set and tagged, CI builds each board twice and drafts the release with the unsigned outputs, and the maintainer signs them offline with the project's keys, publishes, and redeploys the web flasher. [`docs/RELEASE.md`](docs/RELEASE.md) has the steps.
