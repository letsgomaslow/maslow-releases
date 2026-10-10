# Local release workstation

Any maintainer machine (the Lenovo today; the Mac can be set up the same way) can renew, prepare, verify and publish Hub staging releases without GitHub Actions. `tools/local-release.py` is a thin front end over the same reviewed tools the workflows use: `build-candidate.py`, `publish-candidate.py`, `renew/renew-channel.py`, `channel-data.py` and `verify-delivery.py`. There is one signing key and one signing implementation.

## Where things live

| What | Where | In Git? |
| --- | --- | --- |
| Release tools | this repository, at a clean committed revision | yes |
| Workstation paths | `~/.config/maslow-release/workstation.json` (600) | no |
| Encrypted private key | `<signingDir>/release-key.pem` (600, directory 700) | never |
| Public key | `<signingDir>/release.pem` (600), byte-identical to `bootstrap/release.pem` | public copy only |
| Run evidence | `<workDir>/runs/<UTC time>-<operation>/record.json` | no |
| Candidate builds | `<workDir>/runs/<UTC time>-prepare/candidate/` | no |

The passphrase is typed into OpenSSL's own prompt each time. It is never stored, passed as an argument or read by these tools. Any `HUB_SIGNING_PASSPHRASE` variable is removed before local signing.

## One-time setup

1. Python 3.12+, Git, OpenSSL, bsdtar, zstd, curl, Docker (for `prepare`) and an authenticated `gh`.
2. Clone `maslow-releases`, `maslow-hub` and `maslow-os-pkgs` as development checkouts, not installed runtime paths.
3. `python3 tools/local-release.py init --hub-checkout … --recipe-checkout …`
4. Create the signing directory with mode 700 and copy the existing encrypted key and public key into it privately with mode 600. Never generate a replacement key.
5. `python3 tools/local-release.py fingerprint`: OpenSSL asks for the passphrase and the tool compares the private-key-derived fingerprint with the pinned `daacaa5aac138710a3950097b29a05abd3f69c9a8efad512321c45f3103d1ee4`.
6. `python3 tools/local-release.py doctor`

## Operations

- `verify [--candidate DIR]` (no key): fetches `signed-staging`, verifies both signed pairs, checks that Pages serves exactly that commit and, for a candidate, shows the sequence it would publish and the rollback releases it keeps.
- `renew [--no-push]`: re-signs the published channel with a fresh 30-day window. It changes only `sequence`, `generatedAt` and `expiresAt`.
- `prepare --source-sha … --recipe-sha … --note …` (no key): builds a review-only candidate in the isolated Arch container from detached worktrees at the exact commits. Developer checkouts are left untouched. It records the package checksum and the review digest.
- `publish --candidate DIR --approve <review sha256> [--no-push]`: signs and publishes an approved candidate. It never runs without the exact reviewed digest; publish a new version only after the release owner approves that digest.

`--no-push` signs and verifies everything locally and publishes nothing. Use it to rehearse with the production key.
- `resume` (no passphrase): finishes an interrupted publish. `publish` keeps its signed files in the run folder before uploading. `resume` re-verifies them against the pinned key and the approved checksum, compares any draft assets byte for byte and uploads only missing ones (never replacing), publishes the release, checks the anonymous downloads and promotes the channel. It refuses if anyone has published since the run started.

## Two workstations, one channel

Before signing, every operation:
1. fetches the latest `signed-staging`;
2. verifies it against the pinned key;
3. requires Pages to serve exactly those bytes, so an unfinished deployment from the other machine stops the run before any signature.

The new commit must directly extend that fetched commit. The tool checks the remote tip again and then performs a normal (fast-forward-only) push. If the other workstation published in between, the push fails; run the command again and it continues from the newer sequence. Nothing is ever force-pushed. `signed-staging` is protected against force-pushes and deletion for everyone, including admins. Sequences only increase, released assets are immutable and checksum tags never move.

## Publication path

Pages serves the `signed-staging` branch at the unchanged URL `https://letsgomaslow.github.io/maslow-releases/`. Bootstrap files, the index and every channel file stay byte-identical across the switch. `main` keeps its protections and its required Actions check. Branch Pages builds still ran under the 2026-10 Actions billing lock (verified 2026-10-09); if a build ever fails, the previously deployed site keeps serving and `verify` reports the mismatch.

## Tests

`python3 -m unittest discover -s tests -v` runs everything with disposable keys, a local bare repository standing in for GitHub and a local directory standing in for Pages. The archive-ownership tests run the Hub's actual policy when a Hub checkout is beside this one or `MASLOW_HUB_SRC` is set. Passing tests are not evidence of a real publication; only a recorded `renew`/`publish` run plus anonymous delivery and an installed Hub's acceptance are.
