# Public distribution safety

This repository contains public delivery metadata and documentation only. Runtime source is maintained in the private Hub repository. Release binaries belong in GitHub Releases, not Git history.

- Never publish private keys, credentials, personal data, ISO files, or internal build logs.
- Promote only an explicitly approved signed bundle after anonymous artifact verification and recorded acceptance.
- Preserve immutable released bytes and earlier rollback packages. Never overwrite an artifact, move a released checksum tag, or lower a channel sequence.
- Publish each manifest/signature and catalog/signature pair in one `signed-staging` Pages commit; preserve the other channel. `main` owns protected workflow code, tools and the pinned trust root; its channel files are historical seed data, not current delivery state. Never execute scripts from the data branch.
- Keep test keys and fixtures out of production channels. Updating documentation does not authorize promotion.
- Update README status only to match actual evidence. An endpoint returning HTTP 200 is not proof of an authenticated client update.

## Scheduled staging renewal

- `.github/workflows/renew-staging.yml` re-signs `hub/staging` weekly (and on manual dispatch) with a fresh 30-day window. `tools/renew/renew-channel.py` first verifies the published files against `bootstrap/release.pem`, then changes only `sequence`, `generatedAt` and `expiresAt`. It cannot add, remove or alter a release, artifact, note or catalog item.
- The encrypted release key (`HUB_RELEASE_SIGNING_KEY`) and its passphrase (`HUB_SIGNING_PASSPHRASE`) belong only in the `hub-staging-signing` and `hub-release-publishing` environment secrets. Both environments allow only protected `main`; new publication additionally requires the release owner's environment approval. Main requires owner review, with an explicit owner-only bypass for operator maintenance. Never give the workflow bot a bypass for modifying main. Anyone controlling the owner account or approved signing code still controls the release key; encryption at rest does not limit signing authority.
- `tools/renew/*.py` are vendored from the private Hub repository's `release/` directory, which is canonical. Update both together.
- Check failed runs and configure GitHub Actions failure notifications; email delivery depends on account settings. Fix renewal before the published `expiresAt`; newer Hubs show "Updates paused" after expiry. A missing run is not a successful renewal.

## GitHub candidate builds and publication

- `release-hub.yml` accepts exact Hub and package-recipe commits and defaults to build-only. Review the candidate summary and native acceptance evidence before requesting/approving publication. It builds the existing package recipe in an isolated Arch container, preserves the exact signed 0.3.2 Voice payload, and never rebuilds an ISO or silently updates Voice.
- `hub-source-build` holds a read-only deploy key for the private Hub repository and a random candidate-encryption key. The deploy key is deleted before source execution. Unsigned packages are encrypted before upload to this public repository's Actions artifacts; only allowlisted review metadata is readable. The encryption key is also present in `hub-release-publishing` so the approved job can decrypt the same candidate.
- Publication verifies the review digest from the build job, the package checksum/version, previous signed metadata, immutable-release policy and public artifact bytes. It preserves all previous rollback entries and catalog items, then commits both signed pairs together. A competing update fails the normal fast-forward push; never force-push or lower sequences. Existing checksum tags/drafts require manual recovery; do not overwrite them or blindly rerun publication.
- All automation runs from protected `main`. Pages serves `signed-staging` at the unchanged URL. The source clone, package recipe and package content are untrusted build inputs and must never execute in a signing job. Run `python3 -m unittest discover -s tests -v` for infrastructure changes; fixture checks do not establish a real cloud build or Lenovo acceptance.

## Local release workstations

- `tools/local-release.py` (see `docs/local-release.md`) lets the Lenovo or the Mac renew, prepare, verify and publish without GitHub Actions, through the same tools as the workflows. Machine paths stay in `~/.config/maslow-release/workstation.json`; the encrypted key stays in a 700 signing directory and OpenSSL prompts for its passphrase.
- Signing runs only from a clean committed checkout of this repository. Before signing it fetches `signed-staging`, verifies it and requires Pages to serve exactly those bytes; publication is a normal fast-forward push. Never force-push, lower sequences, overwrite released assets or move checksum tags.
- `--no-push` is a local rehearsal and publishes nothing. Tests use disposable keys and local fakes; they are not publication evidence.

