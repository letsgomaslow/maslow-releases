# Public distribution safety

This repository contains public delivery metadata and documentation only. Runtime source is maintained in the private Hub repository. Release binaries belong in GitHub Releases, not Git history.

- Never publish private keys, credentials, personal data, ISO files, or internal build logs.
- Promote only an explicitly approved signed bundle after anonymous artifact verification and recorded acceptance.
- Preserve immutable released bytes and earlier rollback packages. Never overwrite an artifact, move a released checksum tag, or lower a channel sequence.
- Publish each manifest/signature and catalog/signature pair in one Pages commit; preserve the other channel.
- Keep test keys and fixtures out of production channels. Updating documentation does not authorize promotion.
- Update README status only to match actual evidence. An endpoint returning HTTP 200 is not proof of an authenticated client update.

## Scheduled staging renewal

- `.github/workflows/renew-staging.yml` re-signs `hub/staging` weekly (and on manual dispatch) with a fresh 30-day window. `tools/renew/renew-channel.py` first verifies the published files against `bootstrap/release.pem`, then changes only `sequence`, `generatedAt` and `expiresAt`. It cannot add, remove or alter a release, artifact, note or catalog item.
- The encrypted release key (`HUB_RELEASE_SIGNING_KEY`) and its passphrase (`HUB_SIGNING_PASSPHRASE`) are stored only as secrets of the `hub-staging-signing` environment, which is limited to `main`. This was an operator decision on 2026-10-09; write access to this repository is therefore release-signing access, so keep it to maintainers and review every workflow change. The workflow has no pull-request trigger, so forks cannot reach the secret. New releases and catalog changes are still built and signed on the operator's Mac; CI only renews them.
- `tools/renew/*.py` are vendored from the private Hub repository's `release/` directory, which is canonical. Update both together.
- A failed run is the expiry alarm: GitHub emails the failure. Fix it before the published `expiresAt`; installed Hubs show "Updates paused" after expiry.
