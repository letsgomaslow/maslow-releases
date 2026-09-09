# Public distribution safety

This repository contains public delivery metadata and documentation only. Runtime source is maintained in the private Hub repository. Release binaries belong in GitHub Releases, not Git history.

- Never publish private keys, credentials, personal data, ISO files, or internal build logs.
- Promote only an explicitly approved signed bundle after anonymous artifact verification and recorded acceptance.
- Preserve immutable released bytes and earlier rollback packages. Never overwrite an artifact, move a released checksum tag, or lower a channel sequence.
- Publish each manifest/signature and catalog/signature pair in one Pages commit; preserve the other channel.
- Keep test keys and fixtures out of production channels. Updating documentation does not authorize promotion.
- Update README status only to match actual evidence. An endpoint returning HTTP 200 is not proof of an authenticated client update.
