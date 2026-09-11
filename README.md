# Maslow Hub distribution

Public delivery infrastructure for signed Maslow Hub packages and channel metadata. The development source repository is maintained separately.

## Status

Internal staging offers Hub 0.2.1 recovery improvements, retaining 0.2.0 and the exact 0.1.3 rollback baseline. Package downloads and signatures were verified anonymously before this metadata promotion. The recovery update clarifies installation progress, requirements, Docker access and update discovery. End-user internet update/rollback and experimental local observability acceptance remain pending; this is not a stable release. Alpha is not published.

Staging manifest sequence: 3. Metadata expires on 2026-09-24 at 23:56:41 UTC. Expired metadata must be renewed and signed; clients must not bypass expiry or signature checks.

Use Hub's Updates page only after trusted enrollment. The bootstrap script and public verification key are in `bootstrap/`; authenticate the script checksum and public-key fingerprint through an independently trusted operator before running it. Never copy a private signing key to an end-user computer. No ISO rebuild is needed for this Hub update.

GitHub Releases holds immutable packages and signatures under `sha256-<checksum>` tags. GitHub Pages serves signed staging metadata and a data-only catalog at `hub/staging/`. Package publication and channel promotion are separate reviewed steps.

Never commit private signing keys, provider credentials, personal traces, source build logs, or ISO images here. No account token should be required on a client to download public update artifacts.
