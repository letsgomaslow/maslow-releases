# Maslow Hub distribution

Public delivery infrastructure for signed Maslow Hub packages and channel metadata. The development source repository is maintained separately.

## Status

Internal staging offers Hub 0.3.2 with Maslow Voice 0.1.4-9 for GPT-Live testing, retaining immutable 0.3.0, 0.2.1, 0.2.0 and the exact 0.1.3 Hub rollback baseline. Package downloads and signatures were verified anonymously before this metadata promotion. After updating Hub, choose Update Voice on its Voice page, then open Voice Settings, select GPT-Live cloud and choose from 22 voices. First-time Voice users choose Install Voice instead. Voice installation and the separate task agent's setup remain explicit actions.

The exact Voice package has prior installed-system conversation and task evidence with documented audio and speech-recognition limits. This release's installed test-system Hub/Voice update, state preservation and native voice selection passed; a separate fresh Mac synthetic GPT-Live connection check passed. Physical microphone/speaker quality, spoken filenames and Lenovo update acceptance remain test items. Use a disposable project and verify task results. LiveKit testing remains pending. This is not a stable release. Alpha is not published.

Staging manifest sequence: 5. Metadata expires on 2026-09-24 at 23:56:41 UTC. Expired metadata must be renewed and signed; clients must not bypass expiry or signature checks.

Use Hub's Updates page only after trusted enrollment. The bootstrap script and public verification key are in `bootstrap/`; authenticate the script checksum and public-key fingerprint through an independently trusted operator before running it. Never copy a private signing key to an end-user computer. No ISO rebuild is needed for this Hub update.

GitHub Releases holds immutable packages and signatures under `sha256-<checksum>` tags. GitHub Pages serves signed staging metadata and a data-only catalog at `hub/staging/`. Package publication and channel promotion are separate reviewed steps.

Never commit private signing keys, provider credentials, personal traces, source build logs, or ISO images here. No account token should be required on a client to download public update artifacts.
