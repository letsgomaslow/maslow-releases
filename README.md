# Maslow Hub distribution

Public delivery infrastructure for signed Maslow Hub packages and channel metadata. The development source repository is maintained separately.

## Status

Internal staging offers Hub 0.3.2 with Maslow Voice 0.1.4-9 for GPT-Live testing, retaining immutable 0.3.0, 0.2.1, 0.2.0 and the exact 0.1.3 Hub rollback baseline. Package downloads and signatures were verified anonymously before this metadata promotion. After updating Hub, choose Update Voice on its Voice page, then open Voice Settings, select GPT-Live cloud and choose from 22 voices. First-time Voice users choose Install Voice instead. Voice installation and the separate task agent's setup remain explicit actions.

The exact Voice package has prior installed-system conversation and task evidence with documented audio and speech-recognition limits. This release's installed test-system Hub/Voice update, state preservation and native voice selection passed; a separate fresh Mac synthetic GPT-Live connection check passed. Physical microphone/speaker quality, spoken filenames and Lenovo update acceptance remain test items. Use a disposable project and verify task results. LiveKit testing remains pending. This is not a stable release. Alpha is not published.

The last manually promoted staging manifest was sequence 5, expiring on 2026-09-24 at 23:56:41 UTC. Current sequence and expiry are in the [published signed manifest](https://letsgomaslow.github.io/maslow-releases/hub/staging/manifest.json). A workflow being present does not prove renewal succeeded. Expired metadata must be renewed and signed; clients must not bypass expiry or signature checks.

Use Hub's Updates page only after trusted enrollment. The bootstrap script and public verification key are in `bootstrap/`; authenticate the script checksum and public-key fingerprint through an independently trusted operator before running it. Never copy a private signing key to an end-user computer. No ISO rebuild is needed for this Hub update.

GitHub Releases holds immutable packages and signatures under `sha256-<checksum>` tags. GitHub Pages serves signed staging metadata and a data-only catalog at `hub/staging/`. Package publication and channel promotion are separate reviewed steps.

Never commit private signing keys, provider credentials, personal traces, source build logs, or ISO images here. No account token should be required on a client to download public update artifacts.

## Release from either computer

1. Open [Build and publish Hub staging release](https://github.com/letsgomaslow/maslow-releases/actions/workflows/release-hub.yml), choose `main`, and supply reviewed full Hub and package-recipe commit hashes plus release notes. The default creates an encrypted review candidate only. Enable the publication request only when you want a candidate to reach the approval gate.
2. Inspect the build summary: source and recipe revisions, version, package checksum, retained Voice payload and release notes. A successful build establishes source/package checks, not graphical, device, rollback or Voice acceptance. Obtain the applicable acceptance evidence before approval.
3. For a requested publication, the release owner approves the `hub-release-publishing` environment in GitHub. That approval releases signing credentials to the protected publication job, which verifies and publishes the exact candidate as immutable artifacts, promotes signed metadata, and checks anonymous delivery.
4. On the Lenovo, check the existing enrolled staging channel normally and record actual update/state-preservation results. Do not re-enroll trust, reset sequence protection, or rebuild the ISO for a Hub-only release.

[Renew Hub staging signatures](https://github.com/letsgomaslow/maslow-releases/actions/workflows/renew-staging.yml) separately renews existing metadata weekly and on manual request; it does not publish a new version. A successful run must verify both publicly downloaded signature pairs and the exact expected bytes. Failure notifications depend on your GitHub notification settings; periodically check channel expiry as well.

`main` holds reviewed workflow code and the trust root. GitHub Pages serves the separate `signed-staging` data branch; public URLs and installed-client trust are unchanged. Keep future promotions on that branch and preserve alpha. Encrypted candidate artifacts expire after seven days; after expiry, build a new candidate. A partially published draft or existing checksum tag requires inspection rather than overwriting or force-pushing.
