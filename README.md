# Maslow Hub distribution

Public delivery infrastructure for signed Maslow Hub packages and channel metadata. The development source repository is maintained separately.

## Status

Infrastructure setup only. No signed staging or alpha channel is published yet. Do not install files based only on their presence in this repository. A working channel requires independently authenticated Maslow trust, verified release artifacts, and recorded update/rollback acceptance.

GitHub Releases will hold immutable checksum-addressed packages and signatures. GitHub Pages will serve separately signed staging/alpha manifests and data-only catalogs. Package publication and channel promotion are separate reviewed steps.

Never commit private signing keys, provider credentials, personal traces, source build logs, or ISO images here. No account token should be required on a client to download public update artifacts.
