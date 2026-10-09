#!/usr/bin/python3
# Vendored from letsgomaslow/maslow-hub release/renew-channel.py; the Hub repository is canonical. Keep in sync.
"""Renew the validity window of an already published, signed Hub channel.

Only `sequence`, `generatedAt` and `expiresAt` change. Releases, artifact URLs,
checksums, notes and catalog items are carried over byte-for-byte after the
existing signatures verify, so this key use can never introduce a new release.
It does not publish anything or create keys.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from signing import canonical, check_private_key, sign, verify, write_atomic

RENEWED_FIELDS = {"sequence", "generatedAt", "expiresAt"}
MAX_DAYS = 31


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-dir", type=Path, required=True, help="directory holding manifest.json, catalog.json and their .sig files")
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True, help="pinned release trust root used by installed Hubs")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--now", help="ISO-8601 UTC time override for reproducible tests")
    return parser.parse_args()


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_verified(channel_dir: Path, name: str, public_key: Path) -> dict:
    source, signature = channel_dir / name, channel_dir / f"{name}.sig"
    if not source.is_file() or not signature.is_file():
        raise SystemExit(f"{name} and {name}.sig are required")
    if not verify(public_key, source, signature):
        raise SystemExit(f"{name} does not verify against the pinned public key; refusing to renew it")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("sequence"), int):
        raise SystemExit(f"{name} uses an unsupported schema")
    return value


def renewed(previous: dict, now: dt.datetime, days: int) -> dict:
    value = dict(previous)
    value.update(sequence=previous["sequence"] + 1, generatedAt=timestamp(now), expiresAt=timestamp(now + dt.timedelta(days=days)))
    unchanged = {key: item for key, item in value.items() if key not in RENEWED_FIELDS}
    if unchanged != {key: item for key, item in previous.items() if key not in RENEWED_FIELDS}:
        raise SystemExit("renewal may change only sequence, generatedAt and expiresAt")
    return value


def main() -> int:
    args = arguments()
    check_private_key(args.private_key)
    if not 1 <= args.days <= MAX_DAYS:
        raise SystemExit(f"--days must be between 1 and {MAX_DAYS}")
    now = dt.datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else dt.datetime.now(dt.timezone.utc)
    manifest = load_verified(args.channel_dir, "manifest.json", args.public_key)
    catalog = load_verified(args.channel_dir, "catalog.json", args.public_key)
    if catalog.get("kind") != "catalog" or catalog.get("channel") != manifest.get("channel"):
        raise SystemExit("catalog and manifest must belong to the same channel")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name, value in (("manifest.json", renewed(manifest, now, args.days)), ("catalog.json", renewed(catalog, now, args.days))):
        target = write_atomic(output, name, canonical(value))
        signature = output / f"{name}.sig"
        sign(args.private_key, target, signature)
        if not verify(args.public_key, target, signature):
            raise SystemExit(f"renewed {name} does not verify against the pinned public key; the signing key does not match the trust root")
        print(f"{name}: sequence {value['sequence']}, expires {value['expiresAt']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
