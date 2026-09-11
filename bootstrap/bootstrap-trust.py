#!/usr/bin/python3
"""One-time, fingerprint-authenticated trust enrollment. Run from a verified local copy."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

PAGES = "https://letsgomaslow.github.io/maslow-releases"


def atomic_file(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint", required=True, help="SHA-256 of public-key SPKI DER, verified independently")
    parser.add_argument("--channel", choices=("staging", "alpha"), default="staging")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run in a terminal using normal sudo authorization.")
    if not re.fullmatch(r"[0-9a-f]{64}", args.fingerprint):
        parser.error("Fingerprint must be exactly 64 lowercase hexadecimal characters.")
    trust = Path("/usr/share/maslow-hub/trust/release.pem")
    config = Path("/etc/maslow-hub/channel.json")
    if trust.is_symlink() or config.is_symlink():
        parser.error("Symlink trust/config paths are not supported.")
    with urllib.request.urlopen(f"{PAGES}/bootstrap/release.pem", timeout=30) as response:
        if not response.geturl().startswith("https://"):
            parser.error("Insecure key redirect rejected.")
        public = response.read(65537)
    if len(public) > 65536 or b"PRIVATE KEY" in public:
        parser.error("Invalid public-key file.")
    result = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, capture_output=True)
    if result.returncode or hashlib.sha256(result.stdout).hexdigest() != args.fingerprint:
        parser.error("Downloaded key does not match the independently trusted fingerprint.")
    if trust.exists() and trust.read_bytes() != public:
        parser.error("Existing trust differs. Use a separately reviewed key-rotation procedure.")
    channel = {"schemaVersion": 1, "channel": args.channel,
               "channelUrl": f"{PAGES}/hub/{args.channel}/manifest.json",
               "signatureUrl": f"{PAGES}/hub/{args.channel}/manifest.json.sig",
               "catalogUrl": f"{PAGES}/hub/{args.channel}/catalog.json",
               "catalogSignatureUrl": f"{PAGES}/hub/{args.channel}/catalog.json.sig"}
    desired = (json.dumps(channel, indent=2) + "\n").encode()
    if config.exists() and config.read_bytes() != desired:
        backup = config.with_name("channel.json.before-trust-bootstrap")
        if backup.exists():
            parser.error("A prior bootstrap backup exists; review configuration before retrying.")
        atomic_file(backup, config.read_bytes())
    atomic_file(trust, public)
    atomic_file(config, desired)
    print("Hub trust enrolled. No packages installed. Open Hub and explicitly check for updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
