#!/usr/bin/python3
"""Keep unsigned packages encrypted in public Actions artifacts until approval."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def transfer(operation, source, destination):
    secret = os.environ.get("HUB_CANDIDATE_ENCRYPTION_KEY", "")
    if not re.fullmatch(r"[a-f0-9]{64}", secret):
        raise ValueError("candidate encryption key must be 32 random bytes encoded as hex")
    review = json.loads((source / "review.json").read_text())
    package = review["package"]
    name = package["filename"]
    if not re.fullmatch(r"maslow-hub-[A-Za-z0-9._+:-]+\.pkg\.tar\.zst", name):
        raise ValueError("invalid candidate package name")
    if not re.fullmatch(r"[a-f0-9]{64}", package["sha256"]):
        raise ValueError("invalid candidate digest")
    destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="candidate-gpg-") as home:
        common = ["gpg", "--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        if operation == "encrypt":
            plaintext = source / name
            check_package(plaintext, package)
            args = ["--cipher-algo", "AES256", "--force-mdc", "--symmetric", "--output", str(destination / "candidate.pkg.gpg"), str(plaintext)]
        else:
            plaintext = destination / name
            args = ["--decrypt", "--output", str(plaintext), str(source / "candidate.pkg.gpg")]
        result = subprocess.run(common + args, input=(secret + "\n").encode(), capture_output=True)
        if result.returncode:
            if plaintext.parent == destination:
                plaintext.unlink(missing_ok=True)
            raise ValueError("candidate encryption/decryption failed; refusing publication")
        if operation == "decrypt":
            try:
                check_package(plaintext, package)
            except ValueError:
                plaintext.unlink(missing_ok=True)
                raise
    (destination / "review.json").write_text(json.dumps(review, indent=2) + "\n")


def check_package(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected["size"]:
        raise ValueError("candidate size or file type does not match review")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected["sha256"]:
        raise ValueError("candidate digest does not match review")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    transfer(args.operation, args.source, args.destination)


if __name__ == "__main__":
    main()
