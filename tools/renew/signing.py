# Vendored from letsgomaslow/maslow-hub release/signing.py; the Hub repository is canonical. Keep in sync.
"""Shared detached-signing helpers for the release scripts. This never creates keys."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def check_private_key(key: Path) -> None:
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise SystemExit("private key must exist and must not be accessible to group or other users")


def canonical(value: dict) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def write_atomic(output: Path, name: str, raw: bytes) -> Path:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{Path(name).stem}-", dir=output)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    target = output / name
    os.replace(temporary, target)
    os.chmod(target, 0o644)
    return target


PASSPHRASE_VARIABLE = "HUB_SIGNING_PASSPHRASE"


def sign(key: Path, source: Path, destination: Path) -> None:
    argv = ["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(destination)]
    if os.environ.get(PASSPHRASE_VARIABLE):
        # Unattended CI: OpenSSL reads the passphrase from the environment, never from argv.
        # Without it, OpenSSL prompts interactively as on the operator's Mac.
        argv += ["-passin", f"env:{PASSPHRASE_VARIABLE}"]
    subprocess.run(argv + [str(source)], check=True)
    os.chmod(destination, 0o644)


def verify(public_key: Path, source: Path, signature: Path) -> bool:
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(source)],
                            capture_output=True, text=True)
    return result.returncode == 0
