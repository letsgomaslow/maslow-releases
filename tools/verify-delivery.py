#!/usr/bin/python3
"""Verify anonymously served channel bytes against the committed release and trust root."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import urlencode, urlsplit


FILES = ("manifest.json", "manifest.json.sig", "catalog.json", "catalog.json.sig")


class VerificationError(Exception):
    pass


def verify_channel(directory: Path, public_key: Path, min_days: float) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    for name in ("manifest.json", "catalog.json"):
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_key),
             "-signature", str(directory / f"{name}.sig"), str(directory / name)],
            capture_output=True, timeout=10,
        )
        if result.returncode:
            raise VerificationError(f"{name}: signature does not match the pinned public key")
        try:
            value = json.loads((directory / name).read_bytes())
            expires = dt.datetime.fromisoformat(value["expiresAt"].replace("Z", "+00:00"))
            if expires.tzinfo is None:
                raise ValueError("missing expiry timezone")
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise VerificationError(f"{name}: invalid expiry metadata") from error
        if expires - now < dt.timedelta(days=min_days):
            raise VerificationError(f"{name}: expires in fewer than {min_days:g} days")


def download(url: str, destination: Path, timeout: float) -> None:
    # -q disables ~/.curlrc, including any implicit credentials. No auth headers
    # or GitHub token are passed; redirects must also remain HTTPS.
    result = subprocess.run(
        ["curl", "-q", "--fail", "--silent", "--show-error", "--location",
         "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "10485760",
         "--connect-timeout", str(min(10, timeout)), "--max-time", str(timeout),
         "--output", str(destination), url],
        capture_output=True, timeout=timeout + 1,
    )
    if result.returncode:
        raise VerificationError(f"{destination.name}: anonymous download failed (curl {result.returncode})")


def verify_once(expected: dict[str, bytes], public_key: Path, base_url: str,
                deadline: float, min_days: float, attempt: int) -> None:
    with tempfile.TemporaryDirectory(prefix="hub-delivery-") as temporary:
        served = Path(temporary)
        for name in FILES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError("delivery deadline reached")
            query = urlencode({"verify": f"{time.time_ns()}-{attempt}"})
            download(f"{base_url.rstrip('/')}/{name}?{query}", served / name, min(20, remaining))
            if (served / name).read_bytes() != expected[name]:
                raise VerificationError(f"{name}: served bytes differ from the committed channel")
        verify_channel(served, public_key, min_days)


def confirm_delivery(channel_dir: Path, public_key: Path, base_url: str,
                     timeout: float = 600, interval: float = 20, min_days: float = 10) -> None:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise VerificationError("base URL must be an HTTPS URL without credentials, query or fragment")
    if not all(math.isfinite(value) for value in (timeout, interval, min_days)) or timeout <= 0 or interval <= 0 or min_days < 0:
        raise VerificationError("timeout and interval must be positive; min-days cannot be negative")
    expected = {name: (channel_dir / name).read_bytes() for name in FILES}
    # Reject bad local inputs immediately instead of waiting for a deployment.
    verify_channel(channel_dir, public_key, min_days)
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            verify_once(expected, public_key, base_url, deadline, min_days, attempt)
            print("Anonymous delivery verified: all four committed files, both signatures, and expiry windows.")
            return
        except (VerificationError, subprocess.TimeoutExpired, OSError) as error:
            print(f"Waiting for Pages (attempt {attempt}): {error}", flush=True)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
    raise VerificationError(f"Pages did not serve the verified committed channel within {timeout:g} seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-dir", type=Path, required=True, help="directory containing the four committed channel files")
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--interval", type=float, default=20)
    parser.add_argument("--min-days", type=float, default=10)
    args = parser.parse_args()
    try:
        confirm_delivery(args.expected_dir, args.public_key, args.base_url,
                         args.timeout, args.interval, args.min_days)
    except (VerificationError, subprocess.TimeoutExpired, OSError) as error:
        parser.exit(1, f"Delivery verification failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
