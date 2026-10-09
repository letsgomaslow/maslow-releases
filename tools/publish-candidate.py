#!/usr/bin/python3
"""Sign an approved Hub candidate; publish immutable assets only with --publish.

Channel promotion is a separate operation. No code from the candidate is run.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "renew"))
from signing import canonical, check_private_key, sign, verify, write_atomic

REPOSITORY = "letsgomaslow/maslow-releases"
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
SHA256 = r"[0-9a-f]{64}"
REFRESH_FIELDS = {"sequence", "generatedAt", "expiresAt"}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_review(path: Path, package: Path) -> dict:
    require(path.stat().st_size <= 65536, "Review metadata is too large")
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and set(value) == {
        "schemaVersion", "version", "package", "source", "recipe", "notes", "voice", "buildImage"
    }, "Review must contain only the allowlisted public provenance fields")
    require(value["schemaVersion"] == 1 and isinstance(value["version"], str)
            and re.fullmatch(SEMVER, value["version"]) is not None, "Invalid candidate version")
    expected_name = f"maslow-hub-{value['version']}-1-any.pkg.tar.zst"
    info = value["package"]
    require(isinstance(info, dict) and set(info) == {"filename", "sha256", "size"}, "Invalid package review")
    require(package.is_file() and not package.is_symlink() and package.name == expected_name
            and info["filename"] == expected_name, "Candidate filename does not match the reviewed version")
    require(type(info["size"]) is int and 0 < info["size"] <= 2 * 1024**3
            and package.stat().st_size == info["size"], "Candidate size does not match review")
    require(isinstance(info["sha256"], str) and re.fullmatch(SHA256, info["sha256"]) is not None
            and digest(package) == info["sha256"], "Candidate checksum does not match review")
    for field, repository in (("source", "letsgomaslow/maslow-hub"), ("recipe", "letsgomaslow/maslow-os-pkgs")):
        provenance = value[field]
        require(isinstance(provenance, dict) and set(provenance) == {"repository", "commit"}
                and provenance["repository"] == repository and isinstance(provenance["commit"], str)
                and re.fullmatch(r"[0-9a-f]{40}", provenance["commit"]) is not None, f"Invalid {field} provenance")
    voice = value["voice"]
    require(isinstance(voice, dict) and set(voice) == {"sourceVersion", "sourceSha256", "manifestSha256"}
            and voice["sourceVersion"] == "0.3.2"
            and voice["sourceSha256"] == "7cbd9494df66526834a73bc390179c596f18db2e8125694c5b5ba24c1d9ed1ab"
            and isinstance(voice["manifestSha256"], str)
            and re.fullmatch(SHA256, voice["manifestSha256"]) is not None, "Invalid Voice donor provenance")
    require(isinstance(value["buildImage"], str)
            and re.fullmatch(r"archlinux@sha256:" + SHA256, value["buildImage"]) is not None, "Build image must be pinned")
    require(isinstance(value["notes"], list) and 1 <= len(value["notes"]) <= 20
            and all(isinstance(note, str) and 1 <= len(note) <= 2000
                    and not any(ord(c) < 32 for c in note) for note in value["notes"]), "Invalid public release notes")
    # Read one metadata member without extracting or running package scripts.
    with subprocess.Popen(["bsdtar", "-xOf", str(package), ".PKGINFO"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        raw = process.stdout.read(65537)
        if len(raw) > 65536:
            process.kill()
            raise ValueError("Package metadata is too large")
        require(process.wait() == 0, "Cannot read package metadata")
    pkginfo = raw.decode("utf-8")
    fields: dict[str, list[str]] = {}
    for line in pkginfo.splitlines():
        if " = " in line:
            key, item = line.split(" = ", 1)
            fields.setdefault(key, []).append(item)
    for key, expected in (("pkgname", "maslow-hub"), ("pkgver", value["version"] + "-1"), ("arch", "any")):
        require(fields.get(key) == [expected], f"Package {key} does not match reviewed candidate")
    return value


def verified_metadata(channel: Path, name: str, public_key: Path) -> dict:
    source, signature = channel / name, channel / (name + ".sig")
    require(source.stat().st_size <= 1024 * 1024, "Channel metadata is too large")
    require(verify(public_key, source, signature), f"Existing {name} signature is invalid")
    value = json.loads(source.read_text())
    require(isinstance(value, dict) and value.get("schemaVersion") == 1 and value.get("channel") == "staging"
            and type(value.get("sequence")) is int and value["sequence"] >= 1, "Unsupported channel metadata")
    return value


def next_metadata(channel: Path, public_key: Path, review: dict, now: dt.datetime) -> tuple[dict, dict]:
    manifest = verified_metadata(channel, "manifest.json", public_key)
    catalog = verified_metadata(channel, "catalog.json", public_key)
    require(catalog.get("kind") == "catalog" and isinstance(catalog.get("items"), list), "Invalid catalog")
    releases = manifest.get("releases")
    require(isinstance(releases, list) and len(releases) > 0, "Existing rollback releases are required")
    versions = [item.get("version") for item in releases if isinstance(item, dict)]
    require(len(versions) == len(releases) and all(isinstance(v, str) and re.fullmatch(SEMVER, v) for v in versions)
            and len(set(versions)) == len(versions), "Invalid existing release versions")
    version_tuple = lambda v: tuple(map(int, v.split(".")))
    require(version_tuple(review["version"]) > max(map(version_tuple, versions)), "Candidate must be a new higher version")
    info = review["package"]
    require(all(item.get("sha256") != info["sha256"] for item in releases), "Candidate checksum already exists")
    url = f"https://github.com/{REPOSITORY}/releases/download/sha256-{info['sha256']}/{info['filename']}"
    release = {"version": review["version"], "sha256": info["sha256"], "packageSize": info["size"],
               "packageUrl": url, "signatureUrl": url + ".signature", "notes": review["notes"],
               "compatibility": {"architectures": ["x86_64"], "minHelperInterface": 1, "minRuntimeInterface": 1}}
    require(now.tzinfo is not None, "Publication time must include timezone")
    for value in (manifest, catalog):
        value.update(sequence=value["sequence"] + 1,
                     generatedAt=now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                     expiresAt=(now + dt.timedelta(days=30)).astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
    manifest["releases"] = releases + [release]
    return manifest, catalog


def gh_json(endpoint: str) -> object:
    return json.loads(subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, check=True).stdout)


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(newurl.startswith("https://"), "Insecure artifact redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify_anonymous(url: str, expected: Path) -> None:
    # No GitHub token or other authentication is passed to the public endpoint.
    opener = urllib.request.build_opener(SecureRedirect())
    actual = hashlib.sha256()
    size = 0
    with opener.open(url, timeout=60) as response:
        require(response.geturl().startswith("https://"), "Insecure artifact URL")
        while block := response.read(1024 * 1024):
            size += len(block)
            require(size <= expected.stat().st_size, "Published artifact is larger than expected")
            actual.update(block)
    require(size == expected.stat().st_size and actual.hexdigest() == digest(expected), "Published bytes differ from approved artifact")


def publish_assets(artifacts: Path, review: dict) -> None:
    identity = gh_json(f"repos/{REPOSITORY}")
    require(identity.get("full_name") == REPOSITORY and identity.get("private") is False, "Distribution repository must be public")
    require(gh_json(f"repos/{REPOSITORY}/immutable-releases").get("enabled") is True, "Enable immutable releases before publication")
    tag = "sha256-" + review["package"]["sha256"]
    result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases?per_page=100", "--paginate", "--slurp"],
                            capture_output=True, text=True, check=True)
    existing = [item for page in json.loads(result.stdout) for item in page if item["tag_name"] == tag]
    require(not existing, "Release already exists; inspect it manually. No assets or drafts are overwritten")
    refs = gh_json(f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}")
    require(not any(item["ref"] == f"refs/tags/{tag}" for item in refs), "Checksum tag already exists; manual recovery required")
    names = [review["package"]["filename"], review["package"]["filename"] + ".signature", "review.json"]
    subprocess.run(["gh", "release", "create", tag, *[str(artifacts / name) for name in names],
                    "--repo", REPOSITORY, "--draft", "--title", f"Maslow Hub {review['version']}",
                    "--notes", "\n".join(review["notes"]) + f"\n\nSHA-256: {review['package']['sha256']}"], check=True)
    subprocess.run(["gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false"], check=True)
    published = gh_json(f"repos/{REPOSITORY}/releases/tags/{tag}")
    require(published.get("draft") is False and published.get("immutable") is True, "Published release is not immutable")
    for name in names:
        verify_anonymous(f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}", artifacts / name)


def prepare(package: Path, review_path: Path, channel: Path, public_key: Path,
            private_key: Path, output: Path, publish: bool = False, now: dt.datetime | None = None) -> dict:
    require(not output.exists(), "Output already exists; preserve previous evidence and choose a new directory")
    check_private_key(private_key)
    review = load_review(review_path, package)
    manifest, catalog = next_metadata(channel, public_key, review, now or dt.datetime.now(dt.timezone.utc))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".hub-publication-", dir=output.parent) as temporary:
        stage = Path(temporary)
        artifacts = stage / "artifacts"
        artifacts.mkdir()
        target = artifacts / package.name
        shutil.copyfile(package, target)
        require(digest(target) == review["package"]["sha256"], "Candidate changed while staging")
        signature = artifacts / (package.name + ".signature")
        sign(private_key, target, signature)
        require(verify(public_key, target, signature), "Signing key does not match pinned public key")
        write_atomic(artifacts, "review.json", canonical(review))
        # Check all signatures before any external write; expose output only after delivery succeeds.
        site = stage / "channel"
        site.mkdir()
        for name, value in (("manifest.json", manifest), ("catalog.json", catalog)):
            path = write_atomic(site, name, canonical(value))
            signature = site / (name + ".sig")
            sign(private_key, path, signature)
            require(verify(public_key, path, signature), f"New {name} signature is invalid")
        if publish:
            publish_assets(artifacts, review)
        shutil.copytree(stage, output)
    return {"published": publish, "channel": "staging", "sequence": manifest["sequence"],
            "version": review["version"], "sha256": review["package"]["sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "review", "channel-dir", "public-key", "private-key", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.package, args.review, args.channel_dir, args.public_key,
                                 args.private_key, args.output_dir, args.publish), sort_keys=True))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Candidate publication rejected: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
