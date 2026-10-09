#!/usr/bin/python3
"""Build a review-only Hub candidate from exact source and recipe commits.

No signing credentials are consumed. The optional Voice bundle is retained
byte-for-byte from the authenticated 0.3.2 package, never rebuilt here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit


TRUST_SHA256 = "daacaa5aac138710a3950097b29a05abd3f69c9a8efad512321c45f3103d1ee4"
VOICE_SOURCE_SHA256 = "7cbd9494df66526834a73bc390179c596f18db2e8125694c5b5ba24c1d9ed1ab"
VOICE_PREFIX = "usr/share/maslow-hub/voice/"
MAX_PACKAGE = 1024 ** 3


class BuildError(Exception):
    pass


def run(argv, **kwargs):
    # Public Actions logs must not receive private test tracebacks or source.
    # Failures report the command/status only; captured output stays ephemeral.
    if "capture_output" not in kwargs and "stdout" not in kwargs:
        kwargs["capture_output"] = True
    elif "stdout" in kwargs and "stderr" not in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(argv, check=True, timeout=kwargs.pop("timeout", 120), **kwargs)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_signature(public_key, payload, signature):
    result = run(["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"], capture_output=True)
    if hashlib.sha256(result.stdout).hexdigest() != TRUST_SHA256:
        raise BuildError("public key does not match the pinned release fingerprint")
    run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(payload)], capture_output=True)


def donor_record(channel_dir, public_key):
    manifest = channel_dir / "manifest.json"
    verify_signature(public_key, manifest, channel_dir / "manifest.json.sig")
    value = json.loads(manifest.read_text())
    records = [item for item in value["releases"] if item["version"] == "0.3.2"]
    if value.get("channel") != "staging" or len(records) != 1:
        raise BuildError("signed staging manifest must contain one 0.3.2 Voice donor")
    record = records[0]
    if record["sha256"] != VOICE_SOURCE_SHA256 or type(record["packageSize"]) is not int or not 0 < record["packageSize"] <= MAX_PACKAGE:
        raise BuildError("Voice donor does not match the previously reviewed immutable package")
    base = f"https://github.com/letsgomaslow/maslow-releases/releases/download/sha256-{VOICE_SOURCE_SHA256}/maslow-hub-0.3.2-1-any.pkg.tar.zst"
    if record["packageUrl"] != base or record["signatureUrl"] != base + ".signature":
        raise BuildError("Voice donor URL is not the expected immutable public release")
    # Expiry controls update eligibility. This operation only recovers a pinned,
    # previously signed immutable payload; it does not install/promote metadata.
    return record


def download(url, output, limit):
    if urlsplit(url).scheme != "https":
        raise BuildError("downloads require HTTPS")
    run(["curl", "-q", "--fail", "--silent", "--show-error", "--location",
         "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15",
         "--max-time", "900", "--max-filesize", str(limit), "--output", str(output), url], timeout=910)


def export_checkout(checkout, sha, output, subpath=None):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BuildError("source and recipe revisions must be full lowercase commit SHAs")
    head = run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = run(["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True).stdout
    if head != sha or dirty:
        raise BuildError("checkout must be clean and at the exact requested revision")
    output.mkdir()
    with tempfile.TemporaryFile() as archive:
        command = ["git", "-C", str(checkout), "archive", sha]
        if subpath:
            command.append(subpath)
        run(command, stdout=archive)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as source:
            # Python 3.12+ data filtering prevents absolute/traversal paths and
            # escaping links. Git metadata and credential helpers are absent.
            source.extractall(output, filter="data")


def voice_files(package):
    """Read only regular Voice members; never extract arbitrary package paths."""
    files = {}
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(["zstd", "-dc", str(package)], stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                total = 0
                for member in archive:
                    raw = member.name
                    if raw.startswith("./"):
                        raw = raw[2:]
                    path = PurePosixPath(raw)
                    if path.is_absolute() or ".." in path.parts:
                        raise BuildError("unsafe path in package")
                    if not raw.startswith(VOICE_PREFIX):
                        continue
                    relative = raw[len(VOICE_PREFIX):]
                    if member.isdir():
                        continue
                    if not member.isfile() or not relative or relative in files:
                        raise BuildError("Voice payload must contain unique regular files")
                    if relative != "manifest.json" and not re.fullmatch(r"packages/[a-z0-9._-]+\.pkg\.tar\.zst", relative):
                        raise BuildError("unexpected Voice payload file")
                    total += member.size
                    if member.size > MAX_PACKAGE or total > 2 * MAX_PACKAGE:
                        raise BuildError("Voice payload exceeds its size bound")
                    stream = archive.extractfile(member)
                    files[relative] = stream.read()
            if process.wait(timeout=30):
                raise BuildError("cannot decompress package")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    if "manifest.json" not in files:
        raise BuildError("package is missing the Voice bundle")
    value = json.loads(files["manifest.json"])
    records = value.get("packages", [])
    if value.get("schemaVersion") != 1 or len(records) != 3 or {item["name"] for item in records} != {"maslow-voice", "hermes-agent", "maslow-voice-local"}:
        raise BuildError("Voice manifest must preserve all three reviewed packages")
    expected = {"manifest.json"}
    for record in records:
        filename = "packages/" + record["filename"]
        payload = files.get(filename, b"")
        if not payload or len(payload) != record["size"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
            raise BuildError("Voice package bytes do not match its bundle manifest")
        expected.add(filename)
    if set(files) != expected:
        raise BuildError("unexpected Voice bundle members")
    return files


def inside_container_checks():
    # Some updater-security tests deliberately exercise root-owned fixtures.
    # Their root process sees only a read-only export and its disposable copy,
    # with no network, credentials, Docker socket or candidate output mount.
    source = Path("/tmp/check-source")
    shutil.copytree("/inputs/source", source)
    run(["python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], cwd=source, timeout=900)
    run(["node", "tests/ui-contract-test.mjs"], cwd=source, timeout=300)


def archive_preflight(source, package, version):
    metadata = run(["bsdtar", "-xOf", str(package), ".PKGINFO"], text=True).stdout
    fields = {}
    for line in metadata.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            fields.setdefault(key, []).append(value)
    if fields.get("pkgname") != ["maslow-hub"] or fields.get("pkgver") != [f"{version}-1"] or fields.get("arch") != ["any"]:
        raise BuildError("built archive package identity does not match the candidate")
    if fields.get("conflict") or fields.get("replaces"):
        raise BuildError("Hub package may not conflict with or replace unrelated packages")
    # Execute the actual candidate helper's archive policy, without installing
    # the package or pretending the build container has target runtime deps.
    # A fresh subprocess imports helper.common relative to the exported source.
    code = """from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from helper.updater import Updater
root = Path('/tmp/archive-preflight')
updater = Updater(root / 'state', root / 'cache', root / 'channel.json', root / 'unused-public.pem')
updater._validate_archive_paths(Path(sys.argv[2]))
"""
    run(["python", "-c", code, str(source), str(package)], timeout=300)


def inside_container():
    work = Path("/tmp/build")
    work.mkdir()
    source = work / "source"
    shutil.copytree("/inputs/source", source)
    recipe = work / "recipe"
    shutil.copytree("/inputs/recipe/pkgbuilds/maslow-hub", recipe)
    bundle = work / "voice"
    original_voice = voice_files(Path("/inputs/donor.pkg.tar.zst"))
    for name, payload in original_voice.items():
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    run(["python", str(source / "release/check-voice-bundle.py"), str(bundle)])
    version = json.loads((source / "release/version.json").read_text())["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or json.loads((source / "ui/manifest.json").read_text())["version"] != version:
        raise BuildError("source and UI versions must match")
    env = dict(os.environ, MASLOW_HUB_SRC=str(source), MASLOW_VOICE_BUNDLE=str(bundle))
    run(["makepkg", "--nodeps", "--noconfirm"], cwd=recipe, env=env, timeout=1800)
    packages = list(recipe.glob("*.pkg.tar.zst"))
    if len(packages) != 1 or packages[0].name != f"maslow-hub-{version}-1-any.pkg.tar.zst":
        raise BuildError("recipe produced an unexpected package set")
    archive_preflight(source, packages[0], version)
    if voice_files(packages[0]) != original_voice:
        raise BuildError("built package did not preserve the exact Voice payload")
    output = Path("/output")
    shutil.copyfile(packages[0], output / packages[0].name)
    result = {"version": version, "voiceManifestSha256": hashlib.sha256(original_voice["manifest.json"]).hexdigest(),
              "checks": ["Hub Python tests", "Hub UI contract tests", "unchanged recipe build", "updater archive ownership policy", "package identity and conflict checks", "exact Voice payload comparison"]}
    (output / "build-result.json").write_text(json.dumps(result))


def build(args):
    if not re.fullmatch(r"archlinux@sha256:[0-9a-f]{64}", args.arch_image):
        raise BuildError("Arch build image must use an explicit sha256 digest")
    notes = json.loads(args.notes_file.read_text())
    if not isinstance(notes, list) or not notes or any(not isinstance(note, str) or not note.strip() for note in notes):
        raise BuildError("release notes must be a nonempty JSON array of strings")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise BuildError("candidate output directory must be empty")
    record = donor_record(args.channel_dir, args.public_key)
    with tempfile.TemporaryDirectory(prefix="hub-candidate-") as temporary:
        root = Path(temporary)
        inputs = root / "inputs"
        inputs.mkdir()
        export_checkout(args.source_dir, args.source_sha, inputs / "source")
        export_checkout(args.recipe_dir, args.recipe_sha, inputs / "recipe", "pkgbuilds/maslow-hub")
        donor = inputs / "donor.pkg.tar.zst"
        download(record["packageUrl"], donor, MAX_PACKAGE)
        signature = root / "donor.signature"
        download(record["signatureUrl"], signature, 16384)
        if donor.stat().st_size != record["packageSize"] or digest(donor) != VOICE_SOURCE_SHA256:
            raise BuildError("downloaded Voice donor size or checksum mismatch")
        verify_signature(args.public_key, donor, signature)
        # The public-only Docker build context contains neither source nor key.
        context = root / "docker"
        context.mkdir()
        (context / "Dockerfile").write_text(f"FROM {args.arch_image}\nRUN pacman -Syu --noconfirm base-devel python nodejs git openssl zstd && useradd -m builder\nUSER builder\n")
        image_file = root / "image-id"
        run(["docker", "build", "--platform", "linux/amd64", "--iidfile", str(image_file), str(context)], timeout=1800)
        run(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--user", "0",
             "--mount", f"type=bind,src={inputs / 'source'},dst=/inputs/source,readonly",
             "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/build-candidate.py,readonly",
             image_file.read_text().strip(), "python", "/build-candidate.py", "--inside-container-checks"], timeout=1500)
        staged = root / "output"
        staged.mkdir(mode=0o777)
        staged.chmod(0o777)
        run(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--mount", f"type=bind,src={inputs},dst=/inputs,readonly",
             "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/build-candidate.py,readonly",
             "--mount", f"type=bind,src={staged},dst=/output", image_file.read_text().strip(),
             "python", "/build-candidate.py", "--inside-container"], timeout=2400)
        result = json.loads((staged / "build-result.json").read_text())
        filename = f"maslow-hub-{result['version']}-1-any.pkg.tar.zst"
        package = staged / filename
        review = {"schemaVersion": 1, "version": result["version"],
                  "package": {"filename": filename, "sha256": digest(package), "size": package.stat().st_size},
                  "source": {"repository": "letsgomaslow/maslow-hub", "commit": args.source_sha},
                  "recipe": {"repository": "letsgomaslow/maslow-os-pkgs", "commit": args.recipe_sha},
                  "voice": {"sourceVersion": "0.3.2", "sourceSha256": VOICE_SOURCE_SHA256, "manifestSha256": result["voiceManifestSha256"]},
                  "buildImage": args.arch_image, "notes": notes}
        args.output_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package, args.output_dir / filename)
        (args.output_dir / "review.json").write_text(json.dumps(review, indent=2) + "\n")
        print(json.dumps(review, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--inside-container", action="store_true", help=argparse.SUPPRESS)
    modes.add_argument("--inside-container-checks", action="store_true", help=argparse.SUPPRESS)
    for name in ("source-dir", "recipe-dir", "channel-dir", "public-key", "notes-file", "output-dir"):
        parser.add_argument(f"--{name}", type=Path)
    for name in ("source-sha", "recipe-sha", "arch-image"):
        parser.add_argument(f"--{name}")
    args = parser.parse_args()
    try:
        if args.inside_container_checks:
            inside_container_checks()
        elif args.inside_container:
            inside_container()
        elif any(value is None for name, value in vars(args).items() if name not in {"inside_container", "inside_container_checks"}):
            parser.error("all build inputs are required")
        else:
            build(args)
    except (BuildError, subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
        parser.exit(1, f"Candidate build failed: {error}\n")


if __name__ == "__main__":
    main()
