#!/usr/bin/python3
"""Local Hub release workstation: prepare, verify, publish and renew without GitHub Actions.

A thin front end over the reviewed tools beside it (build-candidate, publish-candidate,
renew/renew-channel, channel-data, verify-delivery). It never creates keys. The encrypted
private key stays in the signing directory and OpenSSL asks for its passphrase on the
terminal; the passphrase is never read, stored or passed as an argument by this tool.

Machine-specific paths live in the workstation configuration, not in source:
  $XDG_CONFIG_HOME/maslow-release/workstation.json (default ~/.config/...)

Publication is a fast-forward push of a data-only commit to the `signed-staging` branch
that GitHub Pages serves. A concurrent change from another workstation makes the push
fail; nothing is ever force-pushed, sequences only increase and released assets are
never overwritten.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = "letsgomaslow/maslow-releases"
DATA_BRANCH = "signed-staging"
PAGES_URL = "https://letsgomaslow.github.io/maslow-releases/hub/staging"
TRUST_SHA256 = "daacaa5aac138710a3950097b29a05abd3f69c9a8efad512321c45f3103d1ee4"
ARCH_IMAGE = "archlinux@sha256:996c3a1d6b0d87b01242f6fcd8cfa3ad3eece1a67ab5c8f108e20af1d7b97bdd"
CHANNEL_FILES = ("manifest.json", "manifest.json.sig", "catalog.json", "catalog.json.sig")
PRIVATE_KEY = "release-key.pem"
PUBLIC_KEY = "release.pem"
TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent


class ReleaseError(Exception):
    pass


def load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def utc_stamp(now: dt.datetime | None = None) -> str:
    return (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and result.returncode:
        raise ReleaseError(f"git {' '.join(args[:2])} failed: {(result.stderr or result.stdout).strip()[-300:]}")
    return result.stdout.strip()


def config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "maslow-release" / "workstation.json"


class Workstation:
    """Holds the machine-specific configuration and the side-effecting operations.

    Network and GitHub calls are methods so tests can replace them with local fakes.
    """

    trust_sha256 = TRUST_SHA256

    def __init__(self, config: dict, root: Path = ROOT):
        self.root = root
        self.hub = Path(config["hubCheckout"])
        self.recipe = Path(config["recipeCheckout"])
        self.signing = Path(config["signingDir"])
        self.work = Path(config["workDir"])
        self.arch_image = config.get("archImage", ARCH_IMAGE)
        self.remote = config.get("remote", "origin")
        self.pages_url = config.get("pagesUrl", PAGES_URL)

    @classmethod
    def from_file(cls, path: Path) -> "Workstation":
        if not path.is_file():
            raise ReleaseError(f"No workstation configuration at {path}. Run: local-release.py init")
        value = json.loads(path.read_text())
        required = {"schemaVersion", "hubCheckout", "recipeCheckout", "signingDir", "workDir"}
        if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not required <= set(value):
            raise ReleaseError(f"{path} must be schema 1 with {', '.join(sorted(required))}")
        for key in required - {"schemaVersion"}:
            if not Path(value[key]).is_absolute():
                raise ReleaseError(f"{key} must be an absolute path")
        return cls(value)

    # ---- keys -------------------------------------------------------------
    @property
    def private_key(self) -> Path:
        return self.signing / PRIVATE_KEY

    @property
    def public_key(self) -> Path:
        return self.signing / PUBLIC_KEY

    def trust_root(self) -> Path:
        """The pinned public key in this checkout, after checking its fingerprint. Needs no private key."""
        path = self.root / "bootstrap/release.pem"
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
                             capture_output=True, check=True).stdout
        if hashlib.sha256(der).hexdigest() != self.trust_sha256:
            raise ReleaseError("Public key fingerprint does not match the pinned release trust root")
        return path

    def check_public_key(self) -> None:
        """The workstation's public key must be the pinned trust root shipped to every Hub."""
        if not self.public_key.is_file():
            raise ReleaseError(f"Missing {self.public_key}")
        if self.public_key.read_bytes() != self.trust_root().read_bytes():
            raise ReleaseError("Public key differs from bootstrap/release.pem in this checkout")

    def check_signing_files(self) -> None:
        mode = self.signing.stat().st_mode & 0o777 if self.signing.is_dir() else None
        if mode != 0o700 or self.signing.stat().st_uid != os.getuid():
            raise ReleaseError(f"{self.signing} must be a directory you own with permissions 700")
        for path in (self.private_key, self.public_key):
            if path.is_symlink() or not path.is_file():
                raise ReleaseError(f"Missing regular file {path}")
            if path.stat().st_mode & 0o777 != 0o600 or path.stat().st_uid != os.getuid():
                raise ReleaseError(f"{path} must be owned by you with permissions 600")
        if not self.private_key.read_text(errors="replace").startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            raise ReleaseError(f"{self.private_key} must be the passphrase-encrypted release key")
        self.check_public_key()

    def private_fingerprint(self) -> str:
        """Derive the public fingerprint from the private key. OpenSSL prompts for the passphrase."""
        result = subprocess.run(["openssl", "pkey", "-in", str(self.private_key), "-pubout", "-outform", "DER"],
                                stdout=subprocess.PIPE)
        if result.returncode:
            raise ReleaseError("OpenSSL could not unlock the private key. If it asked for the passphrase, it was not accepted; "
                               "if it did not, run this in a real terminal window")
        return hashlib.sha256(result.stdout).hexdigest()

    # ---- tools checkout -----------------------------------------------------
    def tools_commit(self, require_clean: bool = True) -> str:
        if require_clean and git(self.root, "status", "--porcelain", "--untracked-files=no"):
            raise ReleaseError(f"Release tools checkout {self.root} has uncommitted changes; signing runs only reviewed code")
        return git(self.root, "rev-parse", "HEAD")

    # ---- published channel ----------------------------------------------------
    def fetch_channel(self, destination: Path) -> str:
        """Fetch the data branch and extract its four channel files. Returns the base commit."""
        git(self.root, "fetch", "--quiet", "--no-tags", self.remote,
            f"+refs/heads/{DATA_BRANCH}:refs/remotes/{self.remote}/{DATA_BRANCH}")
        base = git(self.root, "rev-parse", f"refs/remotes/{self.remote}/{DATA_BRANCH}^{{commit}}")
        with contextlib.chdir(self.root):
            load_tool("channel-data").extract(base, destination)
        return base

    def commit_channel(self, base: str, signed: Path) -> str:
        with contextlib.chdir(self.root):
            return load_tool("channel-data").commit(base, signed)

    def signing_environment(self) -> dict:
        """Environment for signing. OpenSSL must prompt on the terminal, so any passphrase variable is removed."""
        return {key: value for key, value in os.environ.items() if key != "HUB_SIGNING_PASSPHRASE"}

    def remote_tip(self) -> str:
        line = git(self.root, "ls-remote", self.remote, f"refs/heads/{DATA_BRANCH}")
        if not line:
            raise ReleaseError(f"Remote branch {DATA_BRANCH} does not exist")
        return line.split()[0]

    def served_files(self, destination: Path) -> None:
        delivery = load_tool("verify-delivery")
        destination.mkdir(parents=True, exist_ok=False)
        for name in CHANNEL_FILES:
            delivery.download(f"{self.pages_url}/{name}?local-release={utc_stamp()}-{os.getpid()}", destination / name, 30)

    def push(self, commit: str, base: str) -> None:
        parents = git(self.root, "rev-list", "--parents", "-n", "1", commit).split()[1:]
        if parents != [base]:
            raise ReleaseError("Refusing to push: the new commit must directly extend the fetched channel")
        if self.remote_tip() != base:
            raise ReleaseError("Another workstation published while this run was signing. Nothing was pushed; run again")
        # A normal push is a fast-forward-only compare-and-swap. Never force.
        result = subprocess.run(["git", "-C", str(self.root), "push", "--quiet", self.remote,
                                 f"{commit}:refs/heads/{DATA_BRANCH}"], capture_output=True, text=True)
        if result.returncode:
            raise ReleaseError("Push rejected (a concurrent publication or branch protection). Nothing was forced; "
                               f"fetch and run again. Git said: {result.stderr.strip()[-300:]}")

    def request_pages_build(self) -> None:
        subprocess.run(["gh", "api", "-X", "POST", f"repos/{REPOSITORY}/pages/builds"], capture_output=True, check=True)

    def confirm_delivery(self, channel: Path) -> None:
        load_tool("verify-delivery").confirm_delivery(channel, self.trust_root(), self.pages_url)

    def publish_assets(self, artifacts: Path, review: dict) -> None:
        load_tool("publish-candidate").publish_assets(artifacts, review)

    # ---- release recovery (used by `resume`) ----------------------------------------
    def release_state(self, tag: str) -> dict | None:
        """The GitHub release for a checksum tag, drafts included (authenticated read)."""
        result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases?per_page=100", "--paginate", "--slurp"],
                                capture_output=True, text=True, check=True)
        found = [item for page in json.loads(result.stdout) for item in page if item["tag_name"] == tag]
        if len(found) > 1:
            raise ReleaseError(f"More than one release uses {tag}; inspect them manually")
        if not found:
            return None
        return {"id": found[0]["id"], "draft": found[0]["draft"], "immutable": found[0].get("immutable") is True,
                "assets": {asset["name"]: asset["state"] for asset in found[0]["assets"]}}

    def download_release_asset(self, tag: str, name: str, destination: Path) -> None:
        subprocess.run(["gh", "release", "download", tag, "--repo", REPOSITORY, "--pattern", name, "--dir", str(destination)],
                       capture_output=True, check=True)

    def upload_release_asset(self, tag: str, path: Path) -> None:
        # No --clobber: an existing asset is never replaced.
        subprocess.run(["gh", "release", "upload", tag, str(path), "--repo", REPOSITORY], capture_output=True, check=True)

    def publish_draft(self, tag: str) -> None:
        subprocess.run(["gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false"],
                       capture_output=True, check=True)

    def verify_public_asset(self, tag: str, path: Path) -> None:
        load_tool("publish-candidate").verify_anonymous(f"https://github.com/{REPOSITORY}/releases/download/{tag}/{path.name}", path)

    # ---- locking and records ------------------------------------------------
    @contextlib.contextmanager
    def lock(self):
        self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.work / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ReleaseError("Another local release operation is running") from error
            yield
        finally:
            os.close(descriptor)

    def run_dir(self, operation: str) -> Path:
        path = self.work / "runs" / f"{utc_stamp()}-{operation}"
        path.mkdir(parents=True, mode=0o700)
        return path


# ---- shared checks ------------------------------------------------------------

def read_channel(channel: Path, public_key: Path) -> tuple[dict, dict]:
    """Verify both signed pairs against the pinned key. Expired metadata is allowed here."""
    values = []
    for name in ("manifest.json", "catalog.json"):
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature",
                                 str(channel / f"{name}.sig"), str(channel / name)], capture_output=True)
        if result.returncode:
            raise ReleaseError(f"Published {name} signature does not verify against the pinned key")
        value = json.loads((channel / name).read_text())
        if value.get("schemaVersion") != 1 or value.get("channel") != "staging" or type(value.get("sequence")) is not int:
            raise ReleaseError(f"Published {name} has unsupported metadata")
        values.append(value)
    manifest, catalog = values
    if catalog.get("kind") != "catalog" or not manifest.get("releases"):
        raise ReleaseError("Published channel is missing releases or catalog items")
    return manifest, catalog


def require_served(station: Workstation, channel: Path, scratch: Path) -> None:
    """Refuse to sign unless Pages serves exactly the fetched branch tip.

    A difference means another workstation's publication is still deploying (or the site
    is not serving the data branch); signing on top of either would be a race.
    """
    served = scratch / "served"
    station.served_files(served)
    different = [name for name in CHANNEL_FILES if (served / name).read_bytes() != (channel / name).read_bytes()]
    if different:
        raise ReleaseError("Pages is not serving the latest signed-staging commit "
                           f"({', '.join(different)} differ). Wait for the deployment to finish or investigate; nothing was signed")


def describe(manifest: dict, catalog: dict) -> dict:
    expires = dt.datetime.fromisoformat(manifest["expiresAt"].replace("Z", "+00:00"))
    left = expires - dt.datetime.now(dt.timezone.utc)
    return {"manifestSequence": manifest["sequence"], "catalogSequence": catalog["sequence"],
            "expiresAt": manifest["expiresAt"], "daysLeft": round(left.total_seconds() / 86400, 1),
            "releases": [item["version"] for item in manifest["releases"]], "catalogItems": len(catalog["items"])}


def file_hashes(directory: Path) -> dict:
    return {name: sha256(directory / name) for name in CHANNEL_FILES}


def write_record(run: Path, record: dict) -> None:
    (run / "record.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def preserved_history(before: dict, after: dict) -> None:
    """Every previously published release must survive unchanged, in order."""
    old, new = before["releases"], after["releases"]
    if new[:len(old)] != old:
        raise ReleaseError("New metadata does not preserve every existing rollback release unchanged")
    if after["sequence"] <= before["sequence"]:
        raise ReleaseError("New metadata must have a higher sequence")


def promote(station: Workstation, run: Path, base: str, signed: Path, record: dict, push: bool) -> None:
    commit = station.commit_channel(base, signed)
    record.update(newCommit=commit, signedHashes=file_hashes(signed))
    if not push:
        record["published"] = False
        write_record(run, record)
        print(f"Signed locally and verified. Not published (--no-push). Evidence: {run}")
        return
    station.push(commit, base)
    record.update(published=True, pushedAt=utc_stamp())
    write_record(run, record)
    print(f"Pushed {commit[:12]} to {DATA_BRANCH}. Requesting a Pages build and waiting for anonymous delivery...")
    station.request_pages_build()
    station.confirm_delivery(signed)
    record["deliveryVerifiedAt"] = utc_stamp()
    write_record(run, record)


# ---- operations ---------------------------------------------------------------

def require_terminal(station: Workstation) -> None:
    """OpenSSL reads the passphrase from the controlling terminal; fail early and clearly without one."""
    if "HUB_SIGNING_PASSPHRASE" in station.signing_environment():
        return
    try:
        with open("/dev/tty"):
            pass
    except OSError as error:
        raise ReleaseError("This step asks for the key passphrase and needs a real terminal window. "
                           "Open a terminal (not an embedded command prompt) and run it there") from error


def op_renew(station: Workstation, days: int, push: bool) -> dict:
    station.check_signing_files()
    require_terminal(station)
    tools = station.tools_commit()
    with station.lock():
        run = station.run_dir("renew")
        published = run / "published"
        base = station.fetch_channel(published)
        manifest, catalog = read_channel(published, station.public_key)
        require_served(station, published, run)
        record = {"operation": "renew", "toolsCommit": tools, "host": socket.gethostname(), "base": base,
                  "before": describe(manifest, catalog), "baseHashes": file_hashes(published)}
        write_record(run, record)
        print(f"Renewing sequence {manifest['sequence']} (expires {manifest['expiresAt']}). "
              "OpenSSL will ask for the release key passphrase twice.")
        renewed = run / "renewed"
        result = subprocess.run([sys.executable, str(TOOLS / "renew/renew-channel.py"), "--channel-dir", str(published),
                                 "--private-key", str(station.private_key), "--public-key", str(station.public_key),
                                 "--output-dir", str(renewed), "--days", str(days)], env=station.signing_environment())
        if result.returncode:
            raise ReleaseError("Renewal signing failed; nothing was published")
        new_manifest, new_catalog = read_channel(renewed, station.public_key)
        preserved_history(manifest, new_manifest)
        record["after"] = describe(new_manifest, new_catalog)
        promote(station, run, base, renewed, record, push)
        return record


def op_verify(station: Workstation, candidate: Path | None) -> dict:
    trust = station.trust_root()
    with tempfile.TemporaryDirectory(prefix="hub-verify-") as temporary:
        scratch = Path(temporary)
        channel = scratch / "published"
        base = station.fetch_channel(channel)
        manifest, catalog = read_channel(channel, trust)
        report = {"base": base, "channel": describe(manifest, catalog)}
        try:
            require_served(station, channel, scratch)
            report["pagesServesTip"] = True
        except ReleaseError as error:
            report["pagesServesTip"] = False
            report["pagesProblem"] = str(error)
        if candidate:
            publisher = load_tool("publish-candidate")
            package = single_package(candidate)
            review = publisher.load_review(candidate / "review.json", package)
            next_manifest, next_catalog = publisher.next_metadata(channel, trust, review,
                                                                  dt.datetime.now(dt.timezone.utc))
            preserved_history(manifest, next_manifest)
            report["candidate"] = {"version": review["version"], "package": review["package"],
                                   "reviewSha256": sha256(candidate / "review.json"),
                                   "source": review["source"]["commit"], "recipe": review["recipe"]["commit"],
                                   "wouldPublishSequence": next_manifest["sequence"],
                                   "rollbackReleasesKept": [item["version"] for item in manifest["releases"]]}
        return report


def single_package(candidate: Path) -> Path:
    packages = sorted(candidate.glob("maslow-hub-*-1-any.pkg.tar.zst"))
    if len(packages) != 1:
        raise ReleaseError(f"{candidate} must contain exactly one maslow-hub package")
    return packages[0]


@contextlib.contextmanager
def exact_worktree(checkout: Path, commit: str, work: Path, label: str):
    """A detached, clean worktree at the reviewed commit; the developer checkout is untouched."""
    if git(checkout, "cat-file", "-t", f"{commit}^{{commit}}", check=False) != "commit":
        git(checkout, "fetch", "--quiet", "origin", commit)
    path = work / "worktrees" / f"{label}-{commit[:12]}-{utc_stamp()}"
    path.parent.mkdir(parents=True, exist_ok=True)
    git(checkout, "worktree", "add", "--quiet", "--detach", str(path), commit)
    try:
        yield path
    finally:
        git(checkout, "worktree", "remove", "--force", str(path), check=False)


def op_prepare(station: Workstation, source_sha: str, recipe_sha: str, notes: list[str]) -> dict:
    """Build a review-only candidate. No signing key is touched."""
    trust = station.trust_root()
    tools = station.tools_commit()
    builder = load_tool("build-candidate")
    with station.lock():
        run = station.run_dir("prepare")
        published = run / "published"
        base = station.fetch_channel(published)
        read_channel(published, trust)
        notes_file = run / "notes.json"
        notes_file.write_text(json.dumps(notes))
        candidate = run / "candidate"
        with exact_worktree(station.hub, source_sha, station.work, "hub") as source, \
                exact_worktree(station.recipe, recipe_sha, station.work, "recipe") as recipe:
            args = argparse.Namespace(source_dir=source, source_sha=source_sha, recipe_dir=recipe, recipe_sha=recipe_sha,
                                      channel_dir=published, public_key=trust, notes_file=notes_file,
                                      output_dir=candidate, arch_image=station.arch_image)
            try:
                builder.build(args)
            except (builder.BuildError, subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
                raise ReleaseError(f"Candidate build failed: {error}") from error
        package = single_package(candidate)
        record = {"operation": "prepare", "toolsCommit": tools, "host": socket.gethostname(),
                  "machine": platform.machine(), "channelBase": base, "candidate": str(candidate),
                  "reviewSha256": sha256(candidate / "review.json"), "packageSha256": sha256(package),
                  "packageSize": package.stat().st_size, "review": json.loads((candidate / "review.json").read_text())}
        write_record(run, record)
        return record


def op_publish(station: Workstation, candidate: Path, approved_review: str, push: bool) -> dict:
    """Sign and publish an approved candidate. Requires the exact reviewed digest."""
    station.check_signing_files()
    require_terminal(station)
    tools = station.tools_commit()
    if sha256(candidate / "review.json") != approved_review:
        raise ReleaseError("--approve does not match this candidate's review.json; review the exact candidate first")
    publisher = load_tool("publish-candidate")
    package = single_package(candidate)
    review = publisher.load_review(candidate / "review.json", package)
    with station.lock():
        run = station.run_dir("publish")
        published = run / "published"
        base = station.fetch_channel(published)
        manifest, catalog = read_channel(published, station.public_key)
        require_served(station, published, run)
        if push and station.remote_tip() != base:
            raise ReleaseError("Another workstation published after the fetch; nothing was signed")
        record = {"operation": "publish", "toolsCommit": tools, "host": socket.gethostname(), "base": base,
                  "before": describe(manifest, catalog), "reviewSha256": approved_review,
                  "version": review["version"], "package": review["package"]}
        write_record(run, record)
        print("OpenSSL will ask for the release key passphrase three times (package, manifest, catalog).")
        output = run / "release"
        # Sign into the run folder first and keep it, so an interrupted upload can be finished with
        # `resume` instead of signing again.
        with _environment(station.signing_environment()):
            try:
                publisher.prepare(package, candidate / "review.json", published, station.public_key,
                                  station.private_key, output, publish=False)
            except (ValueError, OSError, subprocess.CalledProcessError) as error:
                raise ReleaseError(f"Publication rejected: {error}") from error
        if push:
            try:
                station.publish_assets(output / "artifacts", review)
            except (ValueError, OSError, subprocess.CalledProcessError) as error:
                raise ReleaseError(f"Upload stopped ({error}). Everything is signed; finish with: maslow-release resume") from error
        new_manifest, new_catalog = read_channel(output / "channel", station.public_key)
        preserved_history(manifest, new_manifest)
        record["after"] = describe(new_manifest, new_catalog)
        promote(station, run, base, output / "channel", record, push)
        return record


def op_resume(station: Workstation, run: Path | None = None) -> dict:
    """Finish an interrupted publish from its already-signed files. Needs no passphrase.

    Everything is re-verified first; existing release assets are compared, never replaced; the
    channel is promoted only if nobody has published since the run fetched it.
    """
    station.check_public_key()
    trust = station.trust_root()
    with station.lock():
        if run is None:
            unfinished = [path for path in sorted((station.work / "runs").glob("*-publish"), reverse=True)
                          if not json.loads((path / "record.json").read_text()).get("deliveryVerifiedAt")]
            if not unfinished:
                raise ReleaseError("There is no unfinished publication to resume")
            run = unfinished[0]
        record = json.loads((run / "record.json").read_text())
        staged = [run / "release"] if (run / "release/channel").is_dir() else [path for path in run.glob(".hub-publication-*") if path.is_dir()]
        if len(staged) != 1:
            raise ReleaseError(f"{run} has no signed publication files; run publish again")
        artifacts, channel = staged[0] / "artifacts", staged[0] / "channel"
        package = artifacts / record["package"]["filename"]
        if sha256(package) != record["package"]["sha256"] or package.stat().st_size != record["package"]["size"]:
            raise ReleaseError("The staged package does not match the approved checksum")
        for path, signature in ((package, Path(f"{package}.signature")), (channel / "manifest.json", channel / "manifest.json.sig"),
                                (channel / "catalog.json", channel / "catalog.json.sig")):
            result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(trust), "-signature", str(signature), str(path)],
                                    capture_output=True)
            if result.returncode:
                raise ReleaseError(f"{path.name} does not verify against the pinned key")
        manifest, catalog = read_channel(channel, trust)
        preserved_history(json.loads((run / "published/manifest.json").read_text()), manifest)
        if manifest["releases"][-1]["sha256"] != record["package"]["sha256"]:
            raise ReleaseError("The signed channel does not point at the approved package")
        if station.remote_tip() != record["base"]:
            raise ReleaseError("Another publication happened after this run fetched the channel; "
                               "its signed files are now stale. Run publish again")
        tag = "sha256-" + record["package"]["sha256"]
        state = station.release_state(tag)
        if state is None:
            raise ReleaseError("No GitHub release exists for this run yet; run publish again")
        names = [package.name, package.name + ".signature", "review.json"]
        steps = []
        if state["draft"]:
            for name in names:
                if name in state["assets"]:
                    if state["assets"][name] != "uploaded":
                        raise ReleaseError(f"{name} is only partly uploaded; delete that asset from the draft in GitHub, then resume")
                    with tempfile.TemporaryDirectory(prefix="hub-resume-") as temporary:
                        station.download_release_asset(tag, name, Path(temporary))
                        if (Path(temporary) / name).read_bytes() != (artifacts / name).read_bytes():
                            raise ReleaseError(f"The draft's {name} differs from the signed file; inspect the draft manually")
                    steps.append(f"{name}: already uploaded and identical")
                else:
                    print(f"Uploading {name} (the package takes several minutes)...", flush=True)
                    station.upload_release_asset(tag, artifacts / name)
                    steps.append(f"{name}: uploaded")
            station.publish_draft(tag)
            state = station.release_state(tag)
            steps.append("release published")
        if not state or state["draft"] or not state["immutable"]:
            raise ReleaseError("The release is not public and immutable; inspect it in GitHub")
        for name in names:
            station.verify_public_asset(tag, artifacts / name)
        steps.append("anonymous downloads match")
        record.update(after=describe(manifest, catalog), resumedAt=utc_stamp(), resumeSteps=steps)
        promote(station, run, record["base"], channel, record, push=True)
        return record


@contextlib.contextmanager
def _environment(values: dict):
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def op_doctor(station: Workstation) -> dict:
    checks = {}

    def check(name, function):
        try:
            value = function()
            checks[name] = "ok" if value in (None, True) else value
        except (ReleaseError, OSError, subprocess.SubprocessError, ValueError) as error:
            checks[name] = f"FAILED: {error}"

    for tool in ("git", "openssl", "bsdtar", "zstd", "curl", "docker", "gh"):
        check(f"command {tool}", lambda tool=tool: shutil.which(tool) is not None or (_ for _ in ()).throw(ReleaseError("not installed")))
    check("python >= 3.12", lambda: sys.version_info >= (3, 12) or (_ for _ in ()).throw(ReleaseError(sys.version)))
    check("tools checkout clean", lambda: station.tools_commit()[:12])
    check("signing files", station.check_signing_files)
    check("hub checkout", lambda: git(station.hub, "rev-parse", "--short", "HEAD"))
    check("recipe checkout", lambda: git(station.recipe, "rev-parse", "--short", "HEAD"))
    check("docker usable", lambda: subprocess.run(["docker", "info"], capture_output=True, check=True) and None)
    check("github auth", lambda: subprocess.run(["gh", "auth", "status"], capture_output=True, check=True) and None)
    check("pages source", lambda: _pages_source())
    check("immutable releases", lambda: _immutable_releases())
    check("published channel", lambda: op_verify(station, None)["channel"])
    return checks


def _pages_source():
    value = json.loads(subprocess.run(["gh", "api", f"repos/{REPOSITORY}/pages"], capture_output=True, text=True, check=True).stdout)
    branch = value.get("source", {}).get("branch")
    if branch != DATA_BRANCH:
        raise ReleaseError(f"Pages serves {branch}, not {DATA_BRANCH}")


def _immutable_releases():
    value = json.loads(subprocess.run(["gh", "api", f"repos/{REPOSITORY}/immutable-releases"], capture_output=True, text=True, check=True).stdout)
    if value.get("enabled") is not True:
        raise ReleaseError("immutable releases are not enabled (required before publishing a new version)")


def op_init(hub: Path, recipe: Path, signing: Path, work: Path) -> Path:
    path = config_path()
    if path.exists():
        raise ReleaseError(f"{path} already exists; edit it instead of overwriting")
    value = {"schemaVersion": 1, "hubCheckout": str(hub.resolve()), "recipeCheckout": str(recipe.resolve()),
             "signingDir": str(signing.expanduser()), "workDir": str(work.expanduser())}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=None, help="workstation configuration (default: %(default)s)")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="write the local workstation configuration")
    init.add_argument("--hub-checkout", type=Path, required=True)
    init.add_argument("--recipe-checkout", type=Path, required=True)
    init.add_argument("--signing-dir", type=Path, default=Path("~/.config/maslow-release-signing"))
    init.add_argument("--work-dir", type=Path, default=Path("~/.local/share/maslow-release"))
    commands.add_parser("doctor", help="check tools, keys, checkouts, GitHub and the published channel")
    commands.add_parser("fingerprint", help="prove the private key matches the pinned trust root (asks for the passphrase)")
    verify = commands.add_parser("verify", help="verify the published channel and optionally a candidate (no key)")
    verify.add_argument("--candidate", type=Path)
    prepare = commands.add_parser("prepare", help="build a review-only candidate from exact commits (no key)")
    prepare.add_argument("--source-sha", required=True)
    prepare.add_argument("--recipe-sha", required=True)
    prepare.add_argument("--note", action="append", required=True, help="release note; repeat for several")
    publish = commands.add_parser("publish", help="sign and publish an approved candidate")
    publish.add_argument("--candidate", type=Path, required=True)
    publish.add_argument("--approve", required=True, help="SHA-256 of the reviewed candidate review.json")
    publish.add_argument("--no-push", action="store_true", help="sign and verify locally only; publish nothing")
    resume = commands.add_parser("resume", help="finish an interrupted publish from its signed files (no passphrase)")
    resume.add_argument("--run", type=Path, help="a specific publish run directory (default: the latest unfinished)")
    renew = commands.add_parser("renew", help="re-sign the published channel with a fresh validity window")
    renew.add_argument("--days", type=int, default=30)
    renew.add_argument("--no-push", action="store_true", help="sign and verify locally only; publish nothing")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            print(f"Wrote {op_init(args.hub_checkout, args.recipe_checkout, args.signing_dir, args.work_dir)}")
            return 0
        station = Workstation.from_file(args.config or config_path())
        if args.command == "doctor":
            result = op_doctor(station)
            print(json.dumps(result, indent=2))
            return 0 if all(not str(value).startswith("FAILED") for value in result.values()) else 1
        if args.command == "fingerprint":
            station.check_signing_files()
            require_terminal(station)
            print("OpenSSL will ask for the release key passphrase.")
            found = station.private_fingerprint()
            print(f"Private-key-derived public fingerprint: {found}")
            print("MATCHES the pinned trust root." if found == TRUST_SHA256 else "DOES NOT MATCH the pinned trust root.")
            return 0 if found == TRUST_SHA256 else 1
        if args.command == "verify":
            print(json.dumps(op_verify(station, args.candidate), indent=2))
            return 0
        if args.command == "prepare":
            print(json.dumps(op_prepare(station, args.source_sha, args.recipe_sha, args.note), indent=2))
            return 0
        if args.command == "publish":
            print(json.dumps(op_publish(station, args.candidate, args.approve, not args.no_push), indent=2))
            return 0
        if args.command == "resume":
            record = op_resume(station, args.run)
            print(json.dumps({key: record.get(key) for key in ("version", "newCommit", "resumeSteps", "deliveryVerifiedAt", "after")}, indent=2))
            print(f"Done. Hub {record.get('version')} is live on the staging channel.")
            return 0
        if args.command == "renew":
            print(json.dumps(op_renew(station, args.days, not args.no_push), indent=2))
            return 0
    except ReleaseError as error:
        parser.exit(1, f"local-release: {error}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
