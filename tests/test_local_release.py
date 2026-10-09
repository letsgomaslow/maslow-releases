"""Local workstation regression tests.

Everything here uses disposable keys, a local bare repository standing in for GitHub and a
local directory standing in for Pages. Nothing contacts GitHub, signs production data or
publishes anything. Passing these tests is not evidence of a real publication.
"""
import datetime as dt
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_release", ROOT / "tools/local-release.py")
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)

PASSPHRASE = "disposable-test-passphrase"
FILES = local.CHANNEL_FILES


def run(*argv, cwd=None):
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def canonical(value):
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


class FakeStation(local.Workstation):
    """Real git, OpenSSL and release tools; GitHub Pages and release assets are local fakes."""

    def __init__(self, config, root, site, remote_dir):
        super().__init__(config, root)
        self.site = site
        self.remote_dir = remote_dir
        self.published_assets = []
        # The disposable key stands in for the pinned production trust root.
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(self.public_key), "-outform", "DER"],
                             capture_output=True, check=True).stdout
        self.trust_sha256 = local.hashlib.sha256(der).hexdigest()

    def signing_environment(self):
        return dict(super().signing_environment(), HUB_SIGNING_PASSPHRASE=PASSPHRASE)

    def served_files(self, destination):
        shutil.copytree(self.site, destination)

    def request_pages_build(self):
        deploy(self.remote_dir, self.site)

    def confirm_delivery(self, channel):
        for name in FILES:
            if (self.site / name).read_bytes() != (channel / name).read_bytes():
                raise local.ReleaseError(f"{name} not delivered")

    def publish_assets(self, artifacts, review):
        self.published_assets.append((sorted(path.name for path in artifacts.iterdir()), review["version"]))


def deploy(remote_dir, site):
    """Simulate a Pages build of the data branch tip."""
    if site.exists():
        shutil.rmtree(site)
    site.mkdir()
    for name in FILES:
        (site / name).write_bytes(subprocess.run(["git", "-C", str(remote_dir), "show", f"signed-staging:hub/staging/{name}"],
                                                 capture_output=True, check=True).stdout)


class LocalReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.signing = self.base / "signing"
        self.signing.mkdir(mode=0o700)
        self.signing.chmod(0o700)
        plain = self.base / "plain.pem"
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(plain))
        run("openssl", "pkey", "-in", str(plain), "-aes256", "-passout", f"pass:{PASSPHRASE}",
            "-out", str(self.signing / "release-key.pem"))
        run("openssl", "pkey", "-in", str(plain), "-pubout", "-out", str(self.signing / "release.pem"))
        self.plain = plain
        for name in ("release-key.pem", "release.pem"):
            (self.signing / name).chmod(0o600)
        self.now = dt.datetime.now(dt.timezone.utc)
        self.releases = [self.release(version) for version in ("0.1.3", "0.2.0", "0.2.1", "0.3.0", "0.3.2")]
        self.remote = self.base / "remote.git"
        run("git", "init", "--quiet", "--bare", str(self.remote))
        self.root = self.base / "tools"
        run("git", "init", "--quiet", "-b", "main", str(self.root))
        for key, value in (("user.name", "Test"), ("user.email", "test@example.test")):
            run("git", "-C", str(self.root), "config", key, value)
        (self.root / "bootstrap").mkdir()
        shutil.copyfile(self.signing / "release.pem", self.root / "bootstrap/release.pem")
        self.write_channel(sequence=5, expires=self.now - dt.timedelta(days=15))
        run("git", "-C", str(self.root), "add", ".")
        run("git", "-C", str(self.root), "commit", "--quiet", "-m", "seed")
        run("git", "-C", str(self.root), "remote", "add", "origin", str(self.remote))
        run("git", "-C", str(self.root), "push", "--quiet", "origin", "HEAD:refs/heads/signed-staging")
        self.site = self.base / "site"
        deploy(self.remote, self.site)
        self.config = {"schemaVersion": 1, "hubCheckout": str(self.base / "hub"), "recipeCheckout": str(self.base / "recipe"),
                       "signingDir": str(self.signing), "workDir": str(self.base / "work")}
        self.station = FakeStation(self.config, self.root, self.site, self.remote)

    def release(self, version):
        digest = local.hashlib.sha256(version.encode()).hexdigest()
        url = f"https://github.com/letsgomaslow/maslow-releases/releases/download/sha256-{digest}/maslow-hub-{version}-1-any.pkg.tar.zst"
        return {"version": version, "sha256": digest, "packageSize": 100, "packageUrl": url, "signatureUrl": url + ".signature",
                "notes": [f"Release {version}"], "compatibility": {"architectures": ["x86_64"], "minHelperInterface": 1,
                                                                   "minRuntimeInterface": 1}}

    def write_channel(self, sequence, expires, directory=None):
        directory = directory or self.root / "hub/staging"
        directory.mkdir(parents=True, exist_ok=True)
        generated = expires - dt.timedelta(days=30)
        stamp = lambda value: value.isoformat().replace("+00:00", "Z")
        manifest = {"schemaVersion": 1, "channel": "staging", "sequence": sequence, "generatedAt": stamp(generated),
                    "expiresAt": stamp(expires), "releases": self.releases}
        catalog = {"schemaVersion": 1, "kind": "catalog", "channel": "staging", "sequence": 1, "generatedAt": stamp(generated),
                   "expiresAt": stamp(expires), "items": [{"id": "coding-tools", "name": "Coding tools", "status": "Tested"}]}
        for name, value in (("manifest.json", manifest), ("catalog.json", catalog)):
            (directory / name).write_bytes(canonical(value))
            run("openssl", "dgst", "-sha256", "-sign", str(self.plain), "-out", str(directory / f"{name}.sig"), str(directory / name))

    def tip(self):
        return run("git", "-C", str(self.remote), "rev-parse", "signed-staging")

    def remote_json(self, name, ref="signed-staging"):
        return json.loads(run("git", "-C", str(self.remote), "show", f"{ref}:hub/staging/{name}"))

    # ---- renewal -------------------------------------------------------------
    def test_expired_channel_renews_end_to_end_preserving_every_release(self):
        base = self.tip()
        record = local.op_renew(self.station, 30, push=True)
        tip = self.tip()
        self.assertNotEqual(base, tip)
        self.assertEqual(base, run("git", "-C", str(self.remote), "rev-parse", f"{tip}^"))
        changed = run("git", "-C", str(self.remote), "diff", "--name-only", base, tip).splitlines()
        self.assertEqual(sorted(f"hub/staging/{name}" for name in FILES), sorted(changed))
        manifest = self.remote_json("manifest.json")
        self.assertEqual(6, manifest["sequence"])
        self.assertEqual(self.releases, manifest["releases"])
        self.assertEqual(2, self.remote_json("catalog.json")["sequence"])
        expires = dt.datetime.fromisoformat(manifest["expiresAt"].replace("Z", "+00:00"))
        self.assertGreater(expires - dt.datetime.now(dt.timezone.utc), dt.timedelta(days=29))
        self.assertTrue(record["published"])
        self.assertIn("deliveryVerifiedAt", record)
        saved = json.loads(next((self.base / "work/runs").glob("*-renew/record.json")).read_text())
        self.assertEqual(record["newCommit"], saved["newCommit"])
        self.assertNotIn(PASSPHRASE, json.dumps(saved))

    def test_no_push_signs_and_verifies_without_publishing(self):
        base = self.tip()
        record = local.op_renew(self.station, 30, push=False)
        self.assertEqual(base, self.tip())
        self.assertFalse(record["published"])

    def test_tampered_published_metadata_is_rejected_before_signing(self):
        staged = self.root / "hub/staging/manifest.json"
        value = json.loads(staged.read_text())
        value["releases"] = value["releases"][:-1]
        staged.write_bytes(canonical(value))
        run("git", "-C", str(self.root), "commit", "--quiet", "-am", "tamper")
        run("git", "-C", str(self.root), "push", "--quiet", "origin", "HEAD:refs/heads/signed-staging")
        deploy(self.remote, self.site)
        base = self.tip()
        with self.assertRaisesRegex(local.ReleaseError, "signature does not verify"):
            local.op_renew(self.station, 30, push=True)
        self.assertEqual(base, self.tip())
        self.assertFalse(list((self.base / "work/runs").glob("*/renewed")))

    def test_pages_lag_refuses_before_any_signature(self):
        (self.site / "manifest.json").write_bytes(b"older deployment")
        base = self.tip()
        with self.assertRaisesRegex(local.ReleaseError, "not serving the latest"):
            local.op_renew(self.station, 30, push=True)
        self.assertEqual(base, self.tip())
        self.assertFalse(list((self.base / "work/runs").glob("*/renewed")))

    def competitor(self):
        """Another workstation publishes sequence 9 while this run is signing."""
        other = self.base / "other"
        run("git", "clone", "--quiet", "-b", "signed-staging", str(self.remote), str(other))
        for key, value in (("user.name", "Mac"), ("user.email", "mac@example.test")):
            run("git", "-C", str(other), "config", key, value)
        self.write_channel(sequence=9, expires=self.now + dt.timedelta(days=30), directory=other / "hub/staging")
        run("git", "-C", str(other), "commit", "--quiet", "-am", "Mac renewal")
        run("git", "-C", str(other), "push", "--quiet", "origin", "signed-staging")
        return self.tip()

    def test_concurrent_publication_is_detected_and_never_forced(self):
        station = self.station
        original = station.commit_channel
        winner = {}

        def racing_commit(base, signed):
            winner["tip"] = self.competitor()
            return original(base, signed)

        station.commit_channel = racing_commit
        with self.assertRaisesRegex(local.ReleaseError, "Another workstation published"):
            local.op_renew(station, 30, push=True)
        self.assertEqual(winner["tip"], self.tip())
        self.assertEqual(9, self.remote_json("manifest.json")["sequence"])

    def test_git_rejects_a_non_fast_forward_even_if_the_preflight_is_bypassed(self):
        station = self.station
        original = station.commit_channel
        racing = {}

        def racing_commit(base, signed):
            racing["base"] = base
            racing["tip"] = self.competitor()
            return original(base, signed)

        station.commit_channel = racing_commit
        station.remote_tip = lambda: racing["base"]
        with self.assertRaisesRegex(local.ReleaseError, "Push rejected"):
            local.op_renew(station, 30, push=True)
        self.assertEqual(racing["tip"], self.tip())

    def test_renewal_after_another_workstation_continues_its_sequence(self):
        self.competitor()
        deploy(self.remote, self.site)
        local.op_renew(self.station, 30, push=True)
        self.assertEqual(10, self.remote_json("manifest.json")["sequence"])

    # ---- keys and configuration ---------------------------------------------
    def test_signing_directory_and_key_permissions_are_enforced(self):
        self.signing.chmod(0o755)
        with self.assertRaisesRegex(local.ReleaseError, "permissions 700"):
            self.station.check_signing_files()
        self.signing.chmod(0o700)
        (self.signing / "release-key.pem").chmod(0o644)
        with self.assertRaisesRegex(local.ReleaseError, "permissions 600"):
            self.station.check_signing_files()
        (self.signing / "release-key.pem").chmod(0o600)
        shutil.copyfile(self.plain, self.signing / "release-key.pem")
        with self.assertRaisesRegex(local.ReleaseError, "passphrase-encrypted"):
            self.station.check_signing_files()

    def test_public_key_must_be_the_pinned_trust_root(self):
        self.station.trust_sha256 = "0" * 64
        with self.assertRaisesRegex(local.ReleaseError, "fingerprint does not match"):
            local.op_renew(self.station, 30, push=True)

    def test_wrong_private_key_cannot_produce_accepted_signatures(self):
        other = self.base / "other.pem"
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other))
        run("openssl", "pkey", "-in", str(other), "-aes256", "-passout", f"pass:{PASSPHRASE}", "-out", str(self.signing / "release-key.pem"))
        base = self.tip()
        with self.assertRaisesRegex(local.ReleaseError, "Renewal signing failed"):
            local.op_renew(self.station, 30, push=True)
        self.assertEqual(base, self.tip())

    def test_configuration_requires_absolute_machine_paths(self):
        path = self.base / "workstation.json"
        path.write_text(json.dumps(dict(self.config, workDir="relative/work")))
        with self.assertRaisesRegex(local.ReleaseError, "absolute"):
            local.Workstation.from_file(path)

    # ---- candidate publication -----------------------------------------------
    def candidate(self, version="0.3.3"):
        directory = self.base / "candidate"
        directory.mkdir()
        package = directory / f"maslow-hub-{version}-1-any.pkg.tar.zst"
        raw = f"pkgname = maslow-hub\npkgver = {version}-1\narch = any\n".encode()
        with tarfile.open(package, "w") as archive:
            member = tarfile.TarInfo(".PKGINFO")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        review = {"schemaVersion": 1, "version": version,
                  "package": {"filename": package.name, "size": package.stat().st_size, "sha256": local.sha256(package)},
                  "source": {"repository": "letsgomaslow/maslow-hub", "commit": "a" * 40},
                  "recipe": {"repository": "letsgomaslow/maslow-os-pkgs", "commit": "b" * 40},
                  "voice": {"sourceVersion": "0.3.2", "sourceSha256": "7cbd9494df66526834a73bc390179c596f18db2e8125694c5b5ba24c1d9ed1ab",
                            "manifestSha256": "c" * 64},
                  "buildImage": "archlinux@sha256:" + "d" * 64, "notes": ["Disposable test candidate."]}
        (directory / "review.json").write_text(json.dumps(review))
        return directory

    def test_publication_requires_the_exact_reviewed_digest(self):
        candidate = self.candidate()
        base = self.tip()
        with self.assertRaisesRegex(local.ReleaseError, "does not match"):
            local.op_publish(self.station, candidate, "0" * 64, push=True)
        self.assertEqual(base, self.tip())
        self.assertEqual([], self.station.published_assets)

    def test_publication_appends_the_new_release_and_keeps_every_rollback_entry(self):
        candidate = self.candidate()
        approved = local.sha256(candidate / "review.json")
        local.op_publish(self.station, candidate, approved, push=True)
        manifest = self.remote_json("manifest.json")
        self.assertEqual(self.releases, manifest["releases"][:-1])
        self.assertEqual("0.3.3", manifest["releases"][-1]["version"])
        self.assertEqual(6, manifest["sequence"])
        self.assertEqual(self.remote_json("catalog.json", "signed-staging^")["items"], self.remote_json("catalog.json")["items"])
        self.assertEqual([(["maslow-hub-0.3.3-1-any.pkg.tar.zst", "maslow-hub-0.3.3-1-any.pkg.tar.zst.signature", "review.json"], "0.3.3")],
                         self.station.published_assets)

    def test_publication_rehearsal_publishes_no_assets_or_metadata(self):
        candidate = self.candidate()
        base = self.tip()
        record = local.op_publish(self.station, candidate, local.sha256(candidate / "review.json"), push=False)
        self.assertEqual(base, self.tip())
        self.assertEqual([], self.station.published_assets)
        self.assertEqual(6, record["after"]["manifestSequence"])

    def test_an_existing_version_cannot_be_republished(self):
        candidate = self.candidate("0.3.2")
        with self.assertRaisesRegex(local.ReleaseError, "new higher version"):
            local.op_publish(self.station, candidate, local.sha256(candidate / "review.json"), push=False)


def hub_source():
    candidates = [os.environ.get("MASLOW_HUB_SRC"), str(ROOT.parent / "maslow-hub")]
    return next((Path(path) for path in candidates if path and (Path(path) / "helper/updater.py").is_file()), None)


@unittest.skipUnless(hub_source() and shutil.which("bsdtar"), "needs a Hub checkout (MASLOW_HUB_SRC) and bsdtar")
class ArchiveOwnershipTest(unittest.TestCase):
    """Runs the Hub's actual archive-ownership policy, the same check build-candidate applies."""

    def check(self, entries):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            for name, kind in entries:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if kind == "link":
                    path.symlink_to("/etc/passwd")
                else:
                    path.write_text("x")
            package = Path(temporary) / "package.tar"
            subprocess.run(["bsdtar", "-cf", str(package), "-C", str(root), *[name for name, _ in entries]], check=True)
            code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]);"
                    "from helper.updater import Updater; r = Path(sys.argv[3]);"
                    "Updater(r / 's', r / 'c', r / 'x.json', r / 'k.pem')._validate_archive_paths(Path(sys.argv[2]))")
            return subprocess.run(["python3", "-c", code, str(hub_source()), str(package), temporary], capture_output=True, text=True)

    def test_hub_owned_paths_are_accepted(self):
        result = self.check([(".PKGINFO", "file"), ("usr/lib/maslow-hub/helper/hubctl.py", "file"),
                             ("usr/share/maslow-hub/voice/manifest.json", "file"), ("usr/bin/maslow-hubctl", "file")])
        self.assertEqual(0, result.returncode, result.stderr)

    def test_paths_outside_hub_ownership_are_rejected(self):
        result = self.check([(".PKGINFO", "file"), ("etc/pacman.conf", "file")])
        self.assertNotEqual(0, result.returncode)
        self.assertIn("may not own this path", result.stderr)

    def test_install_scripts_and_symbolic_links_are_rejected(self):
        self.assertIn("forbidden path", self.check([(".PKGINFO", "file"), (".INSTALL", "file")]).stderr)
        self.assertIn("symbolic link", self.check([(".PKGINFO", "file"), ("usr/share/maslow-hub/escape", "link")]).stderr)


if __name__ == "__main__":
    unittest.main()
