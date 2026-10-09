"""Disposable-key regression coverage; never contacts GitHub or signs production data."""
import datetime as dt
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("publish_candidate", Path(__file__).resolve().parents[1] / "tools/publish-candidate.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class CandidatePublication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / "private.pem"
        cls.public = Path(cls.keys.name) / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(cls.private)], check=True, capture_output=True)
        cls.private.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private), "-pubout", "-out", str(cls.public)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.channel = self.root / "channel"
        self.channel.mkdir()
        self.package = self.root / "maslow-hub-0.3.3-1-any.pkg.tar.zst"
        # bsdtar identifies compression by bytes; fixture needs no zstd dependency.
        self.make_package("0.3.3-1")
        self.review = {"schemaVersion": 1, "version": "0.3.3",
                       "package": {"filename": self.package.name, "size": self.package.stat().st_size,
                                   "sha256": publisher.digest(self.package)},
                       "source": {"repository": "letsgomaslow/maslow-hub", "commit": "a" * 40},
                       "recipe": {"repository": "letsgomaslow/maslow-os-pkgs", "commit": "b" * 40},
                       "voice": {"sourceVersion": "0.3.2", "sourceSha256": "7cbd9494df66526834a73bc390179c596f18db2e8125694c5b5ba24c1d9ed1ab",
                                 "manifestSha256": "c" * 64},
                       "buildImage": "archlinux@sha256:" + "d" * 64, "notes": ["Approved test candidate."]}
        self.review_path = self.root / "review.json"
        self.save_review()
        self.manifest = {"schemaVersion": 1, "channel": "staging", "sequence": 7,
                         "generatedAt": "2020-01-01T00:00:00Z", "expiresAt": "2020-02-01T00:00:00Z",
                         "releases": [{"version": "0.3.2", "sha256": "1" * 64,
                                       "packageUrl": "https://example.test/old", "notes": ["Keep rollback."]}],
                         "extraPreserved": {"future": True}}
        self.catalog = {"schemaVersion": 1, "channel": "staging", "sequence": 2, "kind": "catalog",
                        "generatedAt": "2020-01-01T00:00:00Z", "expiresAt": "2020-02-01T00:00:00Z",
                        "items": [{"id": "unchanged", "status": "Experimental"}]}
        self.write_signed("manifest.json", self.manifest)
        self.write_signed("catalog.json", self.catalog)
        self.output = self.root / "output"
        self.now = dt.datetime(2026, 10, 9, 12, tzinfo=dt.timezone.utc)

    def make_package(self, version):
        raw = f"pkgname = maslow-hub\npkgver = {version}\narch = any\n".encode()
        with tarfile.open(self.package, "w") as archive:
            member = tarfile.TarInfo(".PKGINFO")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))

    def save_review(self):
        self.review_path.write_text(json.dumps(self.review))

    def write_signed(self, name, value):
        target = publisher.write_atomic(self.channel, name, publisher.canonical(value))
        with patch.dict(os.environ, {}, clear=True):
            publisher.sign(self.private, target, self.channel / (name + ".sig"))

    def prepare(self, publish=False, public=None):
        with patch.dict(os.environ, {}, clear=True):
            return publisher.prepare(self.package, self.review_path, self.channel, public or self.public,
                                     self.private, self.output, publish, self.now)

    def test_dry_run_preserves_rollback_catalog_and_signs_every_pair(self):
        with patch.object(publisher, "gh_json", side_effect=AssertionError("Dry-run network access")):
            result = self.prepare()
        self.assertFalse(result["published"])
        updated = json.loads((self.output / "channel/manifest.json").read_text())
        catalog = json.loads((self.output / "channel/catalog.json").read_text())
        self.assertEqual(updated["releases"][:-1], self.manifest["releases"])
        self.assertEqual(updated["extraPreserved"], self.manifest["extraPreserved"])
        self.assertEqual(updated["sequence"], 8)
        self.assertEqual(catalog["sequence"], 3)
        self.assertEqual(catalog["items"], self.catalog["items"])
        self.assertEqual(updated["expiresAt"], "2026-11-08T12:00:00Z")
        release = updated["releases"][-1]
        self.assertEqual(release["packageUrl"], f"https://github.com/{publisher.REPOSITORY}/releases/download/sha256-{self.review['package']['sha256']}/{self.package.name}")
        for name in ("manifest.json", "catalog.json"):
            self.assertTrue(publisher.verify(self.public, self.output / "channel" / name, self.output / "channel" / (name + ".sig")))
        self.assertTrue(publisher.verify(self.public, self.output / "artifacts" / self.package.name,
                                        self.output / "artifacts" / (self.package.name + ".signature")))

    def test_changed_candidate_is_rejected_before_signing(self):
        self.package.write_bytes(self.package.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "size"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_package_version_must_match_review_even_with_correct_digest(self):
        self.make_package("9.9.9-1")
        self.review["package"]["sha256"] = publisher.digest(self.package)
        self.save_review()
        with self.assertRaisesRegex(ValueError, "pkgver"):
            self.prepare()

    def test_unexpected_provenance_field_cannot_be_published(self):
        self.review["privateBuildLog"] = "not public"
        self.save_review()
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            self.prepare()

    def test_tampered_old_manifest_and_catalog_are_rejected(self):
        for name in ("manifest.json", "catalog.json"):
            with self.subTest(name=name):
                source = self.channel / name
                original = source.read_bytes()
                source.write_bytes(original + b" ")
                with self.assertRaisesRegex(ValueError, "signature"):
                    self.prepare()
                source.write_bytes(original)

    def test_duplicate_and_lower_versions_are_rejected(self):
        for version in ("0.3.3", "0.4.0"):
            self.manifest["releases"][0]["version"] = version
            self.write_signed("manifest.json", self.manifest)
            with self.assertRaisesRegex(ValueError, "higher version"):
                self.prepare()

    def test_publish_failure_does_not_expose_promotable_channel(self):
        with patch.object(publisher, "publish_assets", side_effect=ValueError("delivery failed")):
            with self.assertRaisesRegex(ValueError, "delivery failed"):
                self.prepare(publish=True)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_replaced(self):
        self.output.mkdir()
        (self.output / "evidence").write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.prepare()
        self.assertEqual((self.output / "evidence").read_text(), "keep")

    def test_wrong_key_is_rejected_before_publication(self):
        other = self.root / "other.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other)],
                       check=True, capture_output=True)
        other.chmod(0o600)
        with patch.object(publisher, "publish_assets", side_effect=AssertionError("Must not publish")):
            with self.assertRaisesRegex(ValueError, "pinned"):
                publisher.prepare(self.package, self.review_path, self.channel, self.public, other, self.output, True)

    def test_existing_release_or_draft_is_never_changed(self):
        self.prepare()
        tag = "sha256-" + self.review["package"]["sha256"]
        for draft in (False, True):
            with self.subTest(draft=draft):
                responses = [{"full_name": publisher.REPOSITORY, "private": False}, {"enabled": True}]
                existing = subprocess.CompletedProcess([], 0, json.dumps([[{"tag_name": tag, "draft": draft}]]))
                with patch.object(publisher, "gh_json", side_effect=responses), patch.object(publisher.subprocess, "run", return_value=existing) as run:
                    with self.assertRaisesRegex(ValueError, "already exists"):
                        publisher.publish_assets(self.output / "artifacts", self.review)
                    self.assertEqual(run.call_count, 1)
                    self.assertNotIn("create", run.call_args.args[0])

    def test_publication_requires_immutable_policy(self):
        with patch.object(publisher, "gh_json", side_effect=[{"full_name": publisher.REPOSITORY, "private": False}, {"enabled": False}]):
            with self.assertRaisesRegex(ValueError, "immutable"):
                publisher.publish_assets(self.root, self.review)

    def test_success_publishes_draft_without_clobber_and_verifies_all_assets(self):
        self.prepare()
        responses = [{"full_name": publisher.REPOSITORY, "private": False}, {"enabled": True}, [], {"draft": False, "immutable": True}]
        with patch.object(publisher, "gh_json", side_effect=responses), patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "[]")) as run, patch.object(publisher, "verify_anonymous") as anonymous:
            publisher.publish_assets(self.output / "artifacts", self.review)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertIn("--draft", commands[1])
        self.assertIn("--draft=false", commands[2])
        self.assertTrue(all("--clobber" not in command for command in commands))
        self.assertEqual(anonymous.call_count, 3)
        self.assertTrue(all(call.args[0].startswith("https://github.com/letsgomaslow/maslow-releases/releases/download/sha256-") for call in anonymous.call_args_list))

    def test_anonymous_verification_rejects_wrong_same_size_bytes(self):
        expected = self.root / "expected"
        expected.write_bytes(b"approved")
        response = io.BytesIO(b"tampered")
        response.geturl = lambda: "https://release-assets.githubusercontent.com/file"
        with patch.object(publisher.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "differ"):
                publisher.verify_anonymous("https://github.com/release", expected)
            self.assertEqual(opener.return_value.open.call_args.args, ("https://github.com/release",))

    def test_insecure_redirect_is_rejected_before_following_it(self):
        with self.assertRaisesRegex(ValueError, "Insecure"):
            publisher.SecureRedirect().redirect_request(None, None, 302, "", {}, "http://example.test/package")


if __name__ == "__main__":
    unittest.main()
