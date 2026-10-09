"""Candidate preparation tests use synthetic keys/archives, never production secrets."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "build-candidate.py"
SPEC = importlib.util.spec_from_file_location("build_candidate", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def bundle(self):
        files, records = {}, []
        for name in ("maslow-voice", "maslow-voice-local", "hermes-agent"):
            filename = f"{name}-0.1.4-9-x86_64.pkg.tar.zst"
            payload = f"synthetic {name}".encode()
            files["packages/" + filename] = payload
            records.append({"name": name, "version": "0.1.4-9", "filename": filename,
                            "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})
        files["manifest.json"] = json.dumps({"schemaVersion": 1, "packages": records}).encode()
        return files

    def archive(self, entries):
        path = self.root / "fixture.tar"
        with tarfile.open(path, "w") as archive:
            for name, payload in entries:
                info = tarfile.TarInfo(name)
                if payload is None:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/tmp/escape"
                    archive.addfile(info)
                else:
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
        return path

    def read_voice(self, entries):
        path = self.archive(entries)
        popen = subprocess.Popen
        # Tests use plain synthetic tar streams; production invokes zstd.
        with mock.patch.object(builder.subprocess, "Popen", side_effect=lambda argv, **kw: popen(["cat", str(path)], **kw)):
            return builder.voice_files(path)

    def test_recovers_exact_reviewed_voice_files_only(self):
        files = self.bundle()
        entries = [(builder.VOICE_PREFIX + name, data) for name, data in files.items()]
        entries.append(("usr/lib/maslow-hub/helper/private-source.py", b"not extracted"))
        self.assertEqual(self.read_voice(entries), files)

    def test_symlinks_duplicate_paths_and_traversal_fail(self):
        cases = [[(builder.VOICE_PREFIX + "manifest.json", None)],
                 [(builder.VOICE_PREFIX + "manifest.json", b"{}"), (builder.VOICE_PREFIX + "manifest.json", b"{}")],
                 [("../../outside", b"bad")], [("/absolute", b"bad")]]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(builder.BuildError):
                self.read_voice(entries)

    def test_missing_or_altered_voice_is_rejected(self):
        with self.assertRaisesRegex(builder.BuildError, "missing"):
            self.read_voice([("usr/bin/unrelated", b"data")])
        files = self.bundle()
        files[next(name for name in files if name.startswith("packages/"))] += b"tampered"
        with self.assertRaisesRegex(builder.BuildError, "do not match"):
            self.read_voice([(builder.VOICE_PREFIX + name, data) for name, data in files.items()])

    def test_unexpected_voice_file_is_rejected(self):
        files = self.bundle()
        files["private.pem"] = b"not allowed"
        with self.assertRaisesRegex(builder.BuildError, "unexpected"):
            self.read_voice([(builder.VOICE_PREFIX + name, data) for name, data in files.items()])

    def test_pinned_public_key_and_signature_are_both_checked(self):
        private, public = self.root / "private.pem", self.root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        raw = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"], check=True, capture_output=True).stdout
        payload, signature = self.root / "payload", self.root / "signature"
        payload.write_bytes(b"synthetic test data")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(payload)], check=True, capture_output=True)
        with self.assertRaisesRegex(builder.BuildError, "fingerprint"):
            builder.verify_signature(public, payload, signature)
        with mock.patch.object(builder, "TRUST_SHA256", hashlib.sha256(raw).hexdigest()):
            builder.verify_signature(public, payload, signature)
            payload.write_bytes(b"changed")
            with self.assertRaises(subprocess.CalledProcessError):
                builder.verify_signature(public, payload, signature)

    def donor(self):
        base = f"https://github.com/letsgomaslow/maslow-releases/releases/download/sha256-{builder.VOICE_SOURCE_SHA256}/maslow-hub-0.3.2-1-any.pkg.tar.zst"
        return {"version": "0.3.2", "sha256": builder.VOICE_SOURCE_SHA256, "packageSize": 1234,
                "packageUrl": base, "signatureUrl": base + ".signature"}

    def write_manifest(self, record):
        (self.root / "manifest.json").write_text(json.dumps({"channel": "staging", "releases": [record]}))

    def test_only_exact_authenticated_voice_donor_is_accepted(self):
        original = self.donor()
        self.write_manifest(original)
        with mock.patch.object(builder, "verify_signature") as verify:
            self.assertEqual(builder.donor_record(self.root, self.root / "public.pem"), original)
            verify.assert_called_once()
            for field, value in (("sha256", "0" * 64), ("packageUrl", "https://evil.test/package"), ("signatureUrl", "https://evil.test/sig"), ("packageSize", -1)):
                modified = dict(original, **{field: value})
                self.write_manifest(modified)
                with self.subTest(field=field), self.assertRaises(builder.BuildError):
                    builder.donor_record(self.root, self.root / "public.pem")

    def test_non_exact_or_dirty_checkouts_fail_before_export(self):
        with self.assertRaisesRegex(builder.BuildError, "full lowercase"):
            builder.export_checkout(self.root, "main", self.root / "export")
        for head, dirty in (("b" * 40, ""), ("a" * 40, " M file")):
            responses = [subprocess.CompletedProcess([], 0, stdout=head), subprocess.CompletedProcess([], 0, stdout=dirty)]
            with mock.patch.object(builder, "run", side_effect=responses):
                with self.assertRaisesRegex(builder.BuildError, "clean"):
                    builder.export_checkout(self.root, "a" * 40, self.root / "export")

    def test_private_command_output_is_captured(self):
        with mock.patch.object(builder.subprocess, "run") as execute:
            builder.run(["python", "private-test.py"])
        self.assertTrue(execute.call_args.kwargs["capture_output"])
        self.assertTrue(execute.call_args.kwargs["check"])

    def test_archive_preflight_uses_actual_helper_policy_without_installing(self):
        metadata = "pkgname = maslow-hub\npkgver = 0.3.3-1\narch = any\ndepend = quickshell\n"
        with mock.patch.object(builder, "run", return_value=subprocess.CompletedProcess([], 0, stdout=metadata)) as execute:
            builder.archive_preflight(self.root / "source", self.root / "package", "0.3.3")
        self.assertEqual(execute.call_args_list[0].args[0][:2], ["bsdtar", "-xOf"])
        command = execute.call_args_list[1].args[0]
        self.assertEqual(command[:2], ["python", "-c"])
        self.assertIn("from helper.updater import Updater", command[2])
        self.assertIn("updater._validate_archive_paths", command[2])
        self.assertEqual(command[-2:], [str(self.root / "source"), str(self.root / "package")])
        self.assertNotIn("pacman", " ".join(command))

    def test_archive_preflight_rejects_identity_conflicts_and_policy_failure(self):
        valid = "pkgname = maslow-hub\npkgver = 0.3.3-1\narch = any\n"
        invalid = [valid + "conflict = other\n", valid + "replaces = other\n",
                   valid.replace("0.3.3-1", "0.3.2-1"), valid + "pkgname = duplicate\n"]
        for metadata in invalid:
            with mock.patch.object(builder, "run", return_value=subprocess.CompletedProcess([], 0, stdout=metadata)) as execute:
                with self.subTest(metadata=metadata), self.assertRaises(builder.BuildError):
                    builder.archive_preflight(self.root / "source", self.root / "package", "0.3.3")
                self.assertEqual(execute.call_count, 1)
        with mock.patch.object(builder, "run", side_effect=[subprocess.CompletedProcess([], 0, stdout=valid), subprocess.CalledProcessError(1, "helper archive policy")]):
            with self.assertRaises(subprocess.CalledProcessError):
                builder.archive_preflight(self.root / "source", self.root / "package", "0.3.3")

    def test_anonymous_download_is_bounded_https(self):
        with mock.patch.object(builder, "run") as execute:
            builder.download("https://github.com/example/package", self.root / "download", 1234)
        args = execute.call_args.args[0]
        self.assertEqual(args[:2], ["curl", "-q"])
        self.assertEqual(args[args.index("--max-filesize") + 1], "1234")
        self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
        self.assertEqual(execute.call_args.kwargs["timeout"], 910)
        with self.assertRaises(builder.BuildError):
            builder.download("http://example.test/package", self.root / "download", 1234)

    def test_build_keeps_source_offline_and_exports_only_candidate_and_review(self):
        donor_bytes, package_bytes = b"signed synthetic donor", b"synthetic built package"
        donor_sha = hashlib.sha256(donor_bytes).hexdigest()
        notes = self.root / "notes.json"
        notes.write_text('["Internal staging review candidate."]')
        output = self.root / "candidate"
        args = SimpleNamespace(arch_image="archlinux@sha256:" + "f" * 64, notes_file=notes,
                               output_dir=output, channel_dir=self.root, public_key=self.root / "public.pem",
                               source_dir=self.root / "source", source_sha="a" * 40,
                               recipe_dir=self.root / "recipe", recipe_sha="b" * 40)
        record = {"packageUrl": "https://github.com/package", "signatureUrl": "https://github.com/signature", "packageSize": len(donor_bytes)}
        commands = []

        def export(checkout, sha, destination, subpath=None):
            destination.mkdir()

        def download(url, target, limit):
            target.write_bytes(donor_bytes if url.endswith("package") else b"signature")

        def execute(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ["docker", "build"]:
                Path(argv[argv.index("--iidfile") + 1]).write_text("sha256:" + "e" * 64)
                self.assertEqual({path.name for path in Path(argv[-1]).iterdir()}, {"Dockerfile"})
            elif argv[:2] == ["docker", "run"]:
                if "--inside-container-checks" in argv:
                    self.assertEqual(argv[argv.index("--user") + 1], "0")
                    self.assertFalse(any("dst=/output" in value for value in argv))
                    return subprocess.CompletedProcess(argv, 0)
                mount = next(value for value in argv if "dst=/output" in value)
                staged = Path(mount.split("src=", 1)[1].split(",", 1)[0])
                (staged / "maslow-hub-0.3.3-1-any.pkg.tar.zst").write_bytes(package_bytes)
                (staged / "build-result.json").write_text(json.dumps({"version": "0.3.3", "voiceManifestSha256": "c" * 64}))
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(builder, "donor_record", return_value=record), mock.patch.object(builder, "VOICE_SOURCE_SHA256", donor_sha), mock.patch.object(builder, "export_checkout", side_effect=export), mock.patch.object(builder, "download", side_effect=download), mock.patch.object(builder, "verify_signature"), mock.patch.object(builder, "run", side_effect=execute), mock.patch("builtins.print"):
            builder.build(args)
        self.assertEqual({path.name for path in output.iterdir()}, {"maslow-hub-0.3.3-1-any.pkg.tar.zst", "review.json"})
        review = json.loads((output / "review.json").read_text())
        self.assertEqual(review["source"]["commit"], args.source_sha)
        self.assertEqual(review["recipe"]["commit"], args.recipe_sha)
        self.assertEqual(review["package"]["sha256"], hashlib.sha256(package_bytes).hexdigest())
        containers = [argv for argv in commands if argv[:2] == ["docker", "run"]]
        self.assertEqual(len(containers), 2)
        self.assertIn("--inside-container-checks", containers[0])
        docker = containers[1]
        self.assertNotIn("--user", docker)  # Image USER builder applies to packaging.
        self.assertEqual(docker[docker.index("--network") + 1], "none")
        self.assertNotIn("--env", docker)
        self.assertTrue(any("dst=/inputs,readonly" in value for value in docker))


if __name__ == "__main__":
    unittest.main()
