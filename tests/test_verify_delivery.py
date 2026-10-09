"""Delivery regressions use only disposable signing keys and mocked HTTP transport."""

import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "verify-delivery.py"
SPEC = importlib.util.spec_from_file_location("verify_delivery", SCRIPT)
delivery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delivery)


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / "test-private.pem"
        cls.public = Path(cls.keys.name) / "test-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(cls.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private), "-pubout", "-out", str(cls.public)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.channel = Path(self.temporary.name)
        for name in ("manifest.json", "catalog.json"):
            self.sign_document(name, 30)
        self.expected = {name: (self.channel / name).read_bytes() for name in delivery.FILES}

    def sign_document(self, name, days):
        value = {"sequence": 9, "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()}
        (self.channel / name).write_text(json.dumps(value))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private), "-out", str(self.channel / f"{name}.sig"), str(self.channel / name)], check=True, capture_output=True)

    def transport(self, files):
        def fetch(url, target, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 20)
            self.assertIn("?verify=", url)
            target.write_bytes(files[target.name])
        return fetch

    def verify_once(self, served):
        with mock.patch.object(delivery, "download", side_effect=self.transport(served)) as fetch:
            delivery.verify_once(self.expected, self.public, "https://example.test/staging", delivery.time.monotonic() + 30, 10, 1)
            return fetch.call_count

    def test_all_four_files_and_real_signatures_verify(self):
        self.assertEqual(self.verify_once(self.expected), 4)

    def test_any_changed_file_rejects_same_sequence(self):
        for name in delivery.FILES:
            with self.subTest(name=name):
                served = dict(self.expected)
                served[name] += b" "
                with self.assertRaisesRegex(delivery.VerificationError, "served bytes differ"):
                    self.verify_once(served)

    def test_matching_invalid_signature_is_rejected(self):
        self.expected["catalog.json.sig"] = b"invalid signature"
        with self.assertRaisesRegex(delivery.VerificationError, "signature does not match"):
            self.verify_once(self.expected)

    def test_expired_or_nearly_expired_signed_metadata_is_rejected(self):
        for name in ("manifest.json", "catalog.json"):
            for days in (-1, 5):
                with self.subTest(name=name, days=days):
                    self.sign_document(name, days)
                    self.expected = {file: (self.channel / file).read_bytes() for file in delivery.FILES}
                    with self.assertRaisesRegex(delivery.VerificationError, "expires in fewer"):
                        self.verify_once(self.expected)
                    self.sign_document(name, 30)

    def test_invalid_local_input_fails_before_download(self):
        (self.channel / "manifest.json.sig").write_bytes(b"corrupt")
        with mock.patch.object(delivery, "download") as fetch:
            with self.assertRaises(delivery.VerificationError):
                delivery.confirm_delivery(self.channel, self.public, "https://example.test/staging")
            fetch.assert_not_called()

    def test_transient_stale_delivery_retries_then_passes(self):
        with mock.patch.object(delivery, "verify_once", side_effect=[delivery.VerificationError("stale"), None]) as verify:
            with mock.patch.object(delivery.time, "sleep"):
                delivery.confirm_delivery(self.channel, self.public, "https://example.test/staging")
        self.assertEqual(verify.call_count, 2)

    def test_timeout_retries_then_fails_at_deadline(self):
        with mock.patch.object(delivery, "verify_once", side_effect=subprocess.TimeoutExpired("curl", 20)) as verify:
            with mock.patch.object(delivery.time, "monotonic", side_effect=[0, 0, 4, 5]):
                with mock.patch.object(delivery.time, "sleep") as sleep:
                    with self.assertRaisesRegex(delivery.VerificationError, "within 5 seconds"):
                        delivery.confirm_delivery(self.channel, self.public, "https://example.test/staging", timeout=5)
        self.assertEqual(verify.call_count, 1)
        sleep.assert_called_once_with(1)

    def test_download_is_anonymous_https_and_bounded(self):
        with mock.patch.object(delivery.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            delivery.download("https://example.test/manifest.json", self.channel / "download", 12)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["curl", "-q"])
        self.assertEqual(argv[argv.index("--proto") + 1], "=https")
        self.assertEqual(argv[argv.index("--proto-redir") + 1], "=https")
        self.assertEqual(argv[argv.index("--max-time") + 1], "12")
        self.assertEqual(run.call_args.kwargs["timeout"], 13)
        self.assertNotIn("--user", argv)
        self.assertNotIn("--header", argv)

    def test_download_failure_is_reported_without_remote_content(self):
        with mock.patch.object(delivery.subprocess, "run", return_value=subprocess.CompletedProcess([], 22, stderr=b"untrusted remote text")):
            with self.assertRaisesRegex(delivery.VerificationError, r"curl 22\)"):
                delivery.download("https://example.test/missing", self.channel / "missing", 12)

    def test_reject_credentials_http_and_unbounded_parameters(self):
        for url in ("http://example.test", "https://user:secret@example.test", "https://example.test?x=1", "https://example.test/#fragment"):
            with self.subTest(url=url), self.assertRaises(delivery.VerificationError):
                delivery.confirm_delivery(self.channel, self.public, url)
        for value in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=value), self.assertRaises(delivery.VerificationError):
                delivery.confirm_delivery(self.channel, self.public, "https://example.test", timeout=value)


if __name__ == "__main__":
    unittest.main()
