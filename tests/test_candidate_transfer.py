import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("transfer", Path(__file__).parents[1] / "tools/candidate-transfer.py")
TRANSFER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFER)


class TransferTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.name = "maslow-hub-9.0.0-1-any.pkg.tar.zst"
        self.data = b"disposable candidate fixture"
        (self.source / self.name).write_bytes(self.data)
        self.review = {"package": {"filename": self.name, "sha256": hashlib.sha256(self.data).hexdigest(), "size": len(self.data)}}
        self.save_review()
        self.env = patch.dict(os.environ, {"HUB_CANDIDATE_ENCRYPTION_KEY": "a" * 64})
        self.env.start()
        self.addCleanup(self.env.stop)

    def save_review(self):
        (self.source / "review.json").write_text(json.dumps(self.review))

    def test_rejects_paths_and_wrong_candidate(self):
        self.review["package"]["filename"] = "../escape.pkg.tar.zst"
        self.save_review()
        with self.assertRaises(ValueError):
            TRANSFER.transfer("encrypt", self.source, self.root / "encrypted")
        self.review["package"]["filename"] = self.name
        self.review["package"]["sha256"] = "0" * 64
        self.save_review()
        with self.assertRaises(ValueError):
            TRANSFER.transfer("encrypt", self.source, self.root / "encrypted")

    @unittest.skipUnless(shutil.which("gpg"), "GPG integration runs on GitHub's Linux runner")
    def test_authenticated_roundtrip_and_wrong_secret(self):
        encrypted = self.root / "encrypted"
        TRANSFER.transfer("encrypt", self.source, encrypted)
        self.assertEqual({"candidate.pkg.gpg", "review.json"}, {p.name for p in encrypted.iterdir()})
        decoded = self.root / "decoded"
        TRANSFER.transfer("decrypt", encrypted, decoded)
        self.assertEqual(self.data, (decoded / self.name).read_bytes())
        with patch.dict(os.environ, {"HUB_CANDIDATE_ENCRYPTION_KEY": "b" * 64}):
            with self.assertRaises(ValueError):
                TRANSFER.transfer("decrypt", encrypted, self.root / "wrong")
        self.assertFalse((self.root / "wrong" / self.name).exists())
        data = bytearray((encrypted / "candidate.pkg.gpg").read_bytes())
        data[-10] ^= 1
        (encrypted / "candidate.pkg.gpg").write_bytes(data)
        with self.assertRaises(ValueError):
            TRANSFER.transfer("decrypt", encrypted, self.root / "tampered")
        self.assertFalse((self.root / "tampered" / self.name).exists())
