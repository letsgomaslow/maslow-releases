import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("channel_data", Path(__file__).parents[1] / "tools/channel-data.py")
CHANNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHANNEL)


class ChannelDataTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)
        CHANNEL.git("init", "-q")
        CHANNEL.git("config", "user.name", "Fixture")
        CHANNEL.git("config", "user.email", "fixture@example.invalid")
        (self.root / "hub/staging").mkdir(parents=True)
        for name in CHANNEL.NAMES:
            (self.root / CHANNEL.PREFIX / name).write_text("old-" + name)
        (self.root / "inert-script.sh").write_text("exit 99\n")
        CHANNEL.git("add", ".")
        CHANNEL.git("commit", "-qm", "fixture")
        self.base = CHANNEL.git("rev-parse", "HEAD").decode().strip()

    def test_extract_reads_only_regular_channel_blobs(self):
        output = self.root / "output"
        CHANNEL.extract(self.base, output)
        self.assertEqual(set(CHANNEL.NAMES), {p.name for p in output.iterdir()})
        self.assertEqual("old-manifest.json", (output / "manifest.json").read_text())

    def test_extract_rejects_symlink_without_creating_output(self):
        path = self.root / CHANNEL.PREFIX / "manifest.json"
        path.unlink()
        path.symlink_to("../../inert-script.sh")
        CHANNEL.git("add", ".")
        CHANNEL.git("commit", "-qm", "bad link")
        base = CHANNEL.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            CHANNEL.extract(base, self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_commit_changes_only_four_files_preserving_index_and_branch(self):
        output = self.root / "output"
        CHANNEL.extract(self.base, output)
        for name in CHANNEL.NAMES:
            (output / name).write_text("new-" + name)
        (output / "inert-script.sh").write_text("changed\n")
        index_before = (self.root / ".git/index").read_bytes()
        new = CHANNEL.commit(self.base, output)
        changed = CHANNEL.git("diff", "--name-only", self.base, new).decode().splitlines()
        self.assertEqual(sorted(CHANNEL.PREFIX + n for n in CHANNEL.NAMES), changed)
        self.assertEqual(self.base, CHANNEL.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(index_before, (self.root / ".git/index").read_bytes())
        self.assertEqual(b"exit 99\n", CHANNEL.git("show", new + ":inert-script.sh"))
        self.assertEqual(self.base, CHANNEL.git("rev-parse", new + "^").decode().strip())

    def test_commit_refuses_missing_or_symlink_output(self):
        output = self.root / "output"
        CHANNEL.extract(self.base, output)
        path = output / "catalog.json.sig"
        path.unlink()
        with self.assertRaises(ValueError):
            CHANNEL.commit(self.base, output)
        path.symlink_to(self.root / "inert-script.sh")
        with self.assertRaises(ValueError):
            CHANNEL.commit(self.base, output)


if __name__ == "__main__":
    unittest.main()
