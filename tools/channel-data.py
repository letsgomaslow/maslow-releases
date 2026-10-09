#!/usr/bin/python3
"""Read inert channel blobs and create a commit changing only those blobs."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile

NAMES = ("manifest.json", "manifest.json.sig", "catalog.json", "catalog.json.sig")
PREFIX = "hub/staging/"


def git(*args, data=None, env=None):
    return subprocess.run(["git", *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, env=env).stdout


def extract(base, directory):
    blobs = {}
    for name in NAMES:
        path = PREFIX + name
        entry = git("ls-tree", base, "--", path).decode().strip()
        if not entry.startswith("100644 blob ") or not entry.endswith("\t" + path):
            raise ValueError(f"{path} must be a regular committed data file")
        blobs[name] = git("show", f"{base}:{path}")
    directory.mkdir(parents=True, exist_ok=False)
    for name, content in blobs.items():
        (directory / name).write_bytes(content)


def commit(base, directory):
    blobs = {}
    for name in NAMES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{name} must be a regular signed output file")
        blobs[name] = path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="channel-index-") as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / "index"),
                   GIT_AUTHOR_NAME="maslow-release-bot", GIT_COMMITTER_NAME="maslow-release-bot",
                   GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
                   GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com")
        git("read-tree", base, env=env)
        for name, content in blobs.items():
            blob = git("hash-object", "-w", "--stdin", data=content).decode().strip()
            git("update-index", "--add", "--cacheinfo", f"100644,{blob},{PREFIX}{name}", env=env)
        tree = git("write-tree", env=env).decode().strip()
        return git("commit-tree", tree, "-p", base, "-m", "Renew signed Hub staging metadata", env=env).decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("extract", "commit"))
    parser.add_argument("--base", required=True)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    base = git("rev-parse", "--verify", args.base + "^{commit}").decode().strip()
    if args.operation == "extract":
        extract(base, args.directory)
    else:
        print(commit(base, args.directory))


if __name__ == "__main__":
    main()
