#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see map_head_lines.py header).
"""Unit tests for map_head_lines.py: the merge-ref -> PR-head line map, and main()
on a real merge commit."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import map_head_lines as mhl  # noqa: E402


class MapLine(unittest.TestCase):
    def test_map_line(self):
        hunks = [(3, 0, 2),     # the head has 2 more lines after merge line 3
                 (10, 2, 0),    # merge lines 10-11 do not exist in the head
                 (20, 1, 3)]    # merge line 20 is 3 other lines in the head
        cases = {1: 1, 3: 3, 4: 6, 9: 11, 10: None, 11: None, 12: 12, 19: 19, 20: None, 21: 23}
        for line, want in cases.items():
            self.assertEqual(mhl.map_line(hunks, line), want, line)


class Main(unittest.TestCase):
    def test_merge_ref(self):
        repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, repo)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(repo)

        def git(*args):
            return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@invalid", *args],
                                  check=True, capture_output=True, text=True).stdout.strip()

        def write(lines):
            with open("f.c", "w") as fh:
                fh.write("".join(text + "\n" for text in lines))
        body = [f"line {num}" for num in range(1, 21)]
        git("init", "-q", "-b", "main")
        write(body)
        git("add", "f.c")
        git("commit", "-qm", "base")
        git("checkout", "-qb", "pr")
        write(body[:14] + ["line 15 changed by the PR"] + body[15:])
        git("commit", "-qam", "pr")
        head = git("rev-parse", "HEAD")
        git("checkout", "-q", "main")
        write(["base 1", "base 2", "base 3"] + body)       # the base grows after the fork
        git("commit", "-qam", "base grows")
        git("checkout", "-q", "--detach")
        git("merge", "-q", "--no-edit", head)                # HEAD = what refs/pull/N/merge is

        def run(sha):
            with open("cand.json", "w") as fh:
                json.dump({"source": "clang-tidy", "status": "ok", "dropped": 0, "comments": [
                    {"path": "f.c", "line": 18, "body": "on the PR's line"},
                    {"path": "f.c", "line": 2, "body": "on a base-only line"},
                    {"path": "gone.c", "line": 1, "body": "in neither tree"}]}, fh)
            self.assertEqual(mhl.main(["prog", sha, "cand.json", "missing.json"]), 0)
            with open("cand.json") as fh:
                return json.load(fh)
        doc = run(head)
        self.assertEqual([item["line"] for item in doc["comments"]], [15])
        self.assertEqual((doc["status"], doc["dropped"]), ("partial", 2))
        doc = run("0" * 40)                                  # git cannot diff: nothing posted
        self.assertEqual((doc["comments"], doc["status"], doc["dropped"]), ([], "partial", 3))


if __name__ == "__main__":
    unittest.main()
