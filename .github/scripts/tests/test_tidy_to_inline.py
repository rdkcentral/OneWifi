#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see tidy_to_inline.py header).
"""Unit tests for tidy_to_inline.py: parsing a filtered clang-tidy log into inline
review candidates, and the envelope status main() writes."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tidy_to_inline as tidy_conv  # noqa: E402

ABS = "/home/runner/work/OneWifi/OneWifi/easymesh_project/OneWifi/"
WARN = ABS + "source/foo.c:42:9: warning: 'x' set but not used [bugprone-a]\n"


class Parse(unittest.TestCase):
    def test_parse(self):
        log = (WARN + WARN                                              # repeated -> one comment
               + ABS + "source/bar.c:7:1: error: bad thing [bugprone-b,-warnings-as-errors]\n"
               + "not a clang-tidy line\n\n")                           # dropped; blank skipped
        comments, dropped = tidy_conv.parse(log)
        self.assertEqual(dropped, 1)
        self.assertEqual([(item["path"], item["line"]) for item in comments],
                         [("source/foo.c", 42), ("source/bar.c", 7)])   # repo-relative paths
        self.assertIn("❗ **clang-tidy** `bugprone-a` (warning)", comments[0]["body"])
        self.assertIn("❌ **clang-tidy** `bugprone-b` (error)", comments[1]["body"])


class MainIO(unittest.TestCase):
    def _file(self, text=None):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, path)
        if text is not None:
            with open(path, "w") as fh:
                fh.write(text)
        return path

    def _run(self, log_path, *extra):
        out = self._file()
        self.assertEqual(tidy_conv.main(["prog", log_path, out, *extra]), 0)
        with open(out) as fh:
            return json.load(fh)

    def test_missing_log_is_skipped(self):
        doc = self._run("/no/such/tidy.log")
        self.assertEqual((doc["source"], doc["status"], doc["comments"]), ("clang-tidy", "skipped", []))

    def test_status(self):
        log = self._file(WARN)
        self.assertEqual(self._run(log)["status"], "ok")
        self.assertEqual(self._run(log, self._file(""))["status"], "ok")      # empty failed list
        failed = self._file("source/bar.c: clang-tidy exit 139\n")
        doc = self._run(log, failed)
        self.assertEqual((doc["status"], len(doc["comments"])), ("partial", 1))  # findings kept
        self.assertEqual(self._run(self._file(WARN + "junk\n"))["status"], "partial")  # dropped


if __name__ == "__main__":
    unittest.main()
