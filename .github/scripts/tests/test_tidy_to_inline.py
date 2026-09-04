#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see tidy_to_inline.py header).
"""Unit tests for tidy_to_inline.py: parsing a filtered clang-tidy log into inline
review candidates (gate/advisory split, path strip, dedupe, dropped count) and the
missing-log -> skipped envelope."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tidy_to_inline as t  # noqa: E402

ABS = "/home/runner/work/OneWifi/OneWifi/easymesh_project/OneWifi/"


class Parse(unittest.TestCase):
    def test_gate_advisory_and_pathstrip(self):
        log = (
            ABS + "source/foo.c:42:9: warning: 'x' set but not used [bugprone-a]\n"
            + ABS + "source/bar.c:7:1: error: bad thing [bugprone-b]\n"
        )
        comments, dropped = t.parse(log)
        self.assertEqual(dropped, 0)
        self.assertEqual(comments[0]["path"], "source/foo.c")   # stripped to repo-rel
        self.assertEqual(comments[0]["line"], 42)
        self.assertIn("(advisory)", comments[0]["body"])        # warning -> advisory
        self.assertIn("bugprone-a", comments[0]["body"])
        self.assertIn("(gate)", comments[1]["body"])            # error   -> gate
        self.assertTrue(all(c["side"] == "RIGHT" for c in comments))

    def test_dedupes_same_finding(self):
        # Same finding twice (clang-tidy repeats across TUs / columns) -> one comment.
        line = ABS + "source/foo.c:42:9: warning: dup [check-x]\n"
        comments, dropped = t.parse(line + line)
        self.assertEqual(len(comments), 1)
        self.assertEqual(dropped, 0)

    def test_drops_unparsable(self):
        comments, dropped = t.parse("not a clang-tidy line\n\n")
        self.assertEqual(comments, [])
        self.assertEqual(dropped, 1)        # the blank line is skipped, not dropped


class MainIO(unittest.TestCase):
    def _tmp(self):
        fd, p = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        return p

    def test_missing_log_is_skipped(self):
        out = self._tmp()
        rc = t.main(["prog", "/no/such/tidy.log", out])
        self.assertEqual(rc, 0)
        with open(out) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["status"], "skipped")   # not "ok" -> poster keeps comments
        self.assertEqual(doc["comments"], [])
        self.assertEqual(doc["source"], "clang-tidy")

    def test_writes_ok_envelope(self):
        logfd, logp = tempfile.mkstemp(suffix=".log")
        os.write(logfd, (ABS + "source/foo.c:1:1: error: e [c] \n").encode())
        os.close(logfd)
        out = self._tmp()
        self.assertEqual(t.main(["prog", logp, out]), 0)
        with open(out) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(len(doc["comments"]), 1)
        self.assertIn("(gate)", doc["comments"][0]["body"])


if __name__ == "__main__":
    unittest.main()
