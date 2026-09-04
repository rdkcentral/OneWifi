#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see diff_to_suggestions.py header).
"""Unit tests for diff_to_suggestions.py: parse(), line-scoping, and the candidate
envelope main() now emits for review_poster.py."""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import diff_to_suggestions as d2s  # noqa: E402

DIFF = """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -5,2 +5,2 @@
-int  x=1;
-int  y=2;
+int x = 1;
+int y = 2;
"""


class Parse(unittest.TestCase):
    def test_multiline_suggestion(self):
        comments = d2s.parse(DIFF)
        self.assertEqual(len(comments), 1)
        c = comments[0]
        self.assertEqual(c["path"], "a.c")
        self.assertEqual(c["start_line"], 5)     # two removed lines -> ranged anchor
        self.assertEqual(c["line"], 6)
        self.assertIn("```suggestion", c["body"])
        self.assertIn("int x = 1;", c["body"])

    def test_pure_insertion_dropped(self):
        # A hunk with only + lines would corrupt code on one-click apply -> dropped.
        diff = ("diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n"
                "@@ -5,0 +6,1 @@\n+int added;\n")
        self.assertEqual(d2s.parse(diff), [])


class Scoping(unittest.TestCase):
    def test_commentable_intervals_grow_and_merge(self):
        self.assertEqual(d2s._commentable_intervals([(5, 6)], 3), [[2, 9]])
        # two close ranges merge into one rendered hunk
        self.assertEqual(d2s._commentable_intervals([(5, 5), (9, 9)], 3), [[2, 12]])

    def test_load_changed_lines_ok_and_failopen(self):
        fd, path = tempfile.mkstemp(); os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "w") as fh:
            fh.write("a.c:5-6\n")
        self.assertEqual(d2s.load_changed_lines(path), {"a.c": [(5, 6)]})
        with open(path, "w") as fh:
            fh.write("garbage-no-range\n")
        self.assertIsNone(d2s.load_changed_lines(path))     # fail open


class Envelope(unittest.TestCase):
    def _run_main(self, diff, changed_line=None):
        out_fd, out_path = tempfile.mkstemp(suffix=".json"); os.close(out_fd)
        self.addCleanup(os.unlink, out_path)
        env = {"CANDIDATES_OUT": out_path}
        if changed_line is not None:
            cl_fd, cl_path = tempfile.mkstemp(); os.close(cl_fd)
            self.addCleanup(os.unlink, cl_path)
            with open(cl_path, "w") as fh:
                fh.write(changed_line)
            env["CHANGED_LINES_FILE"] = cl_path
        old_stdin, old_env = sys.stdin, dict(os.environ)
        try:
            sys.stdin = io.StringIO(diff)
            os.environ.pop("CHANGED_LINES_FILE", None)
            os.environ.update(env)
            d2s.main()
        finally:
            sys.stdin = old_stdin
            os.environ.clear(); os.environ.update(old_env)
        with open(out_path) as fh:
            return json.load(fh)

    def test_envelope_shape_and_source(self):
        out = self._run_main(DIFF, changed_line="a.c:5-6\n")
        self.assertEqual(out["source"], "formatter")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["dropped"], 0)
        self.assertEqual(len(out["comments"]), 1)

    def test_offchange_suggestion_dropped(self):
        out = self._run_main(DIFF, changed_line="a.c:100-100\n")
        self.assertEqual(out["comments"], [])
        self.assertEqual(out["dropped"], 1)

    def test_missing_diff_is_clean_ok(self):
        out = self._run_main("")     # empty diff (clang-format clean)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["comments"], [])


if __name__ == "__main__":
    unittest.main()
